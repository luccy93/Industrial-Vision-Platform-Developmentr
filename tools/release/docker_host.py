"""Read-only Docker host inspection for V28 readiness.

The caller must name an existing Docker context. Every command is a read-only
inspection (`version`, `context inspect`, `compose version`, `ps`, `info`) run
through `docker --context <name>`. Nothing here builds, pulls, starts, stops,
removes, or otherwise mutates a container, image, volume, or daemon.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from backend.app.core.redaction import redact_text
from tools.release.manifest import utc_now_iso
from tools.release.verification import (
    FAIL,
    NOT_RUN,
    PASS,
    UNAVAILABLE,
    CommandRunner,
    default_runner,
)

DOCKER_CONTEXT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
PRODUCTION_MARKERS = ("prod", "production", "prd")
DEFAULT_DOCKER_TIMEOUT = 60.0
FAILED_CONTAINER_STATES = frozenset({"dead", "restarting", "paused"})
FAILED_STATUS_MARKERS = ("unhealthy", "restarting", "dead")
DOCKER_CHECKS = (
    "docker-host-inspection",
    "docker-host-compose",
    "docker-host-containers",
    "docker-host-gpu-runtime",
)


class DockerHostError(RuntimeError):
    """The Docker host inspection request is invalid."""


def _check(
    name: str,
    state: str,
    required: bool,
    detail: str,
    *,
    command: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "category": "docker-host",
        "state": state,
        "required": required,
        "mode": "live-read-only",
        "detail": redact_text(detail),
        "command": redact_text(command) if command is not None else None,
    }


def docker_context_errors(value: Any) -> list[str]:
    """Return every reason *value* is not a safe existing Docker context name."""
    if not isinstance(value, str) or not value.strip():
        return ["docker_host must name an existing Docker context"]
    name = value.strip()
    if name != value:
        return ["docker_host must not contain surrounding whitespace"]
    if "://" in name or "@" in name or "/" in name or "\\" in name:
        return ["docker_host must be an existing Docker context name, not a URL or SSH target"]
    if DOCKER_CONTEXT_PATTERN.fullmatch(name) is None:
        return ["docker_host must be a Docker context name using letters, digits, '.', '_', or '-'"]
    lowered = name.lower()
    if any(marker in lowered for marker in PRODUCTION_MARKERS):
        return ["docker_host looks like a production context; only an authorized staging context is allowed"]
    return []


def _run(
    runner: CommandRunner,
    args: Sequence[str],
    *,
    timeout: float,
) -> tuple[subprocess.CompletedProcess[str] | None, str | None]:
    try:
        return runner(list(args), timeout=timeout), None
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except (OSError, subprocess.SubprocessError):
        return None, "execution_error"


def _command_text(args: Sequence[str]) -> str:
    return " ".join(args)


def _json_lines(text: str) -> list[Mapping[str, Any]]:
    documents: list[Mapping[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, Mapping):
            documents.append(payload)
    return documents


def _context_endpoint(payload: Mapping[str, Any]) -> str | None:
    endpoints = payload.get("Endpoints")
    if not isinstance(endpoints, Mapping):
        return None
    for value in endpoints.values():
        if isinstance(value, Mapping) and isinstance(value.get("Host"), str):
            return str(value["Host"])
    return None


def inspect_docker_host(
    context: str | None,
    *,
    compose_project: str | None,
    gpu_required: bool,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None],
    timeout: float = DEFAULT_DOCKER_TIMEOUT,
    now: Callable[[], str] = utc_now_iso,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Inspect an authorized Docker context without mutating it."""
    checks: list[dict[str, Any]] = []
    observation: dict[str, Any] = {
        "source": "docker-context-read-only",
        "observed_at": now(),
        "context": context,
        "compose_project": compose_project,
        "server_version": None,
        "context_endpoint": None,
        "containers": [],
        "gpu_runtime": None,
        "commands": [],
    }
    names = DOCKER_CHECKS
    if context is None:
        return (
            [
                _check(
                    name,
                    NOT_RUN,
                    name != "docker-host-gpu-runtime" or gpu_required,
                    "no authorized Docker context was supplied with --docker-host",
                )
                for name in names
            ],
            observation,
        )
    problems = docker_context_errors(context)
    if problems:
        detail = "; ".join(problems)
        return (
            [
                _check(
                    name,
                    FAIL if name == "docker-host-inspection" else NOT_RUN,
                    name != "docker-host-gpu-runtime" or gpu_required,
                    detail,
                )
                for name in names
            ],
            observation,
        )
    if which("docker") is None:
        return (
            [
                _check(
                    name,
                    UNAVAILABLE,
                    name != "docker-host-gpu-runtime" or gpu_required,
                    "docker is not installed; the authorized Docker context was not inspected",
                )
                for name in names
            ],
            observation,
        )

    base = ["docker", "--context", context]

    version_args = [*base, "version", "--format", "{{json .}}"]
    observation["commands"].append(_command_text(version_args))
    result, failure = _run(runner, version_args, timeout=timeout)
    if failure is not None or result is None or result.returncode != 0:
        detail = (
            (result.stderr or result.stdout or "no output").strip()
            if result is not None
            else (failure or "no result")
        )
        checks.append(
            _check(
                "docker-host-inspection",
                UNAVAILABLE,
                True,
                f"the authorized Docker context is unreachable: {detail[:300]}",
                command=_command_text(version_args),
            )
        )
    else:
        try:
            version_payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            version_payload = None
        server = version_payload.get("Server") if isinstance(version_payload, Mapping) else None
        server_version = server.get("Version") if isinstance(server, Mapping) else None
        observation["server_version"] = server_version
        inspect_args = [*base, "context", "inspect", context, "--format", "{{json .}}"]
        observation["commands"].append(_command_text(inspect_args))
        inspect_result, inspect_failure = _run(runner, inspect_args, timeout=timeout)
        context_problems: list[str] = []
        if inspect_failure is not None or inspect_result is None or inspect_result.returncode != 0:
            context_problems.append("the Docker context metadata could not be inspected")
        else:
            documents = _json_lines(inspect_result.stdout)
            document = documents[0] if documents else None
            if document is None:
                context_problems.append("the Docker context metadata was empty")
            else:
                if document.get("Name") != context:
                    context_problems.append("the Docker context name does not match the requested context")
                endpoint = _context_endpoint(document)
                observation["context_endpoint"] = endpoint
                if endpoint is None:
                    context_problems.append("the Docker context has no inspectable endpoint")
                else:
                    lowered = endpoint.lower()
                    if any(marker in lowered for marker in PRODUCTION_MARKERS):
                        context_problems.append("the Docker context endpoint looks like production")
        checks.append(
            _check(
                "docker-host-inspection",
                FAIL if context_problems else PASS,
                True,
                "; ".join(context_problems)
                if context_problems
                else f"Docker context {context} is reachable read-only; server {server_version or 'unknown'}",
                command=_command_text(version_args),
            )
        )

    compose_args = [*base, "compose", "version"]
    observation["commands"].append(_command_text(compose_args))
    compose_result, compose_failure = _run(runner, compose_args, timeout=timeout)
    if compose_failure is not None or compose_result is None:
        checks.append(
            _check(
                "docker-host-compose",
                UNAVAILABLE,
                True,
                "Docker Compose could not be executed through the context "
                f"({compose_failure or 'no result'})",
                command=_command_text(compose_args),
            )
        )
    elif compose_result.returncode != 0:
        detail = (compose_result.stderr or compose_result.stdout or "no output").strip()
        checks.append(
            _check(
                "docker-host-compose",
                FAIL,
                True,
                f"Docker Compose is not available through the context: {detail[:300]}",
                command=_command_text(compose_args),
            )
        )
    else:
        checks.append(
            _check(
                "docker-host-compose",
                PASS,
                True,
                "Docker Compose is available through the authorized context",
                command=_command_text(compose_args),
            )
        )

    if not isinstance(compose_project, str) or not compose_project:
        checks.append(
            _check(
                "docker-host-containers",
                NOT_RUN,
                True,
                "the staging target has no valid Compose project name",
            )
        )
    else:
        ps_args = [
            *base,
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={compose_project}",
            "--format",
            "{{json .}}",
        ]
        observation["commands"].append(_command_text(ps_args))
        ps_result, ps_failure = _run(runner, ps_args, timeout=timeout)
        if ps_failure is not None or ps_result is None or ps_result.returncode != 0:
            detail = (
                (ps_result.stderr or ps_result.stdout or "no output").strip()
                if ps_result is not None
                else (ps_failure or "no result")
            )
            checks.append(
                _check(
                    "docker-host-containers",
                    UNAVAILABLE,
                    True,
                    f"the project containers could not be inspected: {detail[:300]}",
                    command=_command_text(ps_args),
                )
            )
        else:
            containers = _json_lines(ps_result.stdout)
            observation["containers"] = [
                {
                    "name": item.get("Names") or item.get("Name"),
                    "state": item.get("State"),
                    "status": item.get("Status"),
                }
                for item in containers
            ]
            container_problems: list[str] = []
            for item in containers:
                state = str(item.get("State") or "").lower()
                status = str(item.get("Status") or "").lower()
                name = item.get("Names") or item.get("Name") or "unknown"
                if state in FAILED_CONTAINER_STATES:
                    container_problems.append(f"container {name} is {state}")
                elif any(marker in status for marker in FAILED_STATUS_MARKERS):
                    container_problems.append(f"container {name} reports {status}")
            checks.append(
                _check(
                    "docker-host-containers",
                    FAIL if container_problems else PASS,
                    True,
                    "; ".join(container_problems[:8])
                    if container_problems
                    else (
                        f"{len(containers)} existing project container(s); "
                        "none are restarting, dead, paused, or unhealthy"
                        if containers
                        else "no existing project containers; the host is ready for a new deployment"
                    ),
                    command=_command_text(ps_args),
                )
            )

    gpu_required_flag = bool(gpu_required)
    if not gpu_required_flag:
        checks.append(
            _check(
                "docker-host-gpu-runtime",
                PASS,
                False,
                "GPU runtime is not required for this CPU profile",
            )
        )
    else:
        info_args = [*base, "info", "--format", "{{json .}}"]
        observation["commands"].append(_command_text(info_args))
        info_result, info_failure = _run(runner, info_args, timeout=timeout)
        if info_failure is not None or info_result is None or info_result.returncode != 0:
            detail = (
                (info_result.stderr or info_result.stdout or "no output").strip()
                if info_result is not None
                else (info_failure or "no result")
            )
            checks.append(
                _check(
                    "docker-host-gpu-runtime",
                    UNAVAILABLE,
                    True,
                    f"the Docker host runtime metadata could not be inspected: {detail[:300]}",
                    command=_command_text(info_args),
                )
            )
        else:
            try:
                info_payload = json.loads(info_result.stdout)
            except json.JSONDecodeError:
                info_payload = None
            runtimes = info_payload.get("Runtimes") if isinstance(info_payload, Mapping) else None
            observation["gpu_runtime"] = sorted(runtimes) if isinstance(runtimes, Mapping) else None
            if isinstance(runtimes, Mapping) and "nvidia" in runtimes:
                checks.append(
                    _check(
                        "docker-host-gpu-runtime",
                        PASS,
                        True,
                        "the NVIDIA container runtime is registered on the authorized Docker host",
                        command=_command_text(info_args),
                    )
                )
            else:
                checks.append(
                    _check(
                        "docker-host-gpu-runtime",
                        FAIL,
                        True,
                        "the NVIDIA container runtime is not registered on the authorized Docker host",
                        command=_command_text(info_args),
                    )
                )
    return checks, observation
