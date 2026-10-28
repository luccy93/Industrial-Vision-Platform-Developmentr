"""Live qualification prerequisite probes (V24).

These probes answer one question honestly: can this host actually produce the
evidence a requested qualification profile needs? They never print, store, or
hash credential values; a token is reported only as present or absent. Missing
tools and unreachable services are ``UNAVAILABLE``, never ``PASS``.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from tools.release.manifest import utc_now_iso
from tools.release.qualification import QUALIFICATION_PROFILES, SCOPES
from tools.release.verification import (
    FAIL,
    NOT_RUN,
    PASS,
    UNAVAILABLE,
    attestation_cli_support,
    default_runner,
)

PREREQUISITES_SCHEMA_VERSION = 1
GHCR_HOST = "ghcr.io"
GITHUB_API_HOST = "api.github.com"
HTTPS_PORT = 443


class PrerequisiteError(RuntimeError):
    """The prerequisite probe request is invalid."""


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
NetworkProbe = Callable[[str, int], bool]


def _check(name: str, state: str, required: bool, detail: str) -> dict[str, Any]:
    return {
        "name": name,
        "state": state,
        "required": required,
        "detail": detail,
    }


def _aggregate(checks: list[dict[str, Any]]) -> str:
    states = {str(check.get("state")) for check in checks}
    required_states = {str(check.get("state")) for check in checks if check.get("required") is True}
    if FAIL in states:
        return FAIL
    if UNAVAILABLE in required_states:
        return UNAVAILABLE
    if NOT_RUN in required_states:
        return NOT_RUN
    return PASS


def _run(
    runner: CommandRunner,
    args: list[str],
    *,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str] | None:
    try:
        return runner(args, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def _tcp_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _network_check(
    name: str,
    *,
    host: str,
    required: bool,
    network_probe: NetworkProbe,
) -> dict[str, Any]:
    try:
        reachable = network_probe(host, HTTPS_PORT)
    except OSError:
        reachable = False
    if reachable:
        return _check(name, PASS, required, f"{host}:{HTTPS_PORT} is reachable")
    return _check(
        name,
        UNAVAILABLE if required else NOT_RUN,
        required,
        f"{host}:{HTTPS_PORT} is not reachable",
    )


def _file_check(name: str, path: Path | None, required: bool) -> dict[str, Any]:
    if not required:
        return _check(name, NOT_RUN, False, f"{name} is not required for this profile/scope")
    if path is None:
        return _check(name, FAIL, True, f"{name} was not supplied")
    if path.is_file():
        return _check(name, PASS, True, f"{path} exists")
    return _check(name, FAIL, True, f"{path} does not exist")


def probe_prerequisites(
    *,
    repo_root: Path,
    profile: str = "local_validation",
    scope: str = "artifact",
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    expected_repository: str | None = None,
    artifacts_dir: Path | None = None,
    verification_report: Path | None = None,
    publication_report: Path | None = None,
    deployment_report: Path | None = None,
    rehearsal_report: Path | None = None,
    gpu_report: Path | None = None,
    main_ref: str = "origin/main",
    require_github: bool | None = None,
    require_docker: bool | None = None,
    require_gpu: bool = False,
    require_live_evidence: bool = False,
    production_authorized: bool = False,
    env: Mapping[str, str] | None = None,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None] = shutil.which,
    network_probe: NetworkProbe = _tcp_reachable,
    now: Callable[[], str] = utc_now_iso,
) -> dict[str, Any]:
    if profile not in QUALIFICATION_PROFILES:
        raise PrerequisiteError(
            f"unknown qualification profile {profile!r}; expected one of {QUALIFICATION_PROFILES}"
        )
    if scope not in SCOPES:
        raise PrerequisiteError(f"unknown qualification scope {scope!r}; expected one of {SCOPES}")
    if require_github is None:
        require_github = profile != "local_validation"
    if require_docker is None:
        require_docker = scope in ("deployment", "full")
    if profile == "production_qualification":
        require_gpu = True
    publication_required = require_live_evidence or profile != "local_validation" or scope != "artifact"
    environment = os.environ if env is None else env

    checks: list[dict[str, Any]] = []

    git_path = which("git")
    if git_path is None:
        checks.append(_check("git-cli", FAIL, True, "git is not installed"))
    else:
        result = _run(runner, ["git", "--version"])
        if result is not None and result.returncode == 0:
            checks.append(_check("git-cli", PASS, True, (result.stdout or "git").strip()))
        else:
            checks.append(_check("git-cli", FAIL, True, "git could not be executed"))

    if not repo_root.is_dir():
        checks.append(_check("repository", FAIL, True, f"repository root does not exist: {repo_root}"))
    else:
        result = _run(runner, ["git", "-C", str(repo_root), "rev-parse", "--is-inside-work-tree"])
        if result is not None and result.returncode == 0 and result.stdout.strip() == "true":
            checks.append(_check("repository", PASS, True, f"{repo_root} is a git repository"))
        else:
            checks.append(_check("repository", FAIL, True, f"{repo_root} is not a git repository"))

    if expected_tag is None:
        checks.append(_check("tag", NOT_RUN, False, "no expected tag was supplied"))
    else:
        result = _run(
            runner,
            ["git", "-C", str(repo_root), "rev-parse", "--verify", f"refs/tags/{expected_tag}^{{commit}}"],
        )
        if result is None or result.returncode != 0:
            checks.append(_check("tag", FAIL, True, f"tag {expected_tag} does not exist locally"))
        elif expected_commit is not None and result.stdout.strip() != expected_commit:
            checks.append(
                _check(
                    "tag",
                    FAIL,
                    True,
                    f"tag {expected_tag} points at {result.stdout.strip()}, not {expected_commit}",
                )
            )
        else:
            checks.append(_check("tag", PASS, True, f"tag {expected_tag} resolves locally"))

    if expected_commit is None:
        checks.append(_check("commit", NOT_RUN, False, "no expected commit was supplied"))
    else:
        result = _run(
            runner, ["git", "-C", str(repo_root), "cat-file", "-e", f"{expected_commit}^{{commit}}"]
        )
        if result is not None and result.returncode == 0:
            checks.append(_check("commit", PASS, True, f"commit {expected_commit} exists locally"))
        else:
            checks.append(_check("commit", FAIL, True, f"commit {expected_commit} does not exist locally"))

    if expected_tag is None or expected_commit is None:
        checks.append(_check("main-reachability", NOT_RUN, False, "tag and commit are required"))
    else:
        result = _run(
            runner,
            ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", expected_commit, main_ref],
        )
        if result is not None and result.returncode == 0:
            checks.append(_check("main-reachability", PASS, True, f"commit is reachable from {main_ref}"))
        elif result is not None and result.returncode == 1:
            checks.append(_check("main-reachability", FAIL, True, f"commit is not reachable from {main_ref}"))
        else:
            checks.append(_check("main-reachability", UNAVAILABLE, True, f"could not resolve {main_ref}"))

    if require_github:
        supported, detail = attestation_cli_support(runner, which)
        checks.append(_check("github-cli", PASS if supported else UNAVAILABLE, True, detail))
    else:
        checks.append(_check("github-cli", NOT_RUN, False, "GitHub CLI is not required for this profile"))

    if require_github:
        token_present = bool(environment.get("GH_TOKEN") or environment.get("GITHUB_TOKEN"))
        checks.append(
            _check(
                "github-token",
                PASS if token_present else UNAVAILABLE,
                True,
                "GH_TOKEN or GITHUB_TOKEN is set"
                if token_present
                else "neither GH_TOKEN nor GITHUB_TOKEN is set",
            )
        )
    else:
        checks.append(_check("github-token", NOT_RUN, False, "GitHub credentials are not required"))

    checks.append(
        _network_check(
            "network-ghcr",
            host=GHCR_HOST,
            required=profile != "local_validation",
            network_probe=network_probe,
        )
    )
    checks.append(
        _network_check(
            "network-github",
            host=GITHUB_API_HOST,
            required=require_github,
            network_probe=network_probe,
        )
    )

    if require_docker:
        docker_path = which("docker")
        if docker_path is None:
            checks.append(_check("docker-cli", UNAVAILABLE, True, "docker is not installed"))
            checks.append(_check("docker-daemon", UNAVAILABLE, True, "docker daemon cannot be reached"))
            checks.append(_check("docker-compose", UNAVAILABLE, True, "docker compose is unavailable"))
        else:
            result = _run(runner, ["docker", "--version"])
            checks.append(
                _check(
                    "docker-cli",
                    PASS if result is not None and result.returncode == 0 else UNAVAILABLE,
                    True,
                    (result.stdout or "docker").strip()
                    if result is not None and result.returncode == 0
                    else "docker could not be executed",
                )
            )
            result = _run(runner, ["docker", "version", "--format", "{{.Server.Version}}"])
            daemon_ok = result is not None and result.returncode == 0 and bool(result.stdout.strip())
            checks.append(
                _check(
                    "docker-daemon",
                    PASS if daemon_ok else UNAVAILABLE,
                    True,
                    f"docker server {result.stdout.strip()} is reachable"
                    if daemon_ok and result is not None
                    else "docker daemon is not reachable",
                )
            )
            result = _run(runner, ["docker", "compose", "version"])
            checks.append(
                _check(
                    "docker-compose",
                    PASS if result is not None and result.returncode == 0 else UNAVAILABLE,
                    True,
                    (result.stdout or "docker compose").strip()
                    if result is not None and result.returncode == 0
                    else "docker compose could not be executed",
                )
            )
    else:
        for name in ("docker-cli", "docker-daemon", "docker-compose"):
            checks.append(_check(name, NOT_RUN, False, "Docker is not required for artifact scope"))

    if require_gpu:
        result = _run(
            runner,
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
        )
        gpu_present = result is not None and result.returncode == 0 and bool(result.stdout.strip())
        checks.append(
            _check(
                "gpu-driver",
                PASS if gpu_present else UNAVAILABLE,
                True,
                (result.stdout or "NVIDIA GPU").strip().splitlines()[0]
                if gpu_present and result is not None
                else "nvidia-smi is unavailable; no NVIDIA GPU runtime was proven",
            )
        )
        result = _run(runner, ["docker", "info", "--format", "{{json .Runtimes}}"])
        runtime_ok = (
            result is not None and result.returncode == 0 and "nvidia" in (result.stdout or "").lower()
        )
        checks.append(
            _check(
                "gpu-runtime",
                PASS if runtime_ok else UNAVAILABLE,
                True,
                "NVIDIA container runtime is registered"
                if runtime_ok
                else "NVIDIA container runtime is not registered",
            )
        )
    else:
        checks.append(_check("gpu-driver", NOT_RUN, False, "GPU runtime is not required"))
        checks.append(_check("gpu-runtime", NOT_RUN, False, "GPU runtime is not required"))

    if artifacts_dir is None:
        checks.append(_check("release-artifacts", FAIL, True, "artifacts directory was not supplied"))
    elif artifacts_dir.is_dir():
        checks.append(_check("release-artifacts", PASS, True, f"{artifacts_dir} exists"))
    else:
        checks.append(_check("release-artifacts", FAIL, True, f"{artifacts_dir} does not exist"))

    manifest_path = artifacts_dir / "release-manifest.json" if artifacts_dir is not None else None
    checks.append(_file_check("release-manifest", manifest_path, True))
    checks.append(_file_check("release-verification", verification_report, True))
    checks.append(_file_check("publication-report", publication_report, publication_required))
    checks.append(_file_check("deployment-report", deployment_report, scope in ("deployment", "full")))
    checks.append(_file_check("rollback-rehearsal", rehearsal_report, scope == "full"))
    checks.append(_file_check("gpu-runtime-report", gpu_report, require_gpu))

    if profile == "production_qualification":
        checks.append(
            _check(
                "production-authorization",
                PASS if production_authorized else FAIL,
                True,
                "production qualification was explicitly authorized"
                if production_authorized
                else "production qualification requires explicit authorization",
            )
        )
    else:
        checks.append(
            _check(
                "production-authorization",
                NOT_RUN,
                False,
                "production authorization is only required for production_qualification",
            )
        )

    overall = _aggregate(checks)
    ready = overall == PASS and all(
        check.get("state") == PASS for check in checks if check.get("required") is True
    )
    blockers = [
        f"{check['name']}: {check['state']} - {check['detail']}"
        for check in checks
        if check.get("required") is True and check.get("state") != PASS
    ]
    limitations = [
        f"{check['name']}: {check['state']} - {check['detail']}"
        for check in checks
        if check.get("required") is not True and check.get("state") != PASS
    ]
    return {
        "schema_version": PREREQUISITES_SCHEMA_VERSION,
        "generated_at": now(),
        "profile": profile,
        "scope": scope,
        "subject": {
            "tag": expected_tag,
            "commit": expected_commit,
            "source_repository": expected_repository,
        },
        "requirements": {
            "github": require_github,
            "docker": require_docker,
            "gpu": require_gpu,
            "live_evidence": require_live_evidence,
        },
        "ready": ready,
        "overall_state": overall,
        "checks": checks,
        "blockers": blockers,
        "limitations": limitations,
    }


def render_prerequisites_summary(report: Mapping[str, Any]) -> str:
    lines = [
        f"Qualification prerequisites: {report.get('overall_state')} "
        f"(profile={report.get('profile')}, scope={report.get('scope')}, ready={report.get('ready')})",
    ]
    for check in report.get("checks") or []:
        required = "required" if check.get("required") else "informational"
        lines.append(f"- {check.get('name')}: {check.get('state')} ({required}) - {check.get('detail')}")
    blockers = report.get("blockers") or []
    if blockers:
        lines.append("Blockers:")
        lines.extend(f"- {item}" for item in blockers)
    limitations = report.get("limitations") or []
    if limitations:
        lines.append("Limitations:")
        lines.extend(f"- {item}" for item in limitations)
    return "\n".join(lines) + "\n"
