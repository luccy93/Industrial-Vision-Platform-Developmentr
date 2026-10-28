"""GPU runtime qualification evidence (V24).

A verified GPU *artifact* is not a verified GPU *runtime*. This module proves
the target host exposes an NVIDIA device, Docker registers the NVIDIA container
runtime, and the digest-pinned ``api-gpu`` image can start with GPU access.
Without ``--execute`` every check is ``NOT_RUN``; a missing driver, runtime, or
container failure is ``UNAVAILABLE`` or ``FAIL``, never a pass.
"""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from tools.release.manifest import (
    ManifestError,
    load_manifest,
    manifest_errors,
    sha256_file,
    utc_now_iso,
)
from tools.release.verification import (
    FAIL,
    NOT_RUN,
    PASS,
    UNAVAILABLE,
    CommandRunner,
    default_runner,
    is_placeholder_digest,
)

GPU_SCHEMA_VERSION = 1
GPU_REPORT_FIELDS = (
    "schema_version",
    "generated_at",
    "executed",
    "state",
    "verified",
    "manifest_sha256",
    "subject",
    "gpu",
    "checks",
    "blockers",
    "limitations",
)
GPU_SUBJECT_FIELDS = ("tag", "commit", "source_repository")
GPU_DETAILS_FIELDS = (
    "name",
    "driver_version",
    "memory",
    "runtime",
    "image",
    "image_digest",
    "container_cuda",
)
GPU_CHECK_FIELDS = ("name", "state", "required", "detail", "command")
GPU_IMAGE = "api-gpu"


class GpuError(RuntimeError):
    """The GPU runtime qualification request is invalid."""


def _check(
    name: str,
    state: str,
    required: bool,
    detail: str,
    command: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "state": state,
        "required": required,
        "detail": detail,
        "command": command,
    }


def _aggregate(checks: Sequence[Mapping[str, Any]]) -> str:
    states = {str(check.get("state")) for check in checks}
    required_states = {str(check.get("state")) for check in checks if check.get("required") is True}
    if FAIL in states:
        return FAIL
    if UNAVAILABLE in required_states:
        return UNAVAILABLE
    if NOT_RUN in required_states:
        return NOT_RUN
    return PASS


def _subject(manifest: Mapping[str, Any]) -> dict[str, Any]:
    release = manifest.get("release")
    if not isinstance(release, Mapping):
        return {"tag": None, "commit": None, "source_repository": None}
    return {
        "tag": release.get("tag"),
        "commit": release.get("commit"),
        "source_repository": release.get("source_repository"),
    }


def _command_text(args: Sequence[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in args)


def _gpu_image(manifest: Mapping[str, Any]) -> tuple[str, str] | None:
    for image in manifest.get("images") or []:
        if not isinstance(image, Mapping) or image.get("name") != GPU_IMAGE:
            continue
        repository = image.get("repository")
        digest = image.get("digest")
        if isinstance(repository, str) and isinstance(digest, str) and not is_placeholder_digest(digest):
            return f"{repository}@{digest}", digest
    return None


def _run(
    runner: CommandRunner,
    args: Sequence[str],
    *,
    timeout: int = 300,
) -> subprocess.CompletedProcess[str] | None:
    try:
        return runner(args, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def _gpu_details(
    *,
    name: str | None,
    driver: str | None,
    memory: str | None,
    runtime: str | None,
    image: str | None,
    image_digest: str | None,
    container_cuda: bool,
) -> dict[str, Any]:
    return {
        "name": name,
        "driver_version": driver,
        "memory": memory,
        "runtime": runtime,
        "image": image,
        "image_digest": image_digest,
        "container_cuda": container_cuda,
    }


def qualify_gpu_runtime(
    manifest_path: Path,
    *,
    execute: bool = False,
    run_container: bool = True,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None] = shutil.which,
    now: Callable[[], str] = utc_now_iso,
) -> dict[str, Any]:
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as exc:
        raise GpuError(str(exc)) from exc
    errors = manifest_errors(
        manifest,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
    )
    if errors:
        raise GpuError("manifest is invalid:\n- " + "\n- ".join(errors))
    try:
        manifest_sha = sha256_file(manifest_path)
    except OSError as exc:
        raise GpuError(f"could not hash manifest {manifest_path}: {exc}") from exc

    image = _gpu_image(manifest)
    checks: list[dict[str, Any]] = []
    if image is None:
        checks.append(
            _check(
                "gpu-image",
                FAIL,
                True,
                f"manifest has no digest-pinned {GPU_IMAGE} image",
            )
        )
    else:
        checks.append(
            _check(
                "gpu-image",
                PASS,
                True,
                f"{GPU_IMAGE} is pinned to {image[0]}",
            )
        )

    if not execute:
        checks.append(
            _check(
                "execution",
                NOT_RUN,
                True,
                "GPU runtime qualification was not executed; pass --execute on the GPU host",
            )
        )
        for name, detail in (
            ("nvidia-smi", "GPU driver was not queried"),
            ("docker-cli", "Docker was not queried"),
            ("docker-runtime", "Docker NVIDIA runtime was not queried"),
            ("gpu-container", "the GPU container was not started"),
        ):
            checks.append(_check(name, NOT_RUN, True, detail))
        return _gpu_report(
            manifest,
            manifest_sha=manifest_sha,
            executed=False,
            checks=checks,
            gpu=_gpu_details(
                name=None,
                driver=None,
                memory=None,
                runtime=None,
                image=image[0] if image else None,
                image_digest=image[1] if image else None,
                container_cuda=False,
            ),
            now=now,
        )

    checks.append(_check("execution", PASS, True, "GPU runtime qualification was executed"))
    gpu_name: str | None = None
    driver: str | None = None
    memory: str | None = None
    runtime: str | None = None
    container_cuda = False

    if which("nvidia-smi") is None:
        checks.append(_check("nvidia-smi", UNAVAILABLE, True, "nvidia-smi is not installed"))
    else:
        args = [
            "nvidia-smi",
            "--query-gpu=name,driver_version,memory.total",
            "--format=csv,noheader",
        ]
        command = _command_text(args)
        result = _run(runner, args, timeout=60)
        if result is None or result.returncode != 0 or not (result.stdout or "").strip():
            detail = (
                (result.stderr or result.stdout or "no output").strip()[:500]
                if result is not None
                else "nvidia-smi could not be executed"
            )
            checks.append(
                _check(
                    "nvidia-smi",
                    UNAVAILABLE,
                    True,
                    f"no NVIDIA GPU runtime was proven: {detail}",
                    command,
                )
            )
        else:
            first = (result.stdout or "").strip().splitlines()[0]
            parts = [part.strip() for part in first.split(",")]
            gpu_name = parts[0] if parts and parts[0] else None
            driver = parts[1] if len(parts) > 1 and parts[1] else None
            memory = parts[2] if len(parts) > 2 and parts[2] else None
            if gpu_name is None or driver is None:
                checks.append(
                    _check(
                        "nvidia-smi",
                        FAIL,
                        True,
                        "nvidia-smi output did not include a GPU name and driver version",
                        command,
                    )
                )
            else:
                checks.append(
                    _check(
                        "nvidia-smi",
                        PASS,
                        True,
                        f"NVIDIA GPU {gpu_name} with driver {driver}",
                        command,
                    )
                )

    if which("docker") is None:
        checks.append(_check("docker-cli", UNAVAILABLE, True, "docker is not installed"))
        checks.append(_check("docker-runtime", UNAVAILABLE, True, "docker is not installed"))
    else:
        version_args = ["docker", "--version"]
        version_command = _command_text(version_args)
        version = _run(runner, version_args, timeout=60)
        if version is None or version.returncode != 0:
            checks.append(
                _check(
                    "docker-cli",
                    UNAVAILABLE,
                    True,
                    "docker could not be executed",
                    version_command,
                )
            )
        else:
            checks.append(
                _check(
                    "docker-cli",
                    PASS,
                    True,
                    (version.stdout or "docker").strip(),
                    version_command,
                )
            )
        info_args = ["docker", "info", "--format", "{{json .Runtimes}}"]
        info_command = _command_text(info_args)
        info = _run(runner, info_args, timeout=120)
        if info is None or info.returncode != 0:
            checks.append(
                _check(
                    "docker-runtime",
                    UNAVAILABLE,
                    True,
                    "docker info could not be read",
                    info_command,
                )
            )
        else:
            try:
                runtimes = json.loads((info.stdout or "").strip() or "{}")
            except json.JSONDecodeError as exc:
                checks.append(
                    _check(
                        "docker-runtime",
                        FAIL,
                        True,
                        f"docker runtime list is not valid JSON: {exc}",
                        info_command,
                    )
                )
                runtimes = {}
            names = {str(key).lower() for key in runtimes} if isinstance(runtimes, Mapping) else set()
            if "nvidia" in names:
                runtime = "nvidia"
                checks.append(
                    _check(
                        "docker-runtime",
                        PASS,
                        True,
                        "Docker registers the nvidia container runtime",
                        info_command,
                    )
                )
            else:
                checks.append(
                    _check(
                        "docker-runtime",
                        FAIL,
                        True,
                        "Docker does not register the nvidia container runtime",
                        info_command,
                    )
                )

    if not run_container:
        checks.append(
            _check(
                "gpu-container",
                NOT_RUN,
                True,
                "container GPU access was not tested; pass --run-container",
            )
        )
    elif image is None:
        checks.append(
            _check(
                "gpu-container",
                FAIL,
                True,
                f"manifest has no digest-pinned {GPU_IMAGE} image",
            )
        )
    elif which("docker") is None:
        checks.append(
            _check(
                "gpu-container",
                UNAVAILABLE,
                True,
                "docker is not installed; the GPU container was not started",
            )
        )
    else:
        pull_args = ["docker", "pull", image[0]]
        pull_command = _command_text(pull_args)
        pull = _run(runner, pull_args, timeout=900)
        if pull is None or pull.returncode != 0:
            detail = (
                (pull.stderr or pull.stdout or "no output").strip()[:500]
                if pull is not None
                else "docker pull could not be executed"
            )
            checks.append(
                _check(
                    "gpu-container",
                    FAIL,
                    True,
                    f"GPU image pull failed: {detail}",
                    pull_command,
                )
            )
        else:
            run_args = ["docker", "run", "--rm", "--gpus", "all", image[0], "nvidia-smi", "-L"]
            run_command = _command_text(run_args)
            container = _run(runner, run_args, timeout=300)
            if container is None or container.returncode != 0:
                detail = (
                    (container.stderr or container.stdout or "no output").strip()[:500]
                    if container is not None
                    else "docker run could not be executed"
                )
                checks.append(
                    _check(
                        "gpu-container",
                        FAIL,
                        True,
                        f"GPU container did not start with CUDA access: {detail}",
                        run_command,
                    )
                )
            else:
                container_cuda = True
                checks.append(
                    _check(
                        "gpu-container",
                        PASS,
                        True,
                        "digest-pinned GPU image started and reported CUDA devices",
                        run_command,
                    )
                )

    return _gpu_report(
        manifest,
        manifest_sha=manifest_sha,
        executed=True,
        checks=checks,
        gpu=_gpu_details(
            name=gpu_name,
            driver=driver,
            memory=memory,
            runtime=runtime,
            image=image[0] if image else None,
            image_digest=image[1] if image else None,
            container_cuda=container_cuda,
        ),
        now=now,
    )


def _gpu_report(
    manifest: Mapping[str, Any],
    *,
    manifest_sha: str,
    executed: bool,
    checks: Sequence[Mapping[str, Any]],
    gpu: Mapping[str, Any],
    now: Callable[[], str],
) -> dict[str, Any]:
    overall = _aggregate(checks)
    verified = overall == PASS and all(
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
        "schema_version": GPU_SCHEMA_VERSION,
        "generated_at": now(),
        "executed": executed,
        "state": overall,
        "verified": verified,
        "manifest_sha256": manifest_sha,
        "subject": _subject(manifest),
        "gpu": dict(gpu),
        "checks": list(checks),
        "blockers": blockers,
        "limitations": limitations,
    }


def write_gpu_report(report: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def render_gpu_summary(report: Mapping[str, Any]) -> str:
    subject = report.get("subject") or {}
    gpu = report.get("gpu") or {}
    lines = [
        f"GPU runtime qualification: {report.get('state')} "
        f"(executed={report.get('executed')}, verified={report.get('verified')})",
        f"Subject: {subject.get('tag')} at {subject.get('commit')} from {subject.get('source_repository')}",
        f"Manifest: {report.get('manifest_sha256')}",
        f"GPU: {gpu.get('name')} (driver {gpu.get('driver_version')}, runtime {gpu.get('runtime')})",
        f"Image: {gpu.get('image')}",
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
