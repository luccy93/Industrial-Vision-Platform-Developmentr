"""Container-level GPU inference evidence (V25).

A verified GPU runtime proves the host can start the GPU image. It does not
prove the image can actually load a model and infer on CUDA. This module runs
the digest-pinned ``api-gpu`` image with ``--gpus all`` and executes the
repository's structured inference smoke test inside the container.

Without ``--execute`` every execution check is ``NOT_RUN``. A missing Docker
CLI, missing GPU image, non-zero container exit, malformed JSON, CPU fallback,
or skipped model is reported honestly and never becomes a pass.
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

INFERENCE_SCHEMA_VERSION = 1
INFERENCE_REPORT_FIELDS = (
    "schema_version",
    "generated_at",
    "executed",
    "manifest_sha256",
    "subject",
    "image",
    "digest",
    "state",
    "verified",
    "runtime",
    "checks",
    "blockers",
    "limitations",
)
INFERENCE_SUBJECT_FIELDS = ("tag", "commit", "source_repository")
INFERENCE_CHECK_FIELDS = ("name", "state", "required", "detail", "command")
INFERENCE_RUNTIME_FIELDS = (
    "status",
    "model",
    "requested_device",
    "device",
    "cuda",
    "latency_ms",
    "detections",
    "classes",
    "reason",
)
INFERENCE_IMAGE = "api-gpu"
SMOKE_MODULE = "backend.app.inference.smoke_test"


class InferenceError(RuntimeError):
    """The GPU inference qualification request is invalid."""


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
        if not isinstance(image, Mapping) or image.get("name") != INFERENCE_IMAGE:
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
    timeout: int = 600,
) -> subprocess.CompletedProcess[str] | None:
    try:
        return runner(args, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def _runtime(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, Mapping):
        return None
    cuda = payload.get("cuda")
    return {
        "status": payload.get("status"),
        "model": payload.get("model"),
        "requested_device": payload.get("requested_device"),
        "device": payload.get("device"),
        "cuda": dict(cuda) if isinstance(cuda, Mapping) else cuda,
        "latency_ms": payload.get("latency_ms"),
        "detections": payload.get("detections"),
        "classes": payload.get("classes"),
        "reason": payload.get("reason"),
    }


def _parse_smoke_output(text: str) -> dict[str, Any] | None:
    for line in reversed((text or "").splitlines()):
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, Mapping):
            return dict(payload)
    return None


def _report(
    manifest: Mapping[str, Any],
    *,
    manifest_sha: str,
    executed: bool,
    image: str | None,
    digest: str | None,
    runtime: Mapping[str, Any] | None,
    checks: Sequence[Mapping[str, Any]],
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
        "schema_version": INFERENCE_SCHEMA_VERSION,
        "generated_at": now(),
        "executed": executed,
        "manifest_sha256": manifest_sha,
        "subject": _subject(manifest),
        "image": image,
        "digest": digest,
        "state": overall,
        "verified": verified,
        "runtime": dict(runtime) if runtime is not None else None,
        "checks": list(checks),
        "blockers": blockers,
        "limitations": limitations,
    }


def qualify_gpu_inference(
    manifest_path: Path,
    *,
    execute: bool = False,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None] = shutil.which,
    now: Callable[[], str] = utc_now_iso,
) -> dict[str, Any]:
    """Run the structured inference smoke test inside the pinned GPU image."""
    try:
        manifest = load_manifest(manifest_path)
    except (ManifestError, OSError) as exc:
        raise InferenceError(str(exc)) from exc
    errors = manifest_errors(
        manifest,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
    )
    if errors:
        raise InferenceError("manifest is invalid:\n- " + "\n- ".join(errors))
    try:
        manifest_sha = sha256_file(manifest_path)
    except OSError as exc:
        raise InferenceError(f"could not hash manifest {manifest_path}: {exc}") from exc

    image = _gpu_image(manifest)
    checks: list[dict[str, Any]] = []
    if image is None:
        checks.append(
            _check(
                "gpu-inference-image",
                FAIL,
                True,
                f"manifest has no digest-pinned {INFERENCE_IMAGE} image",
            )
        )
    else:
        checks.append(
            _check(
                "gpu-inference-image",
                PASS,
                True,
                f"{INFERENCE_IMAGE} is pinned to {image[0]}",
            )
        )

    if not execute:
        checks.append(
            _check(
                "gpu-inference-execution",
                NOT_RUN,
                True,
                "container inference was not executed; pass --execute on the GPU host",
            )
        )
        return _report(
            manifest,
            manifest_sha=manifest_sha,
            executed=False,
            image=image[0] if image else None,
            digest=image[1] if image else None,
            runtime=None,
            checks=checks,
            now=now,
        )

    checks.append(_check("gpu-inference-execution", PASS, True, "container inference was executed"))
    if which("docker") is None:
        checks.append(
            _check(
                "gpu-inference-docker",
                UNAVAILABLE,
                True,
                "docker is not installed; container inference was not run",
            )
        )
        return _report(
            manifest,
            manifest_sha=manifest_sha,
            executed=True,
            image=image[0] if image else None,
            digest=image[1] if image else None,
            runtime=None,
            checks=checks,
            now=now,
        )
    if image is None:
        checks.append(
            _check(
                "gpu-inference-docker",
                FAIL,
                True,
                "container inference cannot run without a digest-pinned image",
            )
        )
        return _report(
            manifest,
            manifest_sha=manifest_sha,
            executed=True,
            image=None,
            digest=None,
            runtime=None,
            checks=checks,
            now=now,
        )

    args = [
        "docker",
        "run",
        "--rm",
        "--gpus",
        "all",
        "--entrypoint",
        "python",
        image[0],
        "-m",
        SMOKE_MODULE,
        "--json",
        "--require-cuda",
    ]
    command = _command_text(args)
    result = _run(runner, args, timeout=600)
    if result is None:
        checks.append(
            _check(
                "gpu-inference-docker",
                UNAVAILABLE,
                True,
                "the GPU inference container could not be executed",
                command,
            )
        )
        return _report(
            manifest,
            manifest_sha=manifest_sha,
            executed=True,
            image=image[0],
            digest=image[1],
            runtime=None,
            checks=checks,
            now=now,
        )

    payload = _parse_smoke_output(result.stdout or "")
    runtime = _runtime(payload)
    if result.returncode != 0:
        reason = None
        if payload is not None:
            reason = payload.get("reason")
        detail = str(reason or (result.stderr or result.stdout or "no output")).strip()[:500]
        checks.append(
            _check(
                "gpu-inference-docker",
                FAIL,
                True,
                f"container inference exited with code {result.returncode}: {detail}",
                command,
            )
        )
        return _report(
            manifest,
            manifest_sha=manifest_sha,
            executed=True,
            image=image[0],
            digest=image[1],
            runtime=runtime,
            checks=checks,
            now=now,
        )
    checks.append(
        _check(
            "gpu-inference-docker",
            PASS,
            True,
            "the GPU inference container exited successfully",
            command,
        )
    )
    if payload is None:
        checks.append(
            _check(
                "gpu-inference-report",
                FAIL,
                True,
                "container output did not contain a JSON smoke report",
                command,
            )
        )
        return _report(
            manifest,
            manifest_sha=manifest_sha,
            executed=True,
            image=image[0],
            digest=image[1],
            runtime=None,
            checks=checks,
            now=now,
        )
    checks.append(
        _check(
            "gpu-inference-report",
            PASS,
            True,
            "container emitted a structured inference report",
            command,
        )
    )

    cuda = payload.get("cuda") if isinstance(payload.get("cuda"), Mapping) else {}
    device = str(payload.get("device") or "")
    problems: list[str] = []
    if payload.get("status") != "READY":
        problems.append(f"status is {payload.get('status')!r}, expected 'READY'")
    if cuda.get("available") is not True:
        problems.append("CUDA is not available inside the container")
    if not device.lower().startswith("cuda"):
        problems.append(f"inference device is {device!r}, not a CUDA device")
    latency = payload.get("latency_ms")
    if not isinstance(latency, (int, float)) or latency <= 0:
        problems.append("inference latency was not measured")
    detections = payload.get("detections")
    if not isinstance(detections, int) or detections < 0:
        problems.append("detection count was not reported")
    if problems:
        checks.append(_check("gpu-inference-cuda", FAIL, True, "; ".join(problems), command))
    else:
        checks.append(
            _check(
                "gpu-inference-cuda",
                PASS,
                True,
                f"inference ran on {device} in {latency:.1f} ms with {detections} detections",
                command,
            )
        )
    return _report(
        manifest,
        manifest_sha=manifest_sha,
        executed=True,
        image=image[0],
        digest=image[1],
        runtime=runtime,
        checks=checks,
        now=now,
    )


def write_inference_report(report: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def inference_report_errors(
    report: Any,
    manifest: Mapping[str, Any],
    *,
    manifest_path: Path,
) -> list[str]:
    if not isinstance(report, Mapping):
        return ["GPU inference report must be a JSON object"]
    errors: list[str] = []
    if report.get("schema_version") != INFERENCE_SCHEMA_VERSION:
        errors.append(f"GPU inference schema_version must be {INFERENCE_SCHEMA_VERSION}")
    try:
        expected_sha = sha256_file(manifest_path)
    except OSError as exc:
        return [f"could not hash manifest {manifest_path}: {exc}"]
    if report.get("manifest_sha256") != expected_sha:
        errors.append("GPU inference report is not bound to the supplied manifest")
    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    subject = report.get("subject")
    if not isinstance(subject, Mapping):
        errors.append("GPU inference report subject is missing")
    else:
        for field in INFERENCE_SUBJECT_FIELDS:
            if subject.get(field) != release.get(field):
                errors.append(f"GPU inference report subject.{field} does not match the manifest release")
    if report.get("executed") is not True:
        errors.append("GPU inference was not executed")
    if report.get("state") != PASS:
        errors.append(f"GPU inference state is {report.get('state')!r}, not PASS")
    if report.get("verified") is not True:
        errors.append("GPU inference verified is not true")
    checks = report.get("checks")
    if not isinstance(checks, list):
        errors.append("GPU inference checks are missing")
    else:
        for check in checks:
            if isinstance(check, Mapping) and check.get("required") is True and check.get("state") != PASS:
                errors.append(f"GPU inference required check {check.get('name')} is not PASS")
    runtime = report.get("runtime")
    if not isinstance(runtime, Mapping):
        errors.append("GPU inference runtime details are missing")
    else:
        cuda = runtime.get("cuda")
        if not isinstance(cuda, Mapping) or cuda.get("available") is not True:
            errors.append("GPU inference runtime does not prove CUDA availability")
        if not str(runtime.get("device") or "").lower().startswith("cuda"):
            errors.append("GPU inference runtime did not run on a CUDA device")
    return errors


def render_inference_summary(report: Mapping[str, Any]) -> str:
    runtime = report.get("runtime") or {}
    subject = report.get("subject") or {}
    lines = [
        f"GPU inference: {report.get('state')} "
        f"(executed={report.get('executed')}, verified={report.get('verified')})",
        f"Subject: {subject.get('tag')} at {subject.get('commit')} from {subject.get('source_repository')}",
        f"Image: {report.get('image')}",
        f"Device: {runtime.get('device')} | status={runtime.get('status')} "
        f"| latency_ms={runtime.get('latency_ms')} | detections={runtime.get('detections')}",
    ]
    for check in report.get("checks") or []:
        required = "required" if check.get("required") else "informational"
        lines.append(f"- {check.get('name')}: {check.get('state')} ({required}) - {check.get('detail')}")
    blockers = report.get("blockers") or []
    if blockers:
        lines.append("Blockers:")
        lines.extend(f"- {item}" for item in blockers)
    return "\n".join(lines) + "\n"
