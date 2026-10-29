"""V25 container-level GPU inference evidence tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from backend.tests.unit.test_release_verification import REPO_ROOT, make_release
from tools.release.inference import (
    INFERENCE_CHECK_FIELDS,
    INFERENCE_REPORT_FIELDS,
    INFERENCE_RUNTIME_FIELDS,
    INFERENCE_SUBJECT_FIELDS,
    InferenceError,
    inference_report_errors,
    qualify_gpu_inference,
    render_inference_summary,
    write_inference_report,
)
from tools.release.manifest import sha256_file
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

GENERATED_AT = "2026-10-25T00:00:00Z"


def _payload(
    *,
    status: str = "READY",
    device: str = "cuda:0",
    cuda_available: bool = True,
    latency_ms: float | None = 12.5,
    detections: int | None = 3,
) -> dict[str, Any]:
    return {
        "status": status,
        "model": "models/yolo11n.pt",
        "requested_device": "cuda",
        "device": device,
        "cuda": {"available": cuda_available, "device_count": 1, "torch": "2.13.0+cu126"},
        "latency_ms": latency_ms,
        "detections": detections,
        "classes": 80,
        "reason": None,
    }


def _runner(
    *,
    calls: list[list[str]] | None = None,
    payload: dict[str, Any] | None = None,
    returncode: int = 0,
    stdout: str | None = None,
    stderr: str = "",
) -> Any:
    body = stdout if stdout is not None else json.dumps(payload or _payload())

    def run(args: Any, *, timeout: int = 600, env: Any = None) -> subprocess.CompletedProcess[str]:
        del timeout, env
        if calls is not None:
            calls.append(list(args))
        return subprocess.CompletedProcess(args, returncode, body + "\n", stderr)

    return run


def _qualify(
    manifest_path: Path,
    *,
    execute: bool = True,
    runner: Any | None = None,
    which: Any | None = None,
) -> dict[str, Any]:
    return qualify_gpu_inference(
        manifest_path,
        execute=execute,
        runner=runner or _runner(),
        which=which or (lambda name: f"/usr/bin/{name}"),
        now=lambda: GENERATED_AT,
    )


def _checks(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {check["name"]: check for check in report["checks"]}


def test_inference_without_execute_is_not_run(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    calls: list[list[str]] = []
    report = _qualify(manifest_path, execute=False, runner=_runner(calls=calls))
    checks = _checks(report)
    assert report["generated_at"] == GENERATED_AT
    assert report["executed"] is False
    assert report["state"] == NOT_RUN
    assert report["verified"] is False
    assert report["runtime"] is None
    assert checks["gpu-inference-image"]["state"] == PASS
    assert checks["gpu-inference-execution"]["state"] == NOT_RUN
    assert calls == []


def test_inference_runs_pinned_gpu_image_and_parses_cuda_result(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    calls: list[list[str]] = []
    report = _qualify(manifest_path, runner=_runner(calls=calls))
    checks = _checks(report)
    assert report["state"] == PASS
    assert report["verified"] is True
    assert report["manifest_sha256"] == sha256_file(manifest_path)
    assert report["runtime"]["device"] == "cuda:0"
    assert checks["gpu-inference-docker"]["state"] == PASS
    assert checks["gpu-inference-report"]["state"] == PASS
    assert checks["gpu-inference-cuda"]["state"] == PASS
    gpu = next(image for image in manifest["images"] if image["name"] == "api-gpu")
    assert report["image"] == f"{gpu['repository']}@{gpu['digest']}"
    command = calls[0]
    assert command[:3] == ["docker", "run", "--rm"]
    assert command[command.index("--gpus") + 1] == "all"
    assert command[-2:] == ["--json", "--require-cuda"]
    assert any("@sha256:" in part for part in command)
    assert "GPU inference: PASS" in render_inference_summary(report)


def test_inference_is_unavailable_without_docker(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    report = _qualify(manifest_path, which=lambda name: None)
    checks = _checks(report)
    assert report["state"] == UNAVAILABLE
    assert checks["gpu-inference-docker"]["state"] == UNAVAILABLE
    assert report["verified"] is False


def test_inference_fails_when_container_skips_model(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    skipped = _payload(status="SKIPPED", device="", cuda_available=False, latency_ms=None, detections=None)
    skipped["reason"] = "model weights are not present"
    report = _qualify(manifest_path, runner=_runner(payload=skipped, returncode=2))
    checks = _checks(report)
    assert report["state"] == FAIL
    assert checks["gpu-inference-docker"]["state"] == FAIL
    assert "model weights are not present" in checks["gpu-inference-docker"]["detail"]


def test_inference_fails_on_malformed_output(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    report = _qualify(manifest_path, runner=_runner(stdout="not json"))
    checks = _checks(report)
    assert report["state"] == FAIL
    assert checks["gpu-inference-report"]["state"] == FAIL


def test_inference_fails_on_cpu_fallback(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    cpu = _payload(device="cpu", cuda_available=False)
    report = _qualify(manifest_path, runner=_runner(payload=cpu))
    checks = _checks(report)
    assert report["state"] == FAIL
    assert checks["gpu-inference-cuda"]["state"] == FAIL
    assert "not a CUDA device" in checks["gpu-inference-cuda"]["detail"]


def test_inference_rejects_manifest_without_gpu_image(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    manifest["images"] = [image for image in manifest["images"] if image["name"] != "api-gpu"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    try:
        _qualify(manifest_path)
    except InferenceError as exc:
        assert "api-gpu" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected InferenceError")


def test_inference_report_errors_detect_tampering(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report = _qualify(manifest_path)
    report_path = tmp_path / "gpu-inference.json"
    write_inference_report(report, report_path)
    assert inference_report_errors(report, manifest, manifest_path=manifest_path) == []
    tampered = dict(report)
    tampered["manifest_sha256"] = "sha256:" + "0" * 64
    errors = inference_report_errors(tampered, manifest, manifest_path=manifest_path)
    assert any("not bound to the supplied manifest" in error for error in errors)
    tampered = dict(report)
    tampered["runtime"] = {**report["runtime"], "device": "cpu"}
    errors = inference_report_errors(tampered, manifest, manifest_path=manifest_path)
    assert any("did not run on a CUDA device" in error for error in errors)


def test_inference_schema_matches_contract() -> None:
    schema = json.loads(
        (REPO_ROOT / "release" / "gpu-inference.schema.json").read_text(encoding="utf-8")
    )
    assert set(schema["required"]) == set(INFERENCE_REPORT_FIELDS)
    assert set(schema["$defs"]["check"]["required"]) == set(INFERENCE_CHECK_FIELDS)
    assert set(schema["$defs"]["subject"]["required"]) == set(INFERENCE_SUBJECT_FIELDS)
    assert set(schema["$defs"]["runtime"]["required"]) == set(INFERENCE_RUNTIME_FIELDS)


def test_inference_rejects_invalid_manifest(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    manifest["images"][0]["digest"] = "sha256:" + "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    try:
        _qualify(manifest_path, execute=False)
    except InferenceError as exc:
        assert "manifest is invalid" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected InferenceError")
