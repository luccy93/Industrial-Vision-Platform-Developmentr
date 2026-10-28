"""V24 NVIDIA driver, Docker runtime, and GPU container qualification tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from backend.tests.unit.test_release_verification import REPO_ROOT, make_release
from tools.release.gpu import (
    GPU_CHECK_FIELDS,
    GPU_DETAILS_FIELDS,
    GPU_REPORT_FIELDS,
    GPU_SCHEMA_VERSION,
    GPU_SUBJECT_FIELDS,
    GpuError,
    qualify_gpu_runtime,
    render_gpu_summary,
    write_gpu_report,
)
from tools.release.manifest import sha256_file
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

GENERATED_AT = "2026-10-24T00:00:00Z"


def _runner(
    *,
    gpu_output: str = "NVIDIA A10, 535.104.05, 24564 MiB\n",
    runtimes: dict[str, Any] | None = None,
    pull_failure: bool = False,
    container_failure: bool = False,
) -> Any:
    def run(args: Any, *, timeout: int = 120, env: Any = None) -> subprocess.CompletedProcess[str]:
        del timeout, env
        if args[0] == "nvidia-smi":
            return subprocess.CompletedProcess(args, 0, gpu_output, "")
        if args[:2] == ["docker", "--version"]:
            return subprocess.CompletedProcess(args, 0, "Docker version 27.0.0, build abc\n", "")
        if args[:3] == ["docker", "info", "--format"]:
            return subprocess.CompletedProcess(args, 0, json.dumps(runtimes or {"nvidia": {}}), "")
        if args[:2] == ["docker", "pull"]:
            if pull_failure:
                return subprocess.CompletedProcess(args, 1, "", "manifest unknown")
            return subprocess.CompletedProcess(args, 0, "pulled\n", "")
        if args[:2] == ["docker", "run"]:
            if container_failure:
                return subprocess.CompletedProcess(args, 1, "", "could not select device driver")
            return subprocess.CompletedProcess(args, 0, "GPU 0: NVIDIA A10 (UUID: GPU-123)\n", "")
        return subprocess.CompletedProcess(args, 1, "", "unexpected command")

    return run


def _gpu(
    manifest_path: Path,
    *,
    execute: bool = True,
    runner: Any = None,
    which: Any = lambda name: f"/usr/bin/{name}",
    **overrides: Any,
) -> dict[str, Any]:
    options: dict[str, Any] = {
        "execute": execute,
        "runner": runner if runner is not None else _runner(),
        "which": which,
        "now": lambda: GENERATED_AT,
    }
    options.update(overrides)
    return qualify_gpu_runtime(manifest_path, **options)


def test_gpu_without_execute_is_not_run(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report = _gpu(manifest_path, execute=False)
    assert report["executed"] is False
    assert report["state"] == NOT_RUN
    assert report["verified"] is False
    assert report["generated_at"] == GENERATED_AT
    assert report["manifest_sha256"] == sha256_file(manifest_path)
    assert report["subject"]["commit"] == manifest["release"]["commit"]
    assert report["gpu"]["name"] is None
    assert report["gpu"]["container_cuda"] is False
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["gpu-image"]["state"] == PASS
    for name in ("execution", "nvidia-smi", "docker-cli", "docker-runtime", "gpu-container"):
        assert checks[name]["state"] == NOT_RUN
    assert "GPU runtime qualification: NOT_RUN" in render_gpu_summary(report)


def test_gpu_missing_nvidia_smi_is_unavailable(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    report = _gpu(manifest_path, which=lambda name: None)
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["nvidia-smi"]["state"] == UNAVAILABLE
    assert checks["docker-cli"]["state"] == UNAVAILABLE
    assert checks["gpu-container"]["state"] == UNAVAILABLE
    assert report["state"] == UNAVAILABLE
    assert report["verified"] is False


def test_gpu_missing_nvidia_runtime_fails(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    report = _gpu(manifest_path, runner=_runner(runtimes={"runc": {}}))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["nvidia-smi"]["state"] == PASS
    assert checks["docker-runtime"]["state"] == FAIL
    assert report["state"] == FAIL
    assert report["verified"] is False


def test_gpu_pull_failure_fails_container_check(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    report = _gpu(manifest_path, runner=_runner(pull_failure=True))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["gpu-container"]["state"] == FAIL
    assert "GPU image pull failed" in checks["gpu-container"]["detail"]
    assert report["state"] == FAIL


def test_gpu_container_failure_fails_container_check(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    report = _gpu(manifest_path, runner=_runner(container_failure=True))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["gpu-container"]["state"] == FAIL
    assert "CUDA" in checks["gpu-container"]["detail"]
    assert report["state"] == FAIL


def test_gpu_runtime_qualification_passes_with_cuda_container(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report = _gpu(manifest_path)
    assert report["state"] == PASS
    assert report["verified"] is True
    assert report["gpu"]["name"] == "NVIDIA A10"
    assert report["gpu"]["driver_version"] == "535.104.05"
    assert report["gpu"]["memory"] == "24564 MiB"
    assert report["gpu"]["runtime"] == "nvidia"
    assert report["gpu"]["container_cuda"] is True
    image = next(item for item in manifest["images"] if item["name"] == "api-gpu")
    assert report["gpu"]["image"] == f"{image['repository']}@{image['digest']}"
    assert report["gpu"]["image_digest"] == image["digest"]
    assert "GPU runtime qualification: PASS" in render_gpu_summary(report)


def test_gpu_container_skip_cannot_pass(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    report = _gpu(manifest_path, run_container=False)
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["gpu-container"]["state"] == NOT_RUN
    assert report["state"] == NOT_RUN
    assert report["verified"] is False


def test_gpu_report_round_trip(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    report = _gpu(manifest_path)
    path = tmp_path / "gpu-runtime.json"
    write_gpu_report(report, path)
    assert json.loads(path.read_text(encoding="utf-8"))["state"] == PASS


def test_gpu_rejects_invalid_manifest(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    manifest["release"]["commit"] = "not-a-commit"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(GpuError):
        _gpu(manifest_path)


def test_gpu_schema_matches_contract() -> None:
    schema = json.loads((REPO_ROOT / "release" / "gpu-runtime.schema.json").read_text(encoding="utf-8"))
    assert set(schema["required"]) == set(GPU_REPORT_FIELDS)
    assert schema["properties"]["schema_version"]["const"] == GPU_SCHEMA_VERSION
    assert set(schema["$defs"]["subject"]["required"]) == set(GPU_SUBJECT_FIELDS)
    assert set(schema["$defs"]["gpu"]["required"]) == set(GPU_DETAILS_FIELDS)
    assert set(schema["$defs"]["check"]["required"]) == set(GPU_CHECK_FIELDS)
