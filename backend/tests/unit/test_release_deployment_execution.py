"""V25 controlled deployment execution tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from backend.tests.unit.test_release_deployment import (
    _compose_payload,
    _preflight_report,
    _report,
)
from backend.tests.unit.test_release_verification import REPO_ROOT, make_release
from tools.release.deployment import (
    DeploymentError,
    deploy_release,
)
from tools.release.manifest import sha256_file
from tools.release.verification import FAIL, NOT_RUN, PASS

GENERATED_AT = "2026-10-25T00:00:00Z"


def _runner(
    manifest: dict[str, Any],
    *,
    calls: list[list[str]] | None = None,
    pull_failure: bool = False,
    up_failure: bool = False,
    image_mismatch: bool = False,
) -> Any:
    images = {image["name"]: image for image in manifest["images"]}
    ps = "\n".join(
        json.dumps({"Service": service, "State": "running", "Name": f"ivp-{service}-1"})
        for service in ("api", "web")
    )

    def run(args: Any, *, timeout: int = 120, env: Any = None) -> subprocess.CompletedProcess[str]:
        del timeout, env
        if calls is not None:
            calls.append(list(args))
        if "config" in args:
            return subprocess.CompletedProcess(args, 0, _compose_payload(manifest), "")
        if "pull" in args:
            if pull_failure:
                return subprocess.CompletedProcess(args, 1, "", "manifest unknown")
            return subprocess.CompletedProcess(args, 0, "pulled\n", "")
        if "up" in args:
            if up_failure:
                return subprocess.CompletedProcess(args, 1, "", "port is already allocated")
            return subprocess.CompletedProcess(args, 0, "started\n", "")
        if "ps" in args:
            return subprocess.CompletedProcess(args, 0, ps, "")
        if args[:2] == ["docker", "inspect"]:
            container = args[-1]
            image_name = "api" if "api" in container else "web"
            image_id = "sha256:" + "f" * 64 if image_mismatch else images[image_name]["image_id"]
            return subprocess.CompletedProcess(args, 0, image_id + "\n", "")
        return subprocess.CompletedProcess(args, 1, "", "unexpected command")

    return run


def _inputs(tmp_path: Path, manifest_path: Path, manifest: dict[str, Any]) -> tuple[Path, Path]:
    verification = tmp_path / "release-verification.json"
    verification.write_text(json.dumps(_report(manifest_path, manifest)), encoding="utf-8")
    preflight = tmp_path / "deployment-preflight.json"
    preflight.write_text(json.dumps(_preflight_report(manifest_path, manifest)), encoding="utf-8")
    return verification, preflight


def _deploy(
    tmp_path: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    *,
    execute: bool = True,
    verification: Path | None = None,
    preflight: Path | None = None,
    runner: Any | None = None,
) -> dict[str, Any]:
    if verification is None or preflight is None:
        verification, preflight = _inputs(tmp_path, manifest_path, manifest)
    return deploy_release(
        manifest_path,
        compose_files=[tmp_path / "compose.yaml"],
        verification_report_path=verification,
        preflight_report_path=preflight,
        execute=execute,
        runner=runner or _runner(manifest),
        which=lambda name: f"/usr/bin/{name}",
        base_environment={},
        now=lambda: GENERATED_AT,
    )


def _checks(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {check["name"]: check for check in report["checks"]}


def test_deploy_release_without_execute_is_not_run(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report = _deploy(tmp_path, manifest_path, manifest, execute=False)
    assert report["generated_at"] == GENERATED_AT
    assert report["executed"] is False
    assert report["state"] == NOT_RUN
    assert _checks(report)["deployment-execution"]["state"] == NOT_RUN


def test_deploy_release_requires_verification_and_preflight(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    with pytest.raises(DeploymentError, match="production verification report"):
        deploy_release(
            manifest_path,
            compose_files=[tmp_path / "compose.yaml"],
            execute=True,
            runner=_runner(manifest),
            which=lambda name: f"/usr/bin/{name}",
        )
    verification, _ = _inputs(tmp_path, manifest_path, manifest)
    with pytest.raises(DeploymentError, match="bound deployment preflight"):
        deploy_release(
            manifest_path,
            compose_files=[tmp_path / "compose.yaml"],
            verification_report_path=verification,
            execute=True,
            runner=_runner(manifest),
            which=lambda name: f"/usr/bin/{name}",
        )


def test_deploy_release_pulls_starts_and_verifies_running_stack(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    calls: list[list[str]] = []
    report = _deploy(
        tmp_path,
        manifest_path,
        manifest,
        runner=_runner(manifest, calls=calls),
    )
    checks = _checks(report)
    assert report["executed"] is True
    assert report["state"] == PASS
    assert report["manifest_sha256"] == sha256_file(manifest_path)
    assert checks["verification"]["state"] == PASS
    assert checks["preflight"]["state"] == PASS
    assert checks["compose-config"]["state"] == PASS
    assert checks["pull"]["state"] == PASS
    assert checks["up"]["state"] == PASS
    assert checks["post-deploy-verification"]["state"] == PASS
    assert checks["deployment-execution"]["state"] == PASS
    assert any("pull" in args for args in calls)
    assert any("up" in args for args in calls)
    assert "environment" not in report


def test_deploy_release_stops_after_failed_pull(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    calls: list[list[str]] = []
    report = _deploy(
        tmp_path,
        manifest_path,
        manifest,
        runner=_runner(manifest, calls=calls, pull_failure=True),
    )
    checks = _checks(report)
    assert report["state"] == FAIL
    assert checks["pull"]["state"] == FAIL
    assert checks["deployment-execution"]["state"] == FAIL
    assert not any("up" in args for args in calls)


def test_deploy_release_stops_after_failed_up(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report = _deploy(
        tmp_path,
        manifest_path,
        manifest,
        runner=_runner(manifest, up_failure=True),
    )
    checks = _checks(report)
    assert report["state"] == FAIL
    assert checks["up"]["state"] == FAIL
    assert checks["deployment-execution"]["state"] == FAIL
    assert "post-deploy-verification" not in checks


def test_deploy_release_fails_when_running_image_does_not_match(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report = _deploy(
        tmp_path,
        manifest_path,
        manifest,
        runner=_runner(manifest, image_mismatch=True),
    )
    checks = _checks(report)
    assert report["state"] == FAIL
    assert checks["post-deploy-verification"]["state"] == FAIL
    assert checks["deployment-execution"]["state"] == FAIL


def test_deploy_release_refuses_tampered_preflight(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    verification, preflight = _inputs(tmp_path, manifest_path, manifest)
    payload = json.loads(preflight.read_text(encoding="utf-8"))
    payload["manifest_sha256"] = "sha256:" + "0" * 64
    preflight.write_text(json.dumps(payload), encoding="utf-8")
    calls: list[list[str]] = []
    report = _deploy(
        tmp_path,
        manifest_path,
        manifest,
        verification=verification,
        preflight=preflight,
        runner=_runner(manifest, calls=calls),
    )
    checks = _checks(report)
    assert report["state"] == FAIL
    assert checks["preflight"]["state"] == FAIL
    assert checks["deployment-execution"]["state"] == FAIL
    assert not any("pull" in args for args in calls)


def test_deployment_execution_schema_matches_contract() -> None:
    from tools.release.deployment import DEPLOYMENT_EXECUTION_SCHEMA_VERSION

    schema = json.loads(
        (REPO_ROOT / "release" / "deployment-execution.schema.json").read_text(encoding="utf-8")
    )
    assert schema["properties"]["schema_version"]["const"] == DEPLOYMENT_EXECUTION_SCHEMA_VERSION
    assert schema["properties"]["executed"]["type"] == "boolean"
    assert set(schema["required"]) == {
        "schema_version",
        "generated_at",
        "executed",
        "manifest_sha256",
        "subject",
        "gpu",
        "project",
        "compose_files",
        "state",
        "checks",
        "blockers",
        "limitations",
    }
