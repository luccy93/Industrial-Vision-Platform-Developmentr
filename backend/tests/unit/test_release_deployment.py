"""V23 digest-pinned deployment, report gating, log, and rollback tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from backend.tests.unit.test_release_verification import REPO_ROOT, make_release
from tools.release.deployment import (
    DEPLOYMENT_CHECK_FIELDS,
    DEPLOYMENT_REPORT_FIELDS,
    DEPLOYMENT_SCHEMA_VERSION,
    DEPLOYMENT_SUBJECT_FIELDS,
    DeploymentError,
    deployment_environment,
    render_rollback_plan,
    scan_log_text,
    verification_report_errors,
    verify_deployment,
)
from tools.release.manifest import sha256_file
from tools.release.preflight import REQUIRED_PREFLIGHT_CHECKS
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE


def _compose_payload(
    manifest: dict[str, Any],
    *,
    gpu: bool = False,
    tag_web: bool = False,
) -> str:
    environment = deployment_environment(manifest, gpu=gpu)
    services = {
        "migrate": {"image": environment["IVP_CPU_API_IMAGE"] if gpu else environment["IVP_API_IMAGE"]},
        "api": {
            "image": environment["IVP_GPU_API_IMAGE"] if gpu else environment["IVP_API_IMAGE"],
        },
        "web": {"image": ("ghcr.io/octo/repo/web:v1.2.3" if tag_web else environment["IVP_WEB_IMAGE"])},
    }
    return json.dumps({"services": services})


def _runner(
    config_payload: str,
    *,
    ps_payload: str = "",
    inspected: str = "",
    logs_payload: str = "",
    logs_failure: bool = False,
) -> Any:
    def run(args: Any, *, timeout: int = 120, env: Any = None) -> subprocess.CompletedProcess[str]:
        del timeout, env
        if "config" in args:
            return subprocess.CompletedProcess(args, 0, config_payload, "")
        if "logs" in args:
            if logs_failure:
                return subprocess.CompletedProcess(args, 1, "", "no such service")
            return subprocess.CompletedProcess(args, 0, logs_payload, "")
        if "ps" in args:
            return subprocess.CompletedProcess(args, 0, ps_payload, "")
        if args[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(args, 0, inspected + "\n", "")
        return subprocess.CompletedProcess(args, 1, "", "unexpected command")

    return run


def _report(manifest_path: Path, manifest: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    release = manifest["release"]
    report: dict[str, Any] = {
        "schema_version": 2,
        "profile": "production",
        "generated_at": "2026-10-23T00:00:00Z",
        "manifest_sha256": sha256_file(manifest_path),
        "subject": {
            "tag": release["tag"],
            "commit": release["commit"],
            "source_repository": release["source_repository"],
        },
        "overall_state": PASS,
        "verified": True,
        "production_verified": True,
        "artifact_status": {
            "cpu": {
                "state": PASS,
                "images": {"api": PASS, "web": PASS},
                "runtime_state": NOT_RUN,
                "runtime_verified": False,
            },
            "gpu": {
                "state": PASS,
                "images": {"api-gpu": PASS},
                "runtime_state": NOT_RUN,
                "runtime_verified": False,
            },
        },
        "checks": [],
        "limitations": [],
    }
    report.update(overrides)
    return report


def _write_report(tmp_path: Path, report: dict[str, Any]) -> Path:
    path = tmp_path / "release-verification.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_compose_configuration_is_digest_pinned(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report = verify_deployment(
        manifest_path,
        compose_files=[tmp_path / "compose.yaml", tmp_path / "compose.release.yaml"],
        runner=_runner(_compose_payload(manifest)),
        which=lambda name: f"/usr/bin/{name}",
        base_environment={},
    )
    # Without a verification report the overall result is NOT_RUN, never PASS;
    # the configuration checks themselves still pass.
    assert report["state"] == NOT_RUN
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["compose-config"]["state"] == PASS
    assert checks["compose-pin:api"]["state"] == PASS
    assert checks["compose-pin:web"]["state"] == PASS
    assert checks["compose-pin:migrate"]["state"] == PASS
    assert checks["verification-report"]["state"] == NOT_RUN


def test_compose_configuration_rejects_mutable_tag(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report = verify_deployment(
        manifest_path,
        compose_files=[tmp_path / "compose.yaml"],
        runner=_runner(_compose_payload(manifest, tag_web=True)),
        which=lambda name: f"/usr/bin/{name}",
        base_environment={},
    )
    assert report["state"] == FAIL
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["compose-pin:web"]["state"] == FAIL


def test_missing_docker_is_unavailable(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    report = verify_deployment(
        manifest_path,
        compose_files=[tmp_path / "compose.yaml"],
        runner=_runner("{}"),
        which=lambda name: None,
    )
    assert report["state"] == UNAVAILABLE


def test_running_stack_is_checked_against_manifest_image_ids(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    images = {image["name"]: image for image in manifest["images"]}
    ps = "\n".join(
        json.dumps({"Service": service, "State": "running", "Name": f"ivp-{service}-1"})
        for service in ("api", "web")
    )

    def runner(args: Any, *, timeout: int = 120, env: Any = None) -> subprocess.CompletedProcess[str]:
        del timeout, env
        if "config" in args:
            return subprocess.CompletedProcess(args, 0, _compose_payload(manifest), "")
        if "ps" in args:
            return subprocess.CompletedProcess(args, 0, ps, "")
        if args[:2] == ["docker", "inspect"]:
            container = args[-1]
            image_name = "api" if "api" in container else "web"
            return subprocess.CompletedProcess(args, 0, images[image_name]["image_id"] + "\n", "")
        return subprocess.CompletedProcess(args, 1, "", "unexpected command")

    report = verify_deployment(
        manifest_path,
        compose_files=[tmp_path / "compose.yaml"],
        running=True,
        runner=runner,
        which=lambda name: f"/usr/bin/{name}",
        base_environment={},
    )
    # Running checks pass, but without a report the overall result is NOT_RUN.
    assert report["state"] == NOT_RUN
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["running-service:api"]["state"] == PASS
    assert checks["running-image:web"]["state"] == PASS


def test_running_stack_image_mismatch_fails(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    ps = "\n".join(
        json.dumps({"Service": service, "State": "running", "Name": f"ivp-{service}-1"})
        for service in ("api", "web")
    )

    def runner(args: Any, *, timeout: int = 120, env: Any = None) -> subprocess.CompletedProcess[str]:
        del timeout, env
        if "config" in args:
            return subprocess.CompletedProcess(args, 0, _compose_payload(manifest), "")
        if "ps" in args:
            return subprocess.CompletedProcess(args, 0, ps, "")
        if args[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(args, 0, "sha256:" + "f" * 64 + "\n", "")
        return subprocess.CompletedProcess(args, 1, "", "unexpected command")

    report = verify_deployment(
        manifest_path,
        compose_files=[tmp_path / "compose.yaml"],
        running=True,
        runner=runner,
        which=lambda name: f"/usr/bin/{name}",
        base_environment={},
    )
    assert report["state"] == FAIL
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["running-image:api"]["state"] == FAIL


def test_verified_report_authorizes_deployment(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report_path = _write_report(tmp_path, _report(manifest_path, manifest))
    report = verify_deployment(
        manifest_path,
        compose_files=[tmp_path / "compose.yaml"],
        report_path=report_path,
        require_verified=True,
        runner=_runner(_compose_payload(manifest)),
        which=lambda name: f"/usr/bin/{name}",
        base_environment={},
    )
    assert report["state"] == PASS
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["verification-report"]["state"] == PASS
    assert checks["verification-cpu-artifacts"]["state"] == PASS


def test_require_verified_without_report_fails(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report = verify_deployment(
        manifest_path,
        compose_files=[tmp_path / "compose.yaml"],
        require_verified=True,
        runner=_runner(_compose_payload(manifest)),
        which=lambda name: f"/usr/bin/{name}",
        base_environment={},
    )
    assert report["state"] == FAIL
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["verification-report"]["state"] == FAIL


def test_report_bound_to_different_manifest_fails(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report_path = _write_report(
        tmp_path,
        _report(manifest_path, manifest, manifest_sha256="sha256:" + "0" * 64),
    )
    errors = verification_report_errors(
        json.loads(report_path.read_text(encoding="utf-8")),
        manifest,
        manifest_path=manifest_path,
    )
    assert any("manifest_sha256" in error for error in errors)


def test_report_subject_mismatch_fails(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report_path = _write_report(
        tmp_path,
        _report(
            manifest_path,
            manifest,
            subject={"tag": "v9.9.9", "commit": "b" * 40, "source_repository": "other/repo"},
        ),
    )
    errors = verification_report_errors(
        json.loads(report_path.read_text(encoding="utf-8")),
        manifest,
        manifest_path=manifest_path,
    )
    assert any("subject.tag" in error for error in errors)
    assert any("subject.commit" in error for error in errors)


def test_local_or_unverified_report_is_rejected(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report_path = _write_report(
        tmp_path,
        _report(manifest_path, manifest, profile="local", production_verified=False),
    )
    errors = verification_report_errors(
        json.loads(report_path.read_text(encoding="utf-8")),
        manifest,
        manifest_path=manifest_path,
    )
    assert any("profile" in error for error in errors)
    assert any("production_verified" in error for error in errors)


def test_gpu_report_without_runtime_is_not_a_runtime_pass(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report_path = _write_report(tmp_path, _report(manifest_path, manifest))
    report = verify_deployment(
        manifest_path,
        compose_files=[tmp_path / "compose.yaml", tmp_path / "compose.gpu.release.yaml"],
        gpu=True,
        report_path=report_path,
        require_verified=True,
        runner=_runner(_compose_payload(manifest, gpu=True)),
        which=lambda name: f"/usr/bin/{name}",
        base_environment={},
    )
    assert report["state"] == PASS
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["verification-gpu-artifacts"]["state"] == PASS
    assert checks["verification-gpu-runtime"]["state"] == NOT_RUN
    assert "not verified" in checks["verification-gpu-runtime"]["detail"]


def test_clean_logs_pass_and_secret_logs_fail(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    clean = verify_deployment(
        manifest_path,
        compose_files=[tmp_path / "compose.yaml"],
        check_logs=True,
        runner=_runner(_compose_payload(manifest), logs_payload="api started\nready\n"),
        which=lambda name: f"/usr/bin/{name}",
        base_environment={},
    )
    assert {check["name"]: check for check in clean["checks"]}["log-secrets"]["state"] == PASS

    leaky = verify_deployment(
        manifest_path,
        compose_files=[tmp_path / "compose.yaml"],
        check_logs=True,
        runner=_runner(
            _compose_payload(manifest),
            logs_payload="connecting postgresql://ivp:supersecretpassword@postgres:5432/db\n",
        ),
        which=lambda name: f"/usr/bin/{name}",
        base_environment={},
    )
    assert leaky["state"] == FAIL
    check = {check["name"]: check for check in leaky["checks"]}["log-secrets"]
    assert check["state"] == FAIL
    assert "credential-url" in check["detail"]
    assert "supersecretpassword" not in check["detail"]


def test_log_scan_ignores_redaction_markers() -> None:
    assert scan_log_text('password="[REDACTED]"\nAuthorization: Bearer [REDACTED]') == []
    assert scan_log_text("ghp_" + "a" * 36) == ["github-token"]


def test_placeholder_digest_is_rejected(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    tampered = json.loads(manifest_path.read_text(encoding="utf-8"))
    tampered["images"][0]["digest"] = "sha256:" + "0" * 64
    with pytest.raises(DeploymentError, match="placeholder digest"):
        deployment_environment(tampered, gpu=False)


def test_rollback_plan_uses_previous_digests_and_preserves_data(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report_path = _write_report(tmp_path, _report(manifest_path, manifest))
    plan = render_rollback_plan(
        manifest_path,
        backup_file="before-rollback.sql",
        verification_report_path=report_path,
    )
    for image in manifest["images"]:
        if image["name"] == "api-gpu":
            continue
        assert f"{image['repository']}@{image['digest']}" in plan
    assert "up -d" in plan
    assert "pg_dump" in plan
    assert "Do not reverse Alembic migrations automatically" in plan
    assert "alembic downgrade" not in plan
    assert "Never run `docker compose down -v`" in plan
    assert "Verified by production report" in plan


def test_rollback_plan_requires_verified_report(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    with pytest.raises(DeploymentError, match="verification report is required"):
        render_rollback_plan(manifest_path)


def test_rollback_plan_allows_explicit_unverified_emergency(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    plan = render_rollback_plan(manifest_path, allow_unverified=True)
    assert "WARNING: no verification report was supplied" in plan
    assert "unverified emergency rollback" in plan


def test_rollback_plan_rejects_same_release(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report_path = _write_report(tmp_path, _report(manifest_path, manifest))
    with pytest.raises(DeploymentError, match="nothing to roll back"):
        render_rollback_plan(
            manifest_path,
            current_manifest_path=manifest_path,
            verification_report_path=report_path,
        )


def test_rollback_plan_rejects_invalid_report(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report_path = _write_report(
        tmp_path,
        _report(manifest_path, manifest, production_verified=False),
    )
    with pytest.raises(DeploymentError, match="not valid"):
        render_rollback_plan(manifest_path, verification_report_path=report_path)


def _preflight_report(
    manifest_path: Path,
    manifest: dict[str, Any],
    **overrides: Any,
) -> dict[str, Any]:
    release = manifest["release"]
    payload: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": "2026-10-24T00:00:00Z",
        "manifest_sha256": sha256_file(manifest_path),
        "subject": {
            "tag": release["tag"],
            "commit": release["commit"],
            "source_repository": release["source_repository"],
        },
        "gpu": False,
        "state": PASS,
        "verified": True,
        "checks": [
            {
                "name": name,
                "state": PASS,
                "required": True,
                "detail": "ok",
                "command": None,
            }
            for name in REQUIRED_PREFLIGHT_CHECKS
        ],
        "blockers": [],
        "limitations": [],
    }
    payload.update(overrides)
    return payload


def test_deployment_report_binds_manifest_and_subject(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report = verify_deployment(
        manifest_path,
        compose_files=[tmp_path / "compose.yaml"],
        runner=_runner(_compose_payload(manifest)),
        which=lambda name: f"/usr/bin/{name}",
        base_environment={},
        now=lambda: "2026-10-24T00:00:00Z",
    )
    assert set(report) == set(DEPLOYMENT_REPORT_FIELDS)
    assert report["schema_version"] == DEPLOYMENT_SCHEMA_VERSION
    assert report["generated_at"] == "2026-10-24T00:00:00Z"
    assert report["manifest_sha256"] == sha256_file(manifest_path)
    assert report["subject"] == {
        "tag": manifest["release"]["tag"],
        "commit": manifest["release"]["commit"],
        "source_repository": manifest["release"]["source_repository"],
    }
    assert report["gpu"] is False


def test_deployment_requires_bound_preflight(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report_path = _write_report(tmp_path, _report(manifest_path, manifest))
    preflight_path = tmp_path / "deployment-preflight.json"
    preflight_path.write_text(
        json.dumps(_preflight_report(manifest_path, manifest)),
        encoding="utf-8",
    )
    report = verify_deployment(
        manifest_path,
        compose_files=[tmp_path / "compose.yaml"],
        report_path=report_path,
        require_verified=True,
        preflight_report_path=preflight_path,
        runner=_runner(_compose_payload(manifest)),
        which=lambda name: f"/usr/bin/{name}",
        base_environment={},
    )
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["preflight"]["state"] == PASS
    assert report["state"] == PASS


def test_deployment_rejects_preflight_bound_to_other_manifest(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report_path = _write_report(tmp_path, _report(manifest_path, manifest))
    preflight_path = tmp_path / "deployment-preflight.json"
    preflight_path.write_text(
        json.dumps(_preflight_report(manifest_path, manifest, manifest_sha256="sha256:" + "f" * 64)),
        encoding="utf-8",
    )
    report = verify_deployment(
        manifest_path,
        compose_files=[tmp_path / "compose.yaml"],
        report_path=report_path,
        require_verified=True,
        preflight_report_path=preflight_path,
        runner=_runner(_compose_payload(manifest)),
        which=lambda name: f"/usr/bin/{name}",
        base_environment={},
    )
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["preflight"]["state"] == FAIL
    assert "manifest_sha256" in checks["preflight"]["detail"]
    assert report["state"] == FAIL


def test_deployment_schema_matches_contract() -> None:
    schema = json.loads((REPO_ROOT / "release" / "deployment-report.schema.json").read_text(encoding="utf-8"))
    assert set(schema["required"]) == set(DEPLOYMENT_REPORT_FIELDS)
    assert schema["properties"]["schema_version"]["const"] == DEPLOYMENT_SCHEMA_VERSION
    assert set(schema["$defs"]["subject"]["required"]) == set(DEPLOYMENT_SUBJECT_FIELDS)
    assert set(schema["$defs"]["check"]["required"]) == set(DEPLOYMENT_CHECK_FIELDS)
    assert schema["properties"]["gpu"]["type"] == "boolean"
