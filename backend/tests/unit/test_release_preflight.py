"""V24 deployment preflight, migration, volume, and rollback safety tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from backend.tests.unit.release_evidence import previous_release_manifest
from backend.tests.unit.test_release_verification import REPO_ROOT, make_release
from tools.release.deployment import deployment_environment
from tools.release.manifest import sha256_file
from tools.release.preflight import (
    PreflightError,
    preflight_report_errors,
    render_preflight_summary,
    run_preflight,
    write_preflight_report,
)
from tools.release.verification import FAIL, PASS, UNAVAILABLE

GENERATED_AT = "2026-10-24T00:00:00Z"


def _compose_payload(
    manifest: dict[str, Any],
    *,
    named_volume: bool = True,
) -> str:
    environment = deployment_environment(manifest, gpu=False)
    postgres_mount = (
        {"type": "volume", "source": "postgres-data", "target": "/var/lib/postgresql/data"}
        if named_volume
        else {"type": "bind", "source": "./data", "target": "/var/lib/postgresql/data"}
    )
    services = {
        "migrate": {"image": environment["IVP_API_IMAGE"]},
        "api": {"image": environment["IVP_API_IMAGE"]},
        "web": {"image": environment["IVP_WEB_IMAGE"]},
        "postgres": {"image": "postgres:16-alpine", "volumes": [postgres_mount]},
    }
    volumes = {"postgres-data": {}} if named_volume else {}
    return json.dumps({"services": services, "volumes": volumes})


def _runner(payload: str) -> Any:
    def run(args: Any, *, timeout: int = 120, env: Any = None) -> subprocess.CompletedProcess[str]:
        del timeout, env
        if "config" in args:
            return subprocess.CompletedProcess(args, 0, payload, "")
        return subprocess.CompletedProcess(args, 1, "", "unexpected command")

    return run


def _preflight(
    manifest_path: Path,
    *,
    payload: str | None = None,
    repo_root: Path = REPO_ROOT,
    previous_manifest_path: Path | None = None,
    which: Any = lambda name: f"/usr/bin/{name}",
    **overrides: Any,
) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    options: dict[str, Any] = {
        "repo_root": repo_root,
        "compose_files": [manifest_path.parent / "compose.yaml"],
        "runner": _runner(payload if payload is not None else _compose_payload(manifest)),
        "which": which,
        "base_environment": {},
        "now": lambda: GENERATED_AT,
        "previous_manifest_path": previous_manifest_path,
    }
    options.update(overrides)
    return run_preflight(manifest_path, **options)


def _migration_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "repo"
    versions = root / "backend" / "alembic" / "versions"
    versions.mkdir(parents=True)
    for name, content in files.items():
        (versions / name).write_text(content, encoding="utf-8")
    return root


def test_preflight_passes_with_digest_pinned_compose(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report = _preflight(manifest_path)
    assert report["state"] == PASS
    assert report["verified"] is True
    assert report["generated_at"] == GENERATED_AT
    assert report["manifest_sha256"] == sha256_file(manifest_path)
    checks = {check["name"]: check for check in report["checks"]}
    for name in (
        "manifest-digests",
        "compose-config",
        "migration-history",
        "migration-single-head",
        "no-automatic-downgrade",
        "volume-preservation",
        "rollback-plan-safety",
        "compose-pin:migrate",
        "compose-pin:api",
        "compose-pin:web",
    ):
        assert checks[name]["state"] == PASS
    assert "Deployment preflight: PASS" in render_preflight_summary(report)
    assert report["subject"] == {
        "tag": manifest["release"]["tag"],
        "commit": manifest["release"]["commit"],
        "source_repository": manifest["release"]["source_repository"],
    }


def test_preflight_fails_without_named_postgres_volume(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report = _preflight(manifest_path, payload=_compose_payload(manifest, named_volume=False))
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["volume-preservation"]["state"] == FAIL
    assert report["state"] == FAIL
    assert report["verified"] is False


def test_preflight_fails_with_multiple_migration_heads(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    repo_root = _migration_repo(
        tmp_path,
        {
            "001_a.py": 'revision = "001_a"\ndown_revision = None\n',
            "002_b.py": 'revision = "002_b"\ndown_revision = None\n',
        },
    )
    report = _preflight(manifest_path, repo_root=repo_root)
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["migration-single-head"]["state"] == FAIL
    assert "001_a" in checks["migration-single-head"]["detail"]
    assert report["state"] == FAIL


def test_preflight_fails_with_missing_migration_parent(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    repo_root = _migration_repo(
        tmp_path,
        {"001_a.py": 'revision = "001_a"\ndown_revision = "missing_parent"\n'},
    )
    report = _preflight(manifest_path, repo_root=repo_root)
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["migration-history"]["state"] == FAIL
    assert "missing_parent" in checks["migration-history"]["detail"]


def test_preflight_rejects_automatic_downgrade(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    repo_root = _migration_repo(
        tmp_path,
        {"001_a.py": 'revision = "001_a"\ndown_revision = None\n'},
    )
    (repo_root / "backend" / "Dockerfile").write_text(
        "FROM python:3.11\nCMD alembic downgrade head\n",
        encoding="utf-8",
    )
    report = _preflight(manifest_path, repo_root=repo_root)
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["no-automatic-downgrade"]["state"] == FAIL
    assert report["state"] == FAIL


def test_preflight_reports_unavailable_without_docker(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    report = _preflight(manifest_path, which=lambda name: None)
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["compose-tool"]["state"] == UNAVAILABLE
    assert checks["volume-preservation"]["state"] == UNAVAILABLE
    assert report["state"] == UNAVAILABLE
    assert report["verified"] is False


def test_preflight_binds_previous_release_and_requires_distinct_digests(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    previous_path, _ = previous_release_manifest(tmp_path, manifest)
    report = _preflight(
        manifest_path,
        previous_manifest_path=previous_path,
        expected_previous_tag="v1.2.2",
        expected_previous_commit="b" * 40,
    )
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["previous-release"]["state"] == PASS
    assert report["state"] == PASS

    same = _preflight(manifest_path, previous_manifest_path=manifest_path)
    same_checks = {check["name"]: check for check in same["checks"]}
    assert same_checks["previous-release"]["state"] == FAIL
    assert "identical" in same_checks["previous-release"]["detail"]


def test_preflight_report_binding_rejects_tampering(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report = _preflight(manifest_path)
    path = tmp_path / "deployment-preflight.json"
    write_preflight_report(report, path)
    assert preflight_report_errors(report, manifest, manifest_path=manifest_path) == []

    wrong_subject = json.loads(json.dumps(report))
    wrong_subject["subject"]["commit"] = "c" * 40
    assert any(
        "subject.commit" in item
        for item in preflight_report_errors(wrong_subject, manifest, manifest_path=manifest_path)
    )

    failed = json.loads(json.dumps(report))
    failed["state"] = FAIL
    assert any(
        "not PASS" in item for item in preflight_report_errors(failed, manifest, manifest_path=manifest_path)
    )

    missing_check = json.loads(json.dumps(report))
    missing_check["checks"] = [
        check for check in missing_check["checks"] if check["name"] != "volume-preservation"
    ]
    assert any(
        "volume-preservation" in item
        for item in preflight_report_errors(missing_check, manifest, manifest_path=manifest_path)
    )

    previous_path, _ = previous_release_manifest(tmp_path, manifest)
    assert any(
        "manifest_sha256" in item
        for item in preflight_report_errors(report, manifest, manifest_path=previous_path)
    )


def test_preflight_rejects_invalid_manifest(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    manifest["release"]["commit"] = "not-a-commit"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(PreflightError):
        _preflight(manifest_path)
