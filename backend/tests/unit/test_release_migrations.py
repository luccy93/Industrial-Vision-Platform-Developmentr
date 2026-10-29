"""V25 migration compatibility and rollback safety tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend.tests.unit.release_evidence import previous_release_manifest
from backend.tests.unit.test_release_verification import REPO_ROOT, make_release
from tools.release.manifest import sha256_file
from tools.release.migrations import (
    MIGRATION_CHECK_FIELDS,
    MIGRATION_REPORT_FIELDS,
    MIGRATION_SUBJECT_FIELDS,
    check_migration_compatibility,
    migration_report_errors,
    write_migration_report,
)
from tools.release.verification import FAIL, PASS

GENERATED_AT = "2026-10-25T00:00:00Z"


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "repo"
    versions = root / "backend" / "alembic" / "versions"
    versions.mkdir(parents=True)
    for name, content in files.items():
        (versions / name).write_text(content, encoding="utf-8")
    return root


def _migration(revision: str, down: str | None, upgrade: str = "op.create_table('x')") -> str:
    return (
        "from alembic import op\n\n"
        f"revision = {revision!r}\n"
        f"down_revision = {down!r}\n\n"
        "def upgrade() -> None:\n"
        f"    {upgrade}\n\n"
        "def downgrade() -> None:\n"
        "    pass\n"
    )


def _checks(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {check["name"]: check for check in report["checks"]}


def test_current_repository_migration_graph_is_compatible(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    report = check_migration_compatibility(
        manifest_path,
        repo_root=REPO_ROOT,
        now=lambda: GENERATED_AT,
    )
    checks = _checks(report)
    assert report["generated_at"] == GENERATED_AT
    assert report["manifest_sha256"] == sha256_file(manifest_path)
    assert report["state"] == PASS
    assert report["verified"] is True
    assert checks["migration-graph"]["state"] == PASS
    assert checks["migration-single-head"]["state"] == PASS
    assert checks["upgrade-non-destructive"]["state"] == PASS
    assert checks["previous-release"]["state"] != PASS


def test_migration_report_detects_multiple_heads(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    root = _repo(
        tmp_path,
        {
            "001.py": _migration("001", None),
            "002.py": _migration("002", None),
        },
    )
    report = check_migration_compatibility(manifest_path, repo_root=root)
    assert report["state"] == FAIL
    assert _checks(report)["migration-single-head"]["state"] == FAIL


def test_migration_report_detects_missing_parent(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    root = _repo(tmp_path, {"001.py": _migration("001", "missing")})
    report = check_migration_compatibility(manifest_path, repo_root=root)
    assert report["state"] == FAIL
    assert "missing" in _checks(report)["migration-graph"]["detail"]


def test_migration_report_rejects_destructive_upgrade(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    root = _repo(
        tmp_path,
        {"001.py": _migration("001", None, "op.drop_table('audit_log')")},
    )
    report = check_migration_compatibility(manifest_path, repo_root=root)
    checks = _checks(report)
    assert report["state"] == FAIL
    assert checks["upgrade-non-destructive"]["state"] == FAIL
    assert "drop_table" in checks["upgrade-non-destructive"]["detail"]


def test_migration_report_rejects_destructive_sql_in_upgrade(tmp_path: Path) -> None:
    manifest_path, _, _ = make_release(tmp_path)
    root = _repo(
        tmp_path,
        {"001.py": _migration("001", None, "op.execute('DROP TABLE audit_log')")},
    )
    report = check_migration_compatibility(manifest_path, repo_root=root)
    assert report["state"] == FAIL
    assert "destructive SQL" in _checks(report)["upgrade-non-destructive"]["detail"]


def test_migration_report_accepts_distinct_previous_release(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    previous_path, _ = previous_release_manifest(tmp_path, manifest)
    report = check_migration_compatibility(
        manifest_path,
        repo_root=REPO_ROOT,
        previous_manifest_path=previous_path,
    )
    assert report["state"] == PASS
    assert report["previous_manifest_sha256"] == sha256_file(previous_path)
    assert _checks(report)["previous-release"]["state"] == PASS


def test_migration_report_errors_detect_manifest_tampering(tmp_path: Path) -> None:
    manifest_path, _, manifest = make_release(tmp_path)
    report = check_migration_compatibility(manifest_path, repo_root=REPO_ROOT)
    report_path = tmp_path / "migration-compatibility.json"
    write_migration_report(report, report_path)
    assert migration_report_errors(report, manifest, manifest_path=manifest_path) == []
    tampered = dict(report)
    tampered["manifest_sha256"] = "sha256:" + "0" * 64
    errors = migration_report_errors(tampered, manifest, manifest_path=manifest_path)
    assert any("not bound to the supplied manifest" in error for error in errors)


def test_migration_schema_matches_contract(tmp_path: Path) -> None:
    del tmp_path
    schema = json.loads(
        (REPO_ROOT / "release" / "migration-compatibility.schema.json").read_text(encoding="utf-8")
    )
    assert set(schema["required"]) == set(MIGRATION_REPORT_FIELDS)
    assert set(schema["$defs"]["check"]["required"]) == set(MIGRATION_CHECK_FIELDS)
    assert set(schema["$defs"]["subject"]["required"]) == set(MIGRATION_SUBJECT_FIELDS)
