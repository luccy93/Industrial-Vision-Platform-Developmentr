"""Alembic migration compatibility and rollback safety evidence (V25).

Rollback safety is not just "start the previous image". The current migration
graph must be readable, have exactly one head, contain no missing parents or
cycles, and the ``upgrade`` path must not silently drop data. Downgrade
functions may exist for developer use, but a release rollback never runs them
automatically: the previous release is redeployed by digest and the database is
restored from a verified backup if necessary.

This module is deliberately static. It parses migration files with ``ast`` and
never imports or executes them, so it is safe to run before a deployment.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from tools.release.manifest import (
    ManifestError,
    load_manifest,
    manifest_errors,
    sha256_file,
    utc_now_iso,
)
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

MIGRATION_SCHEMA_VERSION = 1
MIGRATION_REPORT_FIELDS = (
    "schema_version",
    "generated_at",
    "manifest_sha256",
    "subject",
    "previous_manifest_sha256",
    "revisions",
    "heads",
    "state",
    "verified",
    "checks",
    "blockers",
    "limitations",
)
MIGRATION_SUBJECT_FIELDS = ("tag", "commit", "source_repository")
MIGRATION_CHECK_FIELDS = ("name", "state", "required", "detail")
DESTRUCTIVE_UPGRADE_CALLS = frozenset({"drop_table", "drop_column", "drop_constraint", "drop_index"})
DESTRUCTIVE_SQL = ("DROP ", "TRUNCATE ", "DELETE FROM ")


class MigrationError(RuntimeError):
    """The migration tree or compatibility request is invalid."""


def _check(name: str, state: str, required: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "state": state, "required": required, "detail": detail}


def _aggregate(checks: Sequence[Mapping[str, Any]]) -> str:
    states = {str(check.get("state")) for check in checks}
    required = {str(check.get("state")) for check in checks if check.get("required") is True}
    if FAIL in states:
        return FAIL
    if UNAVAILABLE in required:
        return UNAVAILABLE
    if NOT_RUN in required:
        return NOT_RUN
    return PASS


def _subject(manifest: Mapping[str, Any]) -> dict[str, Any]:
    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    return {
        "tag": release.get("tag"),
        "commit": release.get("commit"),
        "source_repository": release.get("source_repository"),
    }


def _literal(value: ast.AST | None) -> Any:
    if value is None:
        return None
    try:
        return ast.literal_eval(value)
    except (ValueError, SyntaxError):
        return None


def _function_operations(tree: ast.Module, name: str) -> list[str]:
    operations: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.name != name:
            continue
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            function = call.func
            if not isinstance(function, ast.Attribute):
                continue
            if not isinstance(function.value, ast.Name) or function.value.id != "op":
                continue
            operations.append(function.attr)
            if function.attr == "execute" and call.args:
                sql = _literal(call.args[0])
                if isinstance(sql, str):
                    operations.append(sql.upper())
    return operations


def _parse_migration(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MigrationError(f"could not read migration {path}: {exc}") from exc
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        raise MigrationError(f"migration {path} is not valid Python: {exc}") from exc
    revision: Any = None
    down_revision: Any = None
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        if target.id == "revision":
            revision = _literal(node.value)
        elif target.id == "down_revision":
            down_revision = _literal(node.value)
    if not isinstance(revision, str) or not revision:
        raise MigrationError(f"migration {path.name} has no string revision")
    if isinstance(down_revision, list):
        down_revision = tuple(down_revision)
    if down_revision is not None and not isinstance(down_revision, (str, tuple)):
        raise MigrationError(f"migration {path.name} has an invalid down_revision")
    if isinstance(down_revision, tuple) and not all(isinstance(item, str) for item in down_revision):
        raise MigrationError(f"migration {path.name} has an invalid down_revision tuple")
    return {
        "revision": revision,
        "down_revision": down_revision,
        "path": path.name,
        "upgrade_operations": _function_operations(tree, "upgrade"),
        "has_downgrade": any(
            isinstance(node, ast.FunctionDef) and node.name == "downgrade" for node in tree.body
        ),
    }


def _graph(versions_dir: Path) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    revisions: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        files = sorted(versions_dir.glob("*.py"))
    except OSError as exc:
        return [], [f"migration versions directory could not be read: {exc}"], []
    if not files:
        return [], ["no migration files were found"], []
    for path in files:
        try:
            revisions.append(_parse_migration(path))
        except MigrationError as exc:
            errors.append(str(exc))
    by_id: dict[str, dict[str, Any]] = {}
    for revision in revisions:
        revision_id = revision["revision"]
        if revision_id in by_id:
            errors.append(f"duplicate revision {revision_id}")
        by_id[revision_id] = revision
    children: dict[str, list[str]] = {revision_id: [] for revision_id in by_id}
    for revision in revisions:
        down = revision["down_revision"]
        parents = () if down is None else (down,) if isinstance(down, str) else down
        for parent in parents:
            if parent not in by_id:
                errors.append(f"revision {revision['revision']} references missing parent {parent}")
            else:
                children[parent].append(revision["revision"])
    for revision in revisions:
        revision_id = revision["revision"]
        down = revision["down_revision"]
        parents = () if down is None else (down,) if isinstance(down, str) else down
        if revision_id in parents:
            errors.append(f"revision {revision_id} is its own parent")
    heads = sorted(revision_id for revision_id, kids in children.items() if not kids)
    return revisions, errors, heads


def _destructive_upgrade_errors(revisions: Sequence[Mapping[str, Any]]) -> list[str]:
    errors: list[str] = []
    for revision in revisions:
        for operation in revision.get("upgrade_operations") or []:
            if operation in DESTRUCTIVE_UPGRADE_CALLS:
                errors.append(f"{revision['path']} calls op.{operation} in upgrade()")
            elif operation.startswith(DESTRUCTIVE_SQL):
                errors.append(f"{revision['path']} executes destructive SQL in upgrade()")
    return errors


def check_migration_compatibility(
    manifest_path: Path,
    *,
    repo_root: Path,
    previous_manifest_path: Path | None = None,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    now: Any = utc_now_iso,
) -> dict[str, Any]:
    """Return migration compatibility evidence bound to *manifest_path*."""
    try:
        manifest = load_manifest(manifest_path)
    except (ManifestError, OSError) as exc:
        raise MigrationError(str(exc)) from exc
    errors = manifest_errors(
        manifest,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
    )
    if errors:
        raise MigrationError("manifest is invalid:\n- " + "\n- ".join(errors))
    try:
        manifest_sha = sha256_file(manifest_path)
    except OSError as exc:
        raise MigrationError(f"could not hash manifest {manifest_path}: {exc}") from exc

    versions_dir = repo_root / "backend" / "alembic" / "versions"
    if not versions_dir.is_dir():
        revisions: list[dict[str, Any]] = []
        graph_errors = [f"migration versions directory does not exist: {versions_dir}"]
        heads: list[str] = []
    else:
        revisions, graph_errors, heads = _graph(versions_dir)

    checks: list[dict[str, Any]] = []
    checks.append(
        _check(
            "migration-graph",
            PASS if not graph_errors else FAIL,
            True,
            f"{len(revisions)} migrations form a complete revision graph"
            if not graph_errors
            else "; ".join(graph_errors[:8]),
        )
    )
    if len(heads) == 1:
        checks.append(_check("migration-single-head", PASS, True, f"exactly one migration head: {heads[0]}"))
    else:
        checks.append(
            _check(
                "migration-single-head",
                FAIL,
                True,
                "expected exactly one migration head, found " + (", ".join(heads) if heads else "none"),
            )
        )
    destructive = _destructive_upgrade_errors(revisions)
    checks.append(
        _check(
            "upgrade-non-destructive",
            PASS if not destructive else FAIL,
            True,
            "upgrade() functions contain no destructive schema operations"
            if not destructive
            else "; ".join(destructive[:8]),
        )
    )
    missing_downgrades = [revision["path"] for revision in revisions if not revision["has_downgrade"]]
    checks.append(
        _check(
            "downgrade-documented",
            PASS if not missing_downgrades else FAIL,
            False,
            "every migration documents a downgrade function"
            if not missing_downgrades
            else "migrations without downgrade(): " + ", ".join(missing_downgrades),
        )
    )

    previous_sha: str | None = None
    if previous_manifest_path is not None:
        try:
            previous = load_manifest(previous_manifest_path)
            previous_sha = sha256_file(previous_manifest_path)
        except (ManifestError, OSError) as exc:
            checks.append(_check("previous-release", FAIL, True, f"previous manifest is invalid: {exc}"))
        else:
            previous_errors = manifest_errors(previous)
            target_release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
            previous_release = previous.get("release") if isinstance(previous.get("release"), Mapping) else {}
            if previous_errors:
                checks.append(
                    _check(
                        "previous-release",
                        FAIL,
                        True,
                        "previous manifest is invalid: " + "; ".join(previous_errors[:8]),
                    )
                )
            elif previous_release.get("commit") == target_release.get("commit"):
                checks.append(
                    _check(
                        "previous-release",
                        FAIL,
                        True,
                        "previous manifest has the same commit as the target",
                    )
                )
            else:
                checks.append(
                    _check(
                        "previous-release",
                        PASS,
                        True,
                        f"previous release {previous_release.get('tag')} at "
                        f"{previous_release.get('commit')} is a distinct release",
                    )
                )
    else:
        checks.append(
            _check(
                "previous-release",
                NOT_RUN,
                False,
                "no previous release manifest was supplied; upgrade-path comparison was not tested",
            )
        )

    overall = _aggregate(checks)
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
        "schema_version": MIGRATION_SCHEMA_VERSION,
        "generated_at": now(),
        "manifest_sha256": manifest_sha,
        "subject": _subject(manifest),
        "previous_manifest_sha256": previous_sha,
        "revisions": [
            {
                "revision": revision["revision"],
                "down_revision": revision["down_revision"],
                "path": revision["path"],
            }
            for revision in revisions
        ],
        "heads": heads,
        "state": overall,
        "verified": overall == PASS,
        "checks": checks,
        "blockers": blockers,
        "limitations": limitations,
    }


def write_migration_report(report: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def migration_report_errors(
    report: Any,
    manifest: Mapping[str, Any],
    *,
    manifest_path: Path,
) -> list[str]:
    if not isinstance(report, Mapping):
        return ["migration report must be a JSON object"]
    errors: list[str] = []
    if report.get("schema_version") != MIGRATION_SCHEMA_VERSION:
        errors.append(f"migration report schema_version must be {MIGRATION_SCHEMA_VERSION}")
    try:
        expected_sha = sha256_file(manifest_path)
    except OSError as exc:
        return [f"could not hash manifest {manifest_path}: {exc}"]
    if report.get("manifest_sha256") != expected_sha:
        errors.append("migration report is not bound to the supplied manifest")
    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    subject = report.get("subject")
    if not isinstance(subject, Mapping):
        errors.append("migration report subject is missing")
    else:
        for field in MIGRATION_SUBJECT_FIELDS:
            if subject.get(field) != release.get(field):
                errors.append(f"migration report subject.{field} does not match the manifest release")
    if report.get("state") != PASS:
        errors.append(f"migration report state is {report.get('state')!r}, not PASS")
    if report.get("verified") is not True:
        errors.append("migration report verified is not true")
    checks = report.get("checks")
    if not isinstance(checks, list):
        errors.append("migration report checks are missing")
    else:
        for check in checks:
            if isinstance(check, Mapping) and check.get("required") is True and check.get("state") != PASS:
                errors.append(f"migration required check {check.get('name')} is not PASS")
    return errors


def render_migration_summary(report: Mapping[str, Any]) -> str:
    subject = report.get("subject") or {}
    lines = [
        f"Migration compatibility: {report.get('state')} (verified={report.get('verified')})",
        f"Subject: {subject.get('tag')} at {subject.get('commit')} from {subject.get('source_repository')}",
        f"Manifest: {report.get('manifest_sha256')}",
        "Revisions: "
        f"{len(report.get('revisions') or [])} | heads: "
        f"{', '.join(report.get('heads') or []) or 'none'}",
    ]
    for check in report.get("checks") or []:
        required = "required" if check.get("required") else "informational"
        lines.append(f"- {check.get('name')}: {check.get('state')} ({required}) - {check.get('detail')}")
    blockers = report.get("blockers") or []
    if blockers:
        lines.append("Blockers:")
        lines.extend(f"- {item}" for item in blockers)
    return "\n".join(lines) + "\n"
