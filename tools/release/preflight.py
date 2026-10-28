"""Deployment preflight and data-preservation evidence (V24).

Preflight runs before a release is deployed or qualified. It proves that the
digest-pinned Compose configuration resolves, the Alembic migration graph has a
single head with no missing parents, the deployment path never runs an
automatic downgrade, PostgreSQL data lives on a named volume, and the generated
rollback plan backs up data instead of deleting the volume.

The report is bound to the exact manifest bytes and release subject. Missing
Docker, an unreadable migration tree, or an unsafe rollback instruction is
reported as ``UNAVAILABLE`` or ``FAIL``, never as success.
"""

from __future__ import annotations

import ast
import json
import re
import shutil
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from tools.release.deployment import (
    DeploymentError,
    deployment_config_checks,
    render_rollback_plan,
)
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
)

PREFLIGHT_SCHEMA_VERSION = 1
PREFLIGHT_REPORT_FIELDS = (
    "schema_version",
    "generated_at",
    "manifest_sha256",
    "subject",
    "gpu",
    "state",
    "verified",
    "checks",
    "blockers",
    "limitations",
)
PREFLIGHT_SUBJECT_FIELDS = ("tag", "commit", "source_repository")
PREFLIGHT_CHECK_FIELDS = ("name", "state", "required", "detail", "command")
MIGRATION_VERSIONS = Path("backend") / "alembic" / "versions"
DOWNGRADE_PATTERN = re.compile(r"(?i)\balembic\b[^\n]*\bdowngrade\b")
REQUIRED_PREFLIGHT_CHECKS = (
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
)


class PreflightError(RuntimeError):
    """The deployment preflight could not be performed."""


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


def _migration_graph(versions_dir: Path) -> tuple[dict[str, Any], list[str]]:
    """Parse Alembic revisions without importing or executing migrations."""
    revisions: dict[str, tuple[str, ...]] = {}
    errors: list[str] = []
    for path in sorted(versions_dir.glob("*.py")):
        if path.name.startswith("__"):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            errors.append(f"{path.name} could not be parsed: {exc}")
            continue
        values: dict[str, Any] = {}
        for node in tree.body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name) or target.id not in ("revision", "down_revision"):
                continue
            try:
                values[target.id] = ast.literal_eval(node.value)
            except (ValueError, SyntaxError) as exc:
                errors.append(f"{path.name} has an unreadable {target.id}: {exc}")
        revision = values.get("revision")
        if not isinstance(revision, str) or not revision:
            errors.append(f"{path.name} has no string revision")
            continue
        down = values.get("down_revision")
        if down is None:
            parents: tuple[str, ...] = ()
        elif isinstance(down, str):
            parents = (down,)
        elif isinstance(down, tuple) and all(isinstance(item, str) for item in down):
            parents = down
        else:
            errors.append(f"{path.name} has an unsupported down_revision")
            parents = ()
        if revision in revisions:
            errors.append(f"duplicate revision {revision}")
        revisions[revision] = parents
    for revision, parents in sorted(revisions.items()):
        for parent in parents:
            if parent not in revisions:
                errors.append(f"revision {revision} references missing parent {parent}")
    heads = sorted(set(revisions) - {parent for parents in revisions.values() for parent in parents})
    return {"revisions": revisions, "heads": heads}, errors


def _migration_checks(repo_root: Path) -> list[dict[str, Any]]:
    versions_dir = repo_root / MIGRATION_VERSIONS
    if not versions_dir.is_dir():
        return [
            _check(
                "migration-history",
                FAIL,
                True,
                f"migration versions directory does not exist: {versions_dir}",
            ),
            _check(
                "migration-single-head",
                FAIL,
                True,
                "migration graph could not be read",
            ),
        ]
    graph, errors = _migration_graph(versions_dir)
    revisions = graph["revisions"]
    heads = graph["heads"]
    checks = [
        _check(
            "migration-history",
            FAIL if errors else PASS,
            True,
            "; ".join(errors[:8])
            if errors
            else f"{len(revisions)} migrations form a complete revision graph",
        )
    ]
    if errors:
        checks.append(_check("migration-single-head", FAIL, True, "; ".join(errors[:8])))
    elif len(heads) == 1:
        checks.append(
            _check(
                "migration-single-head",
                PASS,
                True,
                f"exactly one migration head: {heads[0]}",
            )
        )
    else:
        checks.append(
            _check(
                "migration-single-head",
                FAIL,
                True,
                "expected exactly one migration head, found " + (", ".join(heads) if heads else "none"),
            )
        )
    return checks


def _downgrade_checks(
    repo_root: Path,
    compose_files: Sequence[Path],
) -> list[dict[str, Any]]:
    candidates = list(compose_files) + [
        repo_root / "backend" / "Dockerfile",
        repo_root / "backend" / "entrypoint.sh",
        repo_root / "backend" / "docker-entrypoint.sh",
    ]
    findings: list[str] = []
    for path in candidates:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return [
                _check(
                    "no-automatic-downgrade",
                    FAIL,
                    True,
                    f"could not read {path}: {exc}",
                )
            ]
        if DOWNGRADE_PATTERN.search(text):
            findings.append(str(path))
    if findings:
        return [
            _check(
                "no-automatic-downgrade",
                FAIL,
                True,
                "automatic Alembic downgrade found in: " + ", ".join(findings),
            )
        ]
    return [
        _check(
            "no-automatic-downgrade",
            PASS,
            True,
            "deployment files run upgrades only; no automatic downgrade was found",
        )
    ]


def _volume_check(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    if payload is None:
        return _check(
            "volume-preservation",
            UNAVAILABLE,
            True,
            "Compose configuration did not resolve; PostgreSQL volume preservation was not proven",
        )
    services = payload.get("services")
    volumes = payload.get("volumes")
    named = set(volumes) if isinstance(volumes, Mapping) else set()
    postgres = services.get("postgres") if isinstance(services, Mapping) else None
    if not isinstance(postgres, Mapping):
        return _check("volume-preservation", FAIL, True, "compose has no postgres service")
    mounts = postgres.get("volumes")
    mounted: set[str] = set()
    if isinstance(mounts, list):
        for mount in mounts:
            if isinstance(mount, Mapping):
                source = mount.get("source")
                if isinstance(source, str):
                    mounted.add(source)
            elif isinstance(mount, str):
                mounted.add(mount.split(":", 1)[0])
    shared = sorted(named & mounted)
    if shared:
        return _check(
            "volume-preservation",
            PASS,
            True,
            "PostgreSQL data is stored on named volume " + ", ".join(shared),
        )
    return _check(
        "volume-preservation",
        FAIL,
        True,
        "postgres service does not mount a named volume; data could be lost on recreation",
    )


def _rollback_plan_check(
    manifest_path: Path,
    *,
    gpu: bool,
    expected_tag: str | None,
    expected_commit: str | None,
) -> dict[str, Any]:
    try:
        plan = render_rollback_plan(
            manifest_path,
            gpu=gpu,
            allow_unverified=True,
            expected_tag=expected_tag,
            expected_commit=expected_commit,
        )
    except DeploymentError as exc:
        return _check("rollback-plan-safety", FAIL, True, str(exc))
    destructive = [line for line in plan.splitlines() if "down -v" in line and "Never run" not in line]
    if "alembic downgrade" in plan.lower():
        return _check(
            "rollback-plan-safety",
            FAIL,
            True,
            "rollback plan contains an automatic Alembic downgrade",
        )
    if "pg_dump" not in plan:
        return _check(
            "rollback-plan-safety",
            FAIL,
            True,
            "rollback plan does not take a database backup",
        )
    if destructive:
        return _check(
            "rollback-plan-safety",
            FAIL,
            True,
            "rollback plan contains a volume-destroying command",
        )
    return _check(
        "rollback-plan-safety",
        PASS,
        True,
        "rollback plan takes a database backup and never deletes the PostgreSQL volume",
    )


def _previous_release_check(
    previous_manifest_path: Path,
    *,
    target_manifest: Mapping[str, Any],
    target_manifest_sha: str,
    expected_previous_tag: str | None,
    expected_previous_commit: str | None,
) -> dict[str, Any]:
    try:
        previous = load_manifest(previous_manifest_path)
    except ManifestError as exc:
        return _check("previous-release", FAIL, True, str(exc))
    errors = manifest_errors(
        previous,
        expected_tag=expected_previous_tag,
        expected_commit=expected_previous_commit,
    )
    if errors:
        return _check("previous-release", FAIL, True, "; ".join(errors[:8]))
    try:
        previous_sha = sha256_file(previous_manifest_path)
    except OSError as exc:
        return _check("previous-release", FAIL, True, f"could not hash previous manifest: {exc}")
    target_release = (
        target_manifest.get("release") if isinstance(target_manifest.get("release"), Mapping) else {}
    )
    previous_release = previous.get("release") if isinstance(previous.get("release"), Mapping) else {}
    if previous_sha == target_manifest_sha:
        return _check("previous-release", FAIL, True, "previous and target manifests are identical")
    if previous_release.get("commit") == target_release.get("commit"):
        return _check("previous-release", FAIL, True, "previous and target commits are identical")
    target_digests = {
        image.get("name"): image.get("digest")
        for image in target_manifest.get("images") or []
        if isinstance(image, Mapping)
    }
    previous_digests = {
        image.get("name"): image.get("digest")
        for image in previous.get("images") or []
        if isinstance(image, Mapping)
    }
    shared = set(target_digests) & set(previous_digests)
    if not shared or all(target_digests[name] == previous_digests[name] for name in shared):
        return _check(
            "previous-release",
            FAIL,
            True,
            "previous and target manifests do not contain different image digests",
        )
    return _check(
        "previous-release",
        PASS,
        True,
        f"previous release {previous_release.get('tag')} at {previous_release.get('commit')} "
        "has different digests and can be rehearsed",
    )


def run_preflight(
    manifest_path: Path,
    *,
    repo_root: Path,
    compose_files: Sequence[Path],
    gpu: bool = False,
    project: str | None = None,
    previous_manifest_path: Path | None = None,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    expected_previous_tag: str | None = None,
    expected_previous_commit: str | None = None,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None] = shutil.which,
    base_environment: Mapping[str, str] | None = None,
    now: Callable[[], str] = utc_now_iso,
) -> dict[str, Any]:
    try:
        manifest, config_checks, _, payload = deployment_config_checks(
            manifest_path,
            compose_files=compose_files,
            gpu=gpu,
            project=project,
            expected_tag=expected_tag,
            expected_commit=expected_commit,
            runner=runner,
            which=which,
            base_environment=base_environment,
        )
    except DeploymentError as exc:
        raise PreflightError(str(exc)) from exc
    try:
        manifest_sha = sha256_file(manifest_path)
    except OSError as exc:
        raise PreflightError(f"could not hash manifest {manifest_path}: {exc}") from exc

    checks: list[dict[str, Any]] = list(config_checks)
    checks.extend(_migration_checks(repo_root))
    checks.extend(_downgrade_checks(repo_root, compose_files))
    checks.append(_volume_check(payload))
    checks.append(
        _rollback_plan_check(
            manifest_path,
            gpu=gpu,
            expected_tag=expected_tag,
            expected_commit=expected_commit,
        )
    )
    if previous_manifest_path is not None:
        checks.append(
            _previous_release_check(
                previous_manifest_path,
                target_manifest=manifest,
                target_manifest_sha=manifest_sha,
                expected_previous_tag=expected_previous_tag,
                expected_previous_commit=expected_previous_commit,
            )
        )

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
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "generated_at": now(),
        "manifest_sha256": manifest_sha,
        "subject": _subject(manifest),
        "gpu": gpu,
        "state": overall,
        "verified": verified,
        "checks": checks,
        "blockers": blockers,
        "limitations": limitations,
    }


def write_preflight_report(report: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def preflight_report_errors(
    report: Any,
    manifest: Mapping[str, Any],
    *,
    manifest_path: Path,
) -> list[str]:
    if not isinstance(report, Mapping):
        return ["preflight report must be a JSON object"]
    errors: list[str] = []
    if report.get("schema_version") != PREFLIGHT_SCHEMA_VERSION:
        errors.append(f"preflight report schema_version must be {PREFLIGHT_SCHEMA_VERSION}")
    try:
        expected_sha = sha256_file(manifest_path)
    except OSError as exc:
        return [f"could not hash manifest {manifest_path}: {exc}"]
    if report.get("manifest_sha256") != expected_sha:
        errors.append("preflight report is not bound to the supplied manifest (manifest_sha256 mismatch)")
    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    subject = report.get("subject")
    if not isinstance(subject, Mapping):
        errors.append("preflight report subject is missing")
    else:
        for field in ("tag", "commit", "source_repository"):
            if subject.get(field) != release.get(field):
                errors.append(f"preflight report subject.{field} does not match the manifest release")
    if report.get("state") != PASS:
        errors.append(f"preflight report state is {report.get('state')!r}, not PASS")
    if report.get("verified") is not True:
        errors.append("preflight report verified is not true")
    checks = report.get("checks")
    if not isinstance(checks, list):
        errors.append("preflight report checks are missing")
    else:
        by_name = {
            item.get("name"): item
            for item in checks
            if isinstance(item, Mapping) and isinstance(item.get("name"), str)
        }
        for name in REQUIRED_PREFLIGHT_CHECKS:
            item = by_name.get(name)
            if item is None:
                errors.append(f"preflight report has no {name} check")
            elif item.get("state") != PASS:
                errors.append(f"preflight check {name} is {item.get('state')!r}, not PASS")
    return errors


def render_preflight_summary(report: Mapping[str, Any]) -> str:
    subject = report.get("subject") or {}
    lines = [
        f"Deployment preflight: {report.get('state')} "
        f"(verified={report.get('verified')}, gpu={report.get('gpu')})",
        f"Subject: {subject.get('tag')} at {subject.get('commit')} from {subject.get('source_repository')}",
        f"Manifest: {report.get('manifest_sha256')}",
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
