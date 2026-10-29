"""Controlled staging qualification and mutation gating (V25).

A staging qualification is only meaningful when it names one exact target,
binds that target to one exact release manifest, and refuses to touch anything
until an operator supplies the target's name to ``--authorize``. This module
implements that control plane:

* preflight-only by default (no deployment mutation);
* ``--execute`` adds read-only live probes;
* ``--execute --authorize <target-name>`` is required before any mutation;
* production targets, production-like names, and production-like hosts are
  rejected before a command runs;
* every report is bound to the manifest bytes and every local evidence file by
  SHA-256.

``NOT_RUN``, ``UNAVAILABLE``, and ``SIMULATED`` never qualify a staging target.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from tools.release.deployment import (
    DeploymentError,
    deploy_release,
)
from tools.release.evidence import (
    EvidenceError,
    collect_release_evidence,
    evidence_report_errors,
)
from tools.release.gpu import (
    GpuError,
    qualify_gpu_runtime,
)
from tools.release.identity import verify_tag_commit
from tools.release.inference import (
    InferenceError,
    qualify_gpu_inference,
)
from tools.release.manifest import (
    ManifestError,
    load_manifest,
    manifest_errors,
    sha256_file,
    utc_now_iso,
)
from tools.release.migrations import (
    MigrationError,
    check_migration_compatibility,
)
from tools.release.preflight import (
    PreflightError,
    run_preflight,
)
from tools.release.rehearsal import (
    RehearsalError,
    run_rollback_rehearsal,
)
from tools.release.smoke import (
    SmokeError,
    run_smoke,
)
from tools.release.verification import (
    FAIL,
    NOT_RUN,
    PASS,
    UNAVAILABLE,
    CommandRunner,
    VerificationError,
    attestation_cli_support,
    default_runner,
)

STAGING_TARGET_SCHEMA_VERSION = 1
STAGING_SCHEMA_VERSION = 1
STAGING_MODES = ("preflight", "live-read", "authorized-mutation")
STAGING_TARGET_REQUIRED_FIELDS = (
    "schema_version",
    "name",
    "environment",
    "release",
    "api_url",
    "web_url",
    "ws_url",
    "smoke_username",
    "smoke_password_env",
    "compose_project",
    "compose_files",
    "gpu",
)
STAGING_TARGET_OPTIONAL_FIELDS = ("previous_manifest", "previous_verification_report")
STAGING_TARGET_FIELDS = STAGING_TARGET_REQUIRED_FIELDS + STAGING_TARGET_OPTIONAL_FIELDS
STAGING_TARGET_RELEASE_FIELDS = ("tag", "commit", "source_repository")
STAGING_SUBJECT_FIELDS = ("tag", "commit", "source_repository")
STAGING_CHECK_FIELDS = ("name", "state", "required", "detail", "command")
STAGING_EVIDENCE_FIELDS = ("kind", "path", "sha256")
STAGING_REPORT_FIELDS = (
    "schema_version",
    "generated_at",
    "target",
    "mode",
    "authorized",
    "manifest_sha256",
    "subject",
    "digests",
    "state",
    "staging_qualified",
    "production_qualified",
    "preflight",
    "verification",
    "publication",
    "migration",
    "deployment",
    "smoke",
    "gpu_runtime",
    "gpu_inference",
    "rehearsal",
    "evidence",
    "checks",
    "blockers",
    "limitations",
    "next_steps",
)

STAGING_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{2,62}$")
ENVIRONMENT_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
COMPOSE_PROJECT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
PRODUCTION_TOKENS = frozenset({"prod", "production", "prd"})
REQUIRED_STAGING_CHECKS = (
    "target-definition",
    "target-environment",
    "production-exclusion",
    "target-release",
    "manifest",
    "preflight",
    "authorization",
    "migration-compatibility",
    "deployment-execution",
    "smoke",
    "evidence-collection",
)


class StagingError(RuntimeError):
    """The staging target or qualification request is invalid."""


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


def _digests(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        image.get("name"): image.get("digest")
        for image in manifest.get("images") or []
        if isinstance(image, Mapping) and isinstance(image.get("name"), str)
    }


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise StagingError(f"could not read staging target {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise StagingError(f"staging target {path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise StagingError("staging target must be a JSON object")
    return payload


def _production_marker(value: str) -> bool:
    lowered = value.lower()
    if "production" in lowered:
        return True
    tokens = re.split(r"[^a-z0-9]+", lowered)
    return any(token in PRODUCTION_TOKENS for token in tokens)


def _relative_path_errors(value: Any, label: str) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return [f"{label} must be a non-empty relative path"]
    if value.startswith("~"):
        return [f"{label} must not use home-directory expansion"]
    path = Path(value)
    if path.is_absolute() or path.drive:
        return [f"{label} must be relative to the repository root"]
    if any(part in {"..", ""} for part in path.parts):
        return [f"{label} must not contain parent-directory segments"]
    return []


def _url_errors(value: Any, label: str, scheme: str) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return [f"{label} must be a non-empty URL"]
    parts = urlsplit(value)
    errors: list[str] = []
    if parts.scheme != scheme:
        errors.append(f"{label} must use {scheme}://")
    if not parts.hostname:
        errors.append(f"{label} must include a hostname")
    else:
        if _production_marker(parts.hostname):
            errors.append(f"{label} hostname looks like a production host")
        for part in parts.hostname.lower().split("."):
            if part in PRODUCTION_TOKENS:
                errors.append(f"{label} hostname looks like a production host")
                break
    if parts.username or parts.password:
        errors.append(f"{label} must not embed credentials")
    if parts.query or parts.fragment:
        errors.append(f"{label} must not include a query string or fragment")
    return errors


def staging_target_errors(payload: Mapping[str, Any]) -> list[str]:
    """Return every reason a staging target definition is unsafe or invalid."""
    errors: list[str] = []
    missing = [field for field in STAGING_TARGET_REQUIRED_FIELDS if field not in payload]
    unknown = sorted(set(payload) - set(STAGING_TARGET_FIELDS))
    if missing:
        errors.append("missing fields: " + ", ".join(missing))
    if unknown:
        errors.append("unknown fields: " + ", ".join(unknown))
    if payload.get("schema_version") != STAGING_TARGET_SCHEMA_VERSION:
        errors.append(f"schema_version must be {STAGING_TARGET_SCHEMA_VERSION}")
    name = payload.get("name")
    if not isinstance(name, str) or STAGING_NAME_PATTERN.fullmatch(name) is None:
        errors.append("name must be a lowercase staging identifier")
    elif _production_marker(name):
        errors.append("name looks like a production target")
    if payload.get("environment") != "staging":
        errors.append("environment must be exactly 'staging'")
    release = payload.get("release")
    if not isinstance(release, Mapping):
        errors.append("release must be an object")
    else:
        release_missing = [
            field for field in STAGING_TARGET_RELEASE_FIELDS if not isinstance(release.get(field), str)
        ]
        if release_missing:
            errors.append("release is missing: " + ", ".join(release_missing))
        release_unknown = sorted(set(release) - set(STAGING_TARGET_RELEASE_FIELDS))
        if release_unknown:
            errors.append("release has unknown fields: " + ", ".join(release_unknown))
    errors.extend(_url_errors(payload.get("api_url"), "api_url", "https"))
    errors.extend(_url_errors(payload.get("web_url"), "web_url", "https"))
    errors.extend(_url_errors(payload.get("ws_url"), "ws_url", "wss"))
    username = payload.get("smoke_username")
    if not isinstance(username, str) or not username.strip():
        errors.append("smoke_username must be a non-empty string")
    password_env = payload.get("smoke_password_env")
    if not isinstance(password_env, str) or ENVIRONMENT_NAME_PATTERN.fullmatch(password_env) is None:
        errors.append("smoke_password_env must be an environment variable name")
    project = payload.get("compose_project")
    if not isinstance(project, str) or COMPOSE_PROJECT_PATTERN.fullmatch(project) is None:
        errors.append("compose_project must be a lowercase Compose project name")
    compose_files = payload.get("compose_files")
    if not isinstance(compose_files, list) or not compose_files:
        errors.append("compose_files must be a non-empty array")
    else:
        for index, item in enumerate(compose_files):
            errors.extend(_relative_path_errors(item, f"compose_files[{index}]"))
        if len(set(compose_files)) != len(compose_files):
            errors.append("compose_files must not contain duplicates")
    if not isinstance(payload.get("gpu"), bool):
        errors.append("gpu must be a boolean")
    if "previous_manifest" in payload and payload["previous_manifest"] is not None:
        errors.extend(_relative_path_errors(payload["previous_manifest"], "previous_manifest"))
    if "previous_verification_report" in payload and payload["previous_verification_report"] is not None:
        errors.extend(
            _relative_path_errors(
                payload["previous_verification_report"],
                "previous_verification_report",
            )
        )
    return errors


def load_staging_target(path: Path, *, repo_root: Path | None = None) -> dict[str, Any]:
    """Load and validate an explicit staging target.

    Validation is fail-closed: production targets and production-like names or
    hosts are rejected before the caller can run any command.
    """
    payload = _load_json_object(path)
    errors = staging_target_errors(payload)
    if errors:
        raise StagingError("staging target is invalid:\n- " + "\n- ".join(errors))
    if repo_root is not None:
        root = repo_root.resolve()
        for name in payload["compose_files"]:
            candidate = (root / name).resolve()
            if not candidate.is_relative_to(root):
                raise StagingError(f"compose file escapes the repository root: {name}")
            if not candidate.is_file():
                raise StagingError(f"compose file does not exist: {name}")
        previous = payload.get("previous_manifest")
        if previous is not None:
            candidate = (root / previous).resolve()
            if not candidate.is_relative_to(root):
                raise StagingError(f"previous_manifest escapes the repository root: {previous}")
            if not candidate.is_file():
                raise StagingError(f"previous manifest does not exist: {previous}")
        previous_verification = payload.get("previous_verification_report")
        if previous_verification is not None:
            candidate = (root / previous_verification).resolve()
            if not candidate.is_relative_to(root):
                raise StagingError(
                    f"previous_verification_report escapes the repository root: {previous_verification}"
                )
            if not candidate.is_file():
                raise StagingError(f"previous verification report does not exist: {previous_verification}")
    return payload


def _target_summary(target: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": target.get("name"),
        "environment": target.get("environment"),
        "api_url": target.get("api_url"),
        "web_url": target.get("web_url"),
        "ws_url": target.get("ws_url"),
        "smoke_username": target.get("smoke_username"),
        "smoke_password_env": target.get("smoke_password_env"),
        "compose_project": target.get("compose_project"),
        "compose_files": list(target.get("compose_files") or []),
        "gpu": target.get("gpu"),
        "previous_manifest": target.get("previous_manifest"),
        "previous_verification_report": target.get("previous_verification_report"),
    }


def _expected_release(
    target: Mapping[str, Any],
    *,
    expected_tag: str | None,
    expected_commit: str | None,
    expected_repository: str | None,
) -> dict[str, str]:
    release = target.get("release") if isinstance(target.get("release"), Mapping) else {}
    values = {
        "tag": release.get("tag"),
        "commit": release.get("commit"),
        "source_repository": release.get("source_repository"),
    }
    for field, supplied in (
        ("tag", expected_tag),
        ("commit", expected_commit),
        ("source_repository", expected_repository),
    ):
        if supplied is not None and supplied != values[field]:
            raise StagingError(
                f"supplied {field} {supplied!r} does not match the staging target's "
                f"release binding {values[field]!r}"
            )
    if not all(isinstance(value, str) for value in values.values()):
        raise StagingError("staging target release binding is incomplete")
    return {field: str(value) for field, value in values.items()}


def _target_release_check(target: Mapping[str, Any], manifest: Mapping[str, Any]) -> dict[str, Any]:
    release = target.get("release") if isinstance(target.get("release"), Mapping) else {}
    subject = _subject(manifest)
    mismatches = [
        field for field in STAGING_TARGET_RELEASE_FIELDS if release.get(field) != subject.get(field)
    ]
    if mismatches:
        return _check(
            "target-release",
            FAIL,
            True,
            "staging target release does not match the manifest: " + ", ".join(mismatches),
        )
    return _check(
        "target-release",
        PASS,
        True,
        f"staging target is bound to {subject.get('tag')} at {subject.get('commit')}",
    )


def _live_read_checks(
    *,
    runner: CommandRunner,
    which: Callable[[str], str | None],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    docker = which("docker")
    if docker is None:
        checks.append(_check("docker-cli", UNAVAILABLE, True, "docker is not installed"))
        checks.append(_check("docker-daemon", UNAVAILABLE, True, "docker daemon cannot be reached"))
        checks.append(_check("docker-compose", UNAVAILABLE, True, "docker compose is unavailable"))
    else:
        try:
            version = runner(["docker", "--version"], timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            checks.append(_check("docker-cli", UNAVAILABLE, True, f"docker could not run: {exc}"))
        else:
            checks.append(
                _check(
                    "docker-cli",
                    PASS if version.returncode == 0 else UNAVAILABLE,
                    True,
                    (version.stdout or "docker").strip()
                    if version.returncode == 0
                    else "docker could not be executed",
                )
            )
        try:
            daemon = runner(["docker", "version", "--format", "{{.Server.Version}}"], timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            checks.append(_check("docker-daemon", UNAVAILABLE, True, f"docker daemon probe failed: {exc}"))
        else:
            reachable = daemon.returncode == 0 and bool((daemon.stdout or "").strip())
            checks.append(
                _check(
                    "docker-daemon",
                    PASS if reachable else UNAVAILABLE,
                    True,
                    f"docker server {(daemon.stdout or '').strip()} is reachable"
                    if reachable
                    else "docker daemon is not reachable",
                )
            )
        try:
            compose = runner(["docker", "compose", "version"], timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            checks.append(_check("docker-compose", UNAVAILABLE, True, f"docker compose probe failed: {exc}"))
        else:
            checks.append(
                _check(
                    "docker-compose",
                    PASS if compose.returncode == 0 else UNAVAILABLE,
                    True,
                    (compose.stdout or "docker compose").strip()
                    if compose.returncode == 0
                    else "docker compose could not be executed",
                )
            )
    supported, detail = attestation_cli_support(runner, which)
    checks.append(_check("github-cli", PASS if supported else UNAVAILABLE, True, detail))
    return checks


def _authorization_check(
    *,
    mode: str,
    target_name: str,
    authorize: str | None,
) -> dict[str, Any]:
    if mode == "authorized-mutation":
        return _check(
            "authorization",
            PASS,
            True,
            f"mutation was explicitly authorized for staging target {target_name}",
        )
    if mode == "live-read":
        return _check(
            "authorization",
            NOT_RUN,
            True,
            f"read-only execution; mutations require --authorize {target_name}",
        )
    return _check(
        "authorization",
        NOT_RUN,
        True,
        "preflight only; pass --execute for live reads and --authorize for mutations",
    )


def _write_evidence(
    payload: Mapping[str, Any],
    evidence_dir: Path,
    filename: str,
    evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    path = evidence_dir / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    item = {"kind": filename.removesuffix(".json"), "path": path.name, "sha256": sha256_file(path)}
    evidence.append(item)
    return item


def _binding(
    item: Mapping[str, Any],
    report: Mapping[str, Any],
    *,
    kind: str | None = None,
) -> dict[str, Any]:
    binding: dict[str, Any] = {
        "kind": kind or item.get("kind"),
        "path": item.get("path"),
        "sha256": item.get("sha256"),
        "state": report.get("state", report.get("overall_state")),
        "verified": report.get("verified"),
    }
    if report.get("manifest_sha256") is not None:
        binding["manifest_sha256"] = report.get("manifest_sha256")
    return binding


def _environment_value(
    name: str,
    base_environment: Mapping[str, str] | None,
) -> str | None:
    if base_environment is not None and name in base_environment:
        return base_environment[name]
    return os.environ.get(name)


def _component_detail(report: Mapping[str, Any]) -> str:
    state = report.get("state", report.get("overall_state"))
    blockers = report.get("blockers") or []
    if blockers:
        return f"{state}: " + "; ".join(str(item) for item in blockers[:4])
    return f"{state}: component evidence was collected"


def _component_check(
    name: str,
    report: Mapping[str, Any],
    *,
    required: bool = True,
) -> dict[str, Any]:
    return _check(
        name,
        str(report.get("state", report.get("overall_state"))),
        required,
        _component_detail(report),
    )


def run_staging_qualification(
    target_path: Path,
    manifest_path: Path,
    *,
    repo_root: Path,
    artifacts_dir: Path,
    output: Path,
    evidence_dir: Path | None = None,
    execute: bool = False,
    authorize: str | None = None,
    previous_manifest_path: Path | None = None,
    previous_verification_report_path: Path | None = None,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    expected_repository: str | None = None,
    require_gpu_runtime: bool = False,
    require_rollback: bool = False,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None] = shutil.which,
    base_environment: Mapping[str, str] | None = None,
    identity_verifier: Callable[..., None] = verify_tag_commit,
    evidence_collector: Callable[..., dict[str, Any]] = collect_release_evidence,
    deployment_executor: Callable[..., dict[str, Any]] = deploy_release,
    smoke_runner: Callable[..., dict[str, Any]] = run_smoke,
    gpu_runtime_runner: Callable[..., dict[str, Any]] = qualify_gpu_runtime,
    gpu_inference_runner: Callable[..., dict[str, Any]] = qualify_gpu_inference,
    rehearsal_runner: Callable[..., dict[str, Any]] = run_rollback_rehearsal,
    migration_runner: Callable[..., dict[str, Any]] = check_migration_compatibility,
    now: Callable[[], str] = utc_now_iso,
) -> dict[str, Any]:
    """Qualify one explicit staging target without weakening any gate.

    The default mode is preflight-only. ``execute`` performs read-only live
    probes and collects release evidence. Mutation mode is only selected when
    ``authorize`` exactly equals the target name; it then deploys the pinned
    digests, runs smoke and optional GPU/rehearsal evidence, and qualifies only
    when every required check is PASS.
    """
    if authorize is not None and not execute:
        raise StagingError("--authorize requires --execute")
    target = load_staging_target(target_path, repo_root=repo_root)
    if authorize is not None and authorize != target["name"]:
        raise StagingError(
            f"authorization {authorize!r} does not match the staging target name {target['name']!r}"
        )
    mode = "authorized-mutation" if authorize is not None else ("live-read" if execute else "preflight")
    if not manifest_path.is_file():
        raise StagingError(f"manifest does not exist: {manifest_path}")
    if not artifacts_dir.is_dir():
        raise StagingError(f"artifacts directory does not exist: {artifacts_dir}")
    if not repo_root.is_dir():
        raise StagingError(f"repository root does not exist: {repo_root}")
    try:
        manifest = load_manifest(manifest_path)
        manifest_sha = sha256_file(manifest_path)
    except (ManifestError, OSError) as exc:
        raise StagingError(str(exc)) from exc
    expected = _expected_release(
        target,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
        expected_repository=expected_repository,
    )

    evidence_dir = evidence_dir or output.parent
    if evidence_dir.resolve() != output.parent.resolve():
        raise StagingError("--evidence-dir must be the directory that contains --output")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []

    checks.append(
        _check("target-definition", PASS, True, f"staging target {target['name']} is explicitly defined")
    )
    checks.append(_check("target-environment", PASS, True, "target environment is staging"))
    production_markers = [
        value
        for value in (
            target["name"],
            urlsplit(target["api_url"]).hostname or "",
            urlsplit(target["web_url"]).hostname or "",
            urlsplit(target["ws_url"]).hostname or "",
        )
        if _production_marker(str(value))
    ]
    checks.append(
        _check(
            "production-exclusion",
            FAIL if production_markers else PASS,
            True,
            "target has production markers: " + ", ".join(production_markers)
            if production_markers
            else "target is classified as staging and has no production markers",
        )
    )
    checks.append(_target_release_check(target, manifest))

    manifest_problems = manifest_errors(
        manifest,
        artifacts_dir=artifacts_dir,
        expected_tag=expected["tag"],
        expected_commit=expected["commit"],
    )
    checks.append(
        _check(
            "manifest",
            FAIL if manifest_problems else PASS,
            True,
            "; ".join(manifest_problems[:12])
            if manifest_problems
            else "manifest and local evidence hashes are valid",
        )
    )

    if previous_manifest_path is not None:
        previous = previous_manifest_path
    elif target.get("previous_manifest") is not None:
        previous = repo_root / str(target["previous_manifest"])
    else:
        previous = None
    if previous_verification_report_path is not None:
        previous_verification = previous_verification_report_path
    elif target.get("previous_verification_report") is not None:
        previous_verification = repo_root / str(target["previous_verification_report"])
    else:
        previous_verification = None
    compose_files = [repo_root / str(name) for name in target["compose_files"]]

    preflight: dict[str, Any] | None = None
    preflight_binding: dict[str, Any] | None = None
    try:
        preflight = run_preflight(
            manifest_path,
            repo_root=repo_root,
            compose_files=compose_files,
            gpu=bool(target["gpu"]),
            project=str(target["compose_project"]),
            previous_manifest_path=previous,
            expected_tag=expected["tag"],
            expected_commit=expected["commit"],
            runner=runner,
            which=which,
            base_environment=base_environment,
            now=now,
        )
    except PreflightError as exc:
        checks.append(_check("preflight", FAIL, True, str(exc)))
    else:
        checks.append(
            _check(
                "preflight",
                str(preflight.get("state")),
                True,
                f"deployment preflight is {preflight.get('state')} "
                f"(manifest {preflight.get('manifest_sha256')})",
            )
        )
        preflight_item = _write_evidence(preflight, evidence_dir, "preflight.json", evidence)
        preflight_binding = _binding(preflight_item, preflight)

    checks.append(
        _authorization_check(
            mode=mode,
            target_name=str(target["name"]),
            authorize=authorize,
        )
    )
    if execute:
        checks.extend(_live_read_checks(runner=runner, which=which))
    else:
        for name in ("docker-cli", "docker-daemon", "docker-compose", "github-cli"):
            checks.append(
                _check(
                    name,
                    NOT_RUN,
                    False,
                    "read-only live probes were not requested; pass --execute",
                )
            )

    migration_binding: dict[str, Any] | None = None
    try:
        migration_report = migration_runner(
            manifest_path,
            repo_root=repo_root,
            previous_manifest_path=previous,
            expected_tag=expected["tag"],
            expected_commit=expected["commit"],
            now=now,
        )
    except MigrationError as exc:
        checks.append(_check("migration-compatibility", FAIL, True, str(exc)))
    else:
        migration_item = _write_evidence(
            migration_report,
            evidence_dir,
            "migration-compatibility.json",
            evidence,
        )
        migration_binding = _binding(migration_item, migration_report)
        checks.append(_component_check("migration-compatibility", migration_report))

    evidence_binding: dict[str, Any] | None = None
    verification_binding: dict[str, Any] | None = None
    publication_binding: dict[str, Any] | None = None
    verification_path: Path | None = None
    if not execute:
        checks.append(
            _check(
                "evidence-collection",
                NOT_RUN,
                True,
                "release evidence collection requires --execute",
            )
        )
    else:
        try:
            evidence_report = evidence_collector(
                manifest_path,
                artifacts_dir=artifacts_dir,
                repo_root=repo_root,
                execute=True,
                expected_tag=expected["tag"],
                expected_commit=expected["commit"],
                expected_repository=expected["source_repository"],
                runner=runner,
                which=which,
                identity_verifier=identity_verifier,
                now=now,
            )
        except (EvidenceError, VerificationError) as exc:
            checks.append(_check("evidence-collection", FAIL, True, str(exc)))
        else:
            evidence_item = _write_evidence(
                evidence_report,
                evidence_dir,
                "release-evidence.json",
                evidence,
            )
            evidence_binding = _binding(evidence_item, evidence_report, kind="release-evidence")
            publication_binding = dict(evidence_binding)
            publication_binding["github_release"] = evidence_report.get("github_release")
            verification_report = evidence_report.get("verification")
            if isinstance(verification_report, Mapping):
                verification_item = _write_evidence(
                    verification_report,
                    evidence_dir,
                    "release-verification.json",
                    evidence,
                )
                verification_binding = _binding(
                    verification_item,
                    verification_report,
                    kind="release-verification",
                )
                verification_path = evidence_dir / str(verification_item["path"])
            evidence_problems = evidence_report_errors(
                evidence_report,
                manifest,
                manifest_path=manifest_path,
                artifacts_dir=artifacts_dir,
                require_live=True,
            )
            state = str(evidence_report.get("state"))
            if evidence_problems and state == PASS:
                state = FAIL
            checks.append(
                _check(
                    "evidence-collection",
                    state,
                    True,
                    "release evidence is PASS, live, and bound to the manifest"
                    if state == PASS
                    else "; ".join(evidence_problems[:8]),
                )
            )

    deployment_binding: dict[str, Any] | None = None
    if mode != "authorized-mutation":
        checks.append(
            _check(
                "deployment-execution",
                NOT_RUN,
                True,
                "authorized mutation was not requested; pass --execute --authorize <target-name>",
            )
        )
    elif evidence_binding is None or evidence_binding.get("state") != PASS or verification_path is None:
        checks.append(
            _check(
                "deployment-execution",
                FAIL,
                True,
                "deployment was not attempted because release evidence is not PASS",
            )
        )
    elif preflight_binding is None or preflight_binding.get("state") != PASS:
        checks.append(
            _check(
                "deployment-execution",
                FAIL,
                True,
                "deployment was not attempted because preflight is not PASS",
            )
        )
    else:
        try:
            deployment_report = deployment_executor(
                manifest_path,
                compose_files=compose_files,
                verification_report_path=verification_path,
                preflight_report_path=evidence_dir / str(preflight_binding["path"]),
                gpu=bool(target["gpu"]),
                project=str(target["compose_project"]),
                execute=True,
                expected_tag=expected["tag"],
                expected_commit=expected["commit"],
                runner=runner,
                which=which,
                base_environment=base_environment,
                now=now,
            )
        except DeploymentError as exc:
            checks.append(_check("deployment-execution", FAIL, True, str(exc)))
        else:
            deployment_item = _write_evidence(
                deployment_report,
                evidence_dir,
                "deployment-execution.json",
                evidence,
            )
            deployment_binding = _binding(deployment_item, deployment_report)
            checks.append(_component_check("deployment-execution", deployment_report))

    smoke_binding: dict[str, Any] | None = None
    if mode != "authorized-mutation":
        checks.append(
            _check(
                "smoke",
                NOT_RUN,
                True,
                "post-deployment smoke checks require an authorized mutation run",
            )
        )
    elif deployment_binding is None or deployment_binding.get("state") != PASS:
        checks.append(
            _check(
                "smoke",
                FAIL,
                True,
                "smoke was not attempted because deployment is not PASS",
            )
        )
    else:
        password = _environment_value(
            str(target["smoke_password_env"]),
            base_environment,
        )
        username = str(target["smoke_username"]) if password else None
        try:
            smoke_report = smoke_runner(
                str(target["api_url"]),
                web_url=str(target["web_url"]),
                ws_url=str(target["ws_url"]),
                username=username,
                password=password,
                manifest_path=manifest_path,
                expected_tag=expected["tag"],
                expected_commit=expected["commit"],
                now=now,
            )
        except SmokeError as exc:
            checks.append(_check("smoke", FAIL, True, str(exc)))
        else:
            smoke_item = _write_evidence(smoke_report, evidence_dir, "smoke.json", evidence)
            smoke_binding = _binding(smoke_item, smoke_report)
            checks.append(_component_check("smoke", smoke_report))

    gpu_required = bool(target["gpu"]) or require_gpu_runtime
    gpu_runtime_binding: dict[str, Any] | None = None
    gpu_inference_binding: dict[str, Any] | None = None
    if not gpu_required:
        checks.append(
            _check(
                "gpu-runtime",
                NOT_RUN,
                False,
                "GPU runtime is not required for this staging target",
            )
        )
        checks.append(
            _check(
                "gpu-inference",
                NOT_RUN,
                False,
                "GPU inference is not required for this staging target",
            )
        )
    elif mode != "authorized-mutation":
        checks.append(
            _check(
                "gpu-runtime",
                NOT_RUN,
                True,
                "GPU runtime evidence requires an authorized mutation run",
            )
        )
        checks.append(
            _check(
                "gpu-inference",
                NOT_RUN,
                True,
                "GPU inference evidence requires an authorized mutation run",
            )
        )
    elif deployment_binding is None or deployment_binding.get("state") != PASS:
        checks.append(
            _check(
                "gpu-runtime",
                FAIL,
                True,
                "GPU runtime was not tested because deployment is not PASS",
            )
        )
        checks.append(
            _check(
                "gpu-inference",
                FAIL,
                True,
                "GPU inference was not tested because deployment is not PASS",
            )
        )
    else:
        try:
            gpu_runtime_report = gpu_runtime_runner(
                manifest_path,
                execute=True,
                expected_tag=expected["tag"],
                expected_commit=expected["commit"],
                runner=runner,
                which=which,
                now=now,
            )
        except GpuError as exc:
            checks.append(_check("gpu-runtime", FAIL, True, str(exc)))
        else:
            gpu_runtime_item = _write_evidence(
                gpu_runtime_report,
                evidence_dir,
                "gpu-runtime.json",
                evidence,
            )
            gpu_runtime_binding = _binding(gpu_runtime_item, gpu_runtime_report)
            checks.append(_component_check("gpu-runtime", gpu_runtime_report))
        if gpu_runtime_binding is None or gpu_runtime_binding.get("state") != PASS:
            checks.append(
                _check(
                    "gpu-inference",
                    FAIL,
                    True,
                    "GPU inference was not attempted because GPU runtime is not PASS",
                )
            )
        else:
            try:
                gpu_inference_report = gpu_inference_runner(
                    manifest_path,
                    execute=True,
                    expected_tag=expected["tag"],
                    expected_commit=expected["commit"],
                    runner=runner,
                    which=which,
                    now=now,
                )
            except InferenceError as exc:
                checks.append(_check("gpu-inference", FAIL, True, str(exc)))
            else:
                gpu_inference_item = _write_evidence(
                    gpu_inference_report,
                    evidence_dir,
                    "gpu-inference.json",
                    evidence,
                )
                gpu_inference_binding = _binding(gpu_inference_item, gpu_inference_report)
                checks.append(_component_check("gpu-inference", gpu_inference_report))

    rehearsal_binding: dict[str, Any] | None = None
    if not require_rollback:
        checks.append(
            _check(
                "rollback-rehearsal",
                NOT_RUN,
                False,
                "rollback rehearsal was not requested",
            )
        )
    elif mode != "authorized-mutation":
        checks.append(
            _check(
                "rollback-rehearsal",
                NOT_RUN,
                True,
                "rollback rehearsal requires an authorized mutation run",
            )
        )
    elif previous is None:
        checks.append(
            _check(
                "rollback-rehearsal",
                FAIL,
                True,
                "no previous release manifest was supplied",
            )
        )
    elif previous_verification is None:
        checks.append(
            _check(
                "rollback-rehearsal",
                FAIL,
                True,
                "no previous production verification report was supplied",
            )
        )
    elif migration_binding is None or migration_binding.get("state") != PASS:
        checks.append(
            _check(
                "rollback-rehearsal",
                FAIL,
                True,
                "rollback rehearsal was not attempted because migration compatibility is not PASS",
            )
        )
    elif deployment_binding is None or deployment_binding.get("state") != PASS:
        checks.append(
            _check(
                "rollback-rehearsal",
                FAIL,
                True,
                "rollback rehearsal was not attempted because deployment is not PASS",
            )
        )
    else:
        password = _environment_value(
            str(target["smoke_password_env"]),
            base_environment,
        )
        username = str(target["smoke_username"]) if password else None
        try:
            rehearsal_report = rehearsal_runner(
                manifest_path,
                previous,
                compose_files=compose_files,
                gpu=bool(target["gpu"]),
                project=str(target["compose_project"]),
                execute=True,
                target_verification_report=verification_path,
                previous_verification_report=previous_verification,
                migration_report_path=evidence_dir / str(migration_binding["path"]),
                smoke_api_url=str(target["api_url"]),
                smoke_web_url=str(target["web_url"]),
                smoke_username=username,
                smoke_password=password,
                evidence_dir=evidence_dir / "rehearsal",
                runner=runner,
                which=which,
                base_environment=base_environment,
                now=now,
            )
        except RehearsalError as exc:
            checks.append(_check("rollback-rehearsal", FAIL, True, str(exc)))
        else:
            rehearsal_item = _write_evidence(
                rehearsal_report,
                evidence_dir,
                "rollback-rehearsal.json",
                evidence,
            )
            rehearsal_binding = _binding(rehearsal_item, rehearsal_report)
            checks.append(_component_check("rollback-rehearsal", rehearsal_report))

    overall = _aggregate(checks)
    required_bindings = [
        preflight_binding,
        verification_binding,
        publication_binding,
        migration_binding,
        deployment_binding,
        smoke_binding,
    ]
    if gpu_required:
        required_bindings.extend([gpu_runtime_binding, gpu_inference_binding])
    if require_rollback:
        required_bindings.append(rehearsal_binding)
    bindings_ready = all(
        isinstance(binding, Mapping) and binding.get("state") == PASS for binding in required_bindings
    )
    staging_qualified = (
        mode == "authorized-mutation"
        and overall == PASS
        and bindings_ready
        and all(check.get("state") == PASS for check in checks if check.get("required") is True)
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
    next_steps = [
        "run preflight on the staging host and resolve every blocker",
        "supply --execute for read-only live probes",
        f"supply --execute --authorize {target['name']} only after the target and digests are confirmed",
    ]
    if mode == "preflight":
        next_steps.append("this run did not contact the staging deployment or perform any mutation")
    elif mode == "live-read":
        next_steps.append("this run collected read-only evidence and performed no mutation")
    return {
        "schema_version": STAGING_SCHEMA_VERSION,
        "generated_at": now(),
        "target": _target_summary(target),
        "mode": mode,
        "authorized": mode == "authorized-mutation",
        "manifest_sha256": manifest_sha,
        "subject": _subject(manifest),
        "digests": _digests(manifest),
        "state": overall,
        "staging_qualified": staging_qualified,
        "production_qualified": False,
        "preflight": preflight_binding,
        "verification": verification_binding,
        "publication": publication_binding,
        "migration": migration_binding,
        "deployment": deployment_binding,
        "smoke": smoke_binding,
        "gpu_runtime": gpu_runtime_binding,
        "gpu_inference": gpu_inference_binding,
        "rehearsal": rehearsal_binding,
        "evidence": evidence,
        "checks": checks,
        "blockers": blockers,
        "limitations": limitations,
        "next_steps": next_steps,
    }


def write_staging_report(report: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _plain_file_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and "/" not in value
        and "\\" not in value
        and value not in {".", ".."}
    )


def _binding_evidence_errors(
    report: Mapping[str, Any],
    kind: str,
    binding: Mapping[str, Any],
    evidence_dir: Path,
) -> list[str]:
    evidence = report.get("evidence")
    if not isinstance(evidence, list):
        return [f"staging report has no {kind} evidence"]
    matching = [item for item in evidence if isinstance(item, Mapping) and item.get("kind") == kind]
    if not matching:
        return [f"staging report has no {kind} evidence"]
    if not any(
        item.get("sha256") == binding.get("sha256") and item.get("path") == binding.get("path")
        for item in matching
    ):
        return [f"staging {kind} evidence does not match its binding"]
    path = evidence_dir / str(binding.get("path"))
    if not path.is_file():
        return [f"staging {kind} evidence file is missing: {binding.get('path')}"]
    try:
        actual = sha256_file(path)
    except OSError as exc:
        return [f"staging {kind} evidence file could not be hashed: {exc}"]
    if actual != binding.get("sha256"):
        return [f"staging {kind} evidence hash does not match"]
    return []


def staging_report_errors(
    report: Any,
    manifest: Mapping[str, Any],
    *,
    manifest_path: Path,
    evidence_dir: Path | None = None,
) -> list[str]:
    """Return every reason a staging report cannot authorize the target."""
    if not isinstance(report, Mapping):
        return ["staging report must be a JSON object"]
    errors: list[str] = []
    if report.get("schema_version") != STAGING_SCHEMA_VERSION:
        errors.append(f"staging report schema_version must be {STAGING_SCHEMA_VERSION}")
    try:
        expected_sha = sha256_file(manifest_path)
    except OSError as exc:
        return [f"could not hash manifest {manifest_path}: {exc}"]
    if report.get("manifest_sha256") != expected_sha:
        errors.append("staging report is not bound to the supplied manifest (manifest_sha256 mismatch)")
    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    subject = report.get("subject")
    if not isinstance(subject, Mapping):
        errors.append("staging report subject is missing")
    else:
        for field in STAGING_SUBJECT_FIELDS:
            if subject.get(field) != release.get(field):
                errors.append(f"staging report subject.{field} does not match the manifest release")
    target = report.get("target")
    if not isinstance(target, Mapping):
        errors.append("staging report target is missing")
    else:
        if target.get("environment") != "staging":
            errors.append("staging report target environment is not staging")
        name = target.get("name")
        if not isinstance(name, str) or STAGING_NAME_PATTERN.fullmatch(name) is None:
            errors.append("staging report target name is invalid")
        elif _production_marker(name):
            errors.append("staging report target name looks like a production target")
    mode = report.get("mode")
    if mode not in STAGING_MODES:
        errors.append(f"staging report mode {mode!r} is not recognized")
    if report.get("authorized") is not (mode == "authorized-mutation"):
        errors.append("staging report authorized flag is inconsistent with its mode")
    if mode != "authorized-mutation":
        errors.append("staging qualification requires an explicitly authorized mutation mode")
    if report.get("state") != PASS:
        errors.append(f"staging report state is {report.get('state')!r}, not PASS")
    if report.get("staging_qualified") is not True:
        errors.append("staging report staging_qualified is not true")
    if report.get("production_qualified") is not False:
        errors.append("staging report must never claim production qualification")
    checks = report.get("checks")
    if not isinstance(checks, list):
        errors.append("staging report checks are missing")
    else:
        for check in checks:
            if not isinstance(check, Mapping):
                errors.append("staging report contains a malformed check")
                continue
            if check.get("required") is True and check.get("state") != PASS:
                errors.append(
                    f"staging required check {check.get('name')} is {check.get('state')!r}, not PASS"
                )
        names = {check.get("name") for check in checks if isinstance(check, Mapping)}
        for name in REQUIRED_STAGING_CHECKS:
            if name not in names:
                errors.append(f"staging report has no {name} check")
    checks_by_name = (
        {str(check.get("name")): check for check in checks if isinstance(check, Mapping)}
        if isinstance(checks, list)
        else {}
    )

    def binding_errors(
        name: str,
        kind: str,
        *,
        required: bool = True,
        require_verified: bool = True,
    ) -> list[str]:
        binding = report.get(name)
        if not isinstance(binding, Mapping):
            return [f"staging {name} binding is missing"] if required else []
        problems: list[str] = []
        if binding.get("state") != PASS:
            problems.append(f"staging {name} binding state is {binding.get('state')!r}, not PASS")
        if require_verified and binding.get("verified") is not True:
            problems.append(f"staging {name} binding is not verified")
        if binding.get("manifest_sha256") not in (None, expected_sha):
            problems.append(f"staging {name} binding is not bound to the supplied manifest")
        problems.extend(
            _binding_evidence_errors(
                report,
                kind,
                binding,
                evidence_dir or manifest_path.parent,
            )
        )
        return problems

    errors.extend(binding_errors("preflight", "preflight"))
    errors.extend(binding_errors("verification", "release-verification"))
    publication_errors = binding_errors("publication", "release-evidence")
    publication = report.get("publication")
    if isinstance(publication, Mapping):
        github_release = publication.get("github_release")
        if not isinstance(github_release, Mapping) or github_release.get("state") != PASS:
            publication_errors.append(
                "staging publication evidence does not prove a published GitHub Release"
            )
    errors.extend(publication_errors)
    errors.extend(binding_errors("migration", "migration-compatibility"))
    errors.extend(binding_errors("deployment", "deployment-execution", require_verified=False))
    errors.extend(binding_errors("smoke", "smoke"))
    for check_name, binding_name, kind in (
        ("gpu-runtime", "gpu_runtime", "gpu-runtime"),
        ("gpu-inference", "gpu_inference", "gpu-inference"),
        ("rollback-rehearsal", "rehearsal", "rollback-rehearsal"),
    ):
        check = checks_by_name.get(check_name)
        if isinstance(check, Mapping) and check.get("required") is True:
            errors.extend(binding_errors(binding_name, kind))
    evidence = report.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append("staging report evidence is missing")
    else:
        for item in evidence:
            if not isinstance(item, Mapping):
                errors.append("staging report evidence contains a malformed entry")
                continue
            if not _plain_file_name(item.get("path")):
                errors.append("staging report evidence path is invalid")
                continue
            digest = item.get("sha256")
            if not isinstance(digest, str):
                errors.append("staging report evidence hash is invalid")
                continue
            path = (evidence_dir or manifest_path.parent) / str(item["path"])
            if not path.is_file():
                errors.append(f"staging report evidence file is missing: {item['path']}")
                continue
            try:
                actual = sha256_file(path)
            except OSError as exc:
                errors.append(f"staging report evidence file could not be hashed: {exc}")
                continue
            if actual != digest:
                errors.append(f"staging report evidence hash does not match {item['path']}")
    return errors


def render_staging_summary(report: Mapping[str, Any]) -> str:
    target = report.get("target") or {}
    subject = report.get("subject") or {}
    lines = [
        f"Staging qualification: {report.get('state')} "
        f"(target={target.get('name')}, mode={report.get('mode')}, "
        f"authorized={report.get('authorized')}, staging_qualified={report.get('staging_qualified')})",
        f"Environment: {target.get('environment')}",
        f"API: {target.get('api_url')} | Web: {target.get('web_url')} | WS: {target.get('ws_url')}",
        f"Subject: {subject.get('tag')} at {subject.get('commit')} from {subject.get('source_repository')}",
        f"Manifest: {report.get('manifest_sha256')}",
    ]
    for name, digest in (report.get("digests") or {}).items():
        lines.append(f"- digest {name}: {digest}")
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
    next_steps = report.get("next_steps") or []
    if next_steps:
        lines.append("Next steps:")
        lines.extend(f"- {item}" for item in next_steps)
    return "\n".join(lines) + "\n"
