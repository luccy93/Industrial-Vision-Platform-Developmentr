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
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from tools.release.manifest import (
    ManifestError,
    load_manifest,
    manifest_errors,
    sha256_file,
    utc_now_iso,
)
from tools.release.preflight import (
    PreflightError,
    run_preflight,
)
from tools.release.verification import (
    FAIL,
    NOT_RUN,
    PASS,
    UNAVAILABLE,
    CommandRunner,
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
STAGING_TARGET_OPTIONAL_FIELDS = ("previous_manifest",)
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
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    expected_repository: str | None = None,
    require_gpu_runtime: bool = False,
    require_rollback: bool = False,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None] = shutil.which,
    base_environment: Mapping[str, str] | None = None,
    now: Callable[[], str] = utc_now_iso,
) -> dict[str, Any]:
    """Qualify one explicit staging target without weakening any gate.

    The default mode is preflight-only. ``execute`` performs read-only live
    probes. A mutation mode is only selected when ``authorize`` exactly equals
    the target name; mutation execution itself is added by the V25 evidence
    collection phase.
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
        preflight_binding = {
            "path": preflight_item["path"],
            "sha256": preflight_item["sha256"],
            "state": preflight.get("state"),
            "verified": preflight.get("verified"),
            "manifest_sha256": preflight.get("manifest_sha256"),
        }

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

    checks.append(
        _check(
            "deployment-execution",
            NOT_RUN,
            True,
            "authorized mutation execution is not enabled in this build",
        )
    )
    checks.append(
        _check(
            "smoke",
            NOT_RUN,
            True,
            "post-deployment smoke evidence is not collected in this build",
        )
    )
    checks.append(
        _check(
            "evidence-collection",
            NOT_RUN,
            True,
            "release evidence collection is not enabled in this build",
        )
    )
    gpu_required = bool(target["gpu"]) or require_gpu_runtime
    checks.append(
        _check(
            "gpu-runtime",
            NOT_RUN,
            gpu_required,
            "GPU runtime evidence was not collected"
            if gpu_required
            else "GPU runtime is not required for this staging target",
        )
    )
    checks.append(
        _check(
            "rollback-rehearsal",
            NOT_RUN,
            require_rollback,
            "rollback rehearsal was not requested"
            if not require_rollback
            else "rollback rehearsal evidence was not collected",
        )
    )

    overall = _aggregate(checks)
    staging_qualified = (
        mode == "authorized-mutation"
        and overall == PASS
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
        "verification": None,
        "publication": None,
        "deployment": None,
        "smoke": None,
        "gpu_runtime": None,
        "gpu_inference": None,
        "rehearsal": None,
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
    preflight = report.get("preflight")
    if not isinstance(preflight, Mapping):
        errors.append("staging preflight binding is missing")
    else:
        if preflight.get("state") != PASS:
            errors.append(f"staging preflight binding state is {preflight.get('state')!r}, not PASS")
        errors.extend(
            _binding_evidence_errors(
                report,
                "preflight",
                preflight,
                evidence_dir or manifest_path.parent,
            )
        )
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
