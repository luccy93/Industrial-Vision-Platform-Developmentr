"""Staging infrastructure readiness assessment (V26).

Readiness answers a narrower question than qualification or deployment: is this
host, repository checkout, release binding, and staging target actually prepared
for a future, separately authorized staging qualification run? It never deploys,
publishes, tags, or authorizes anything.

The default mode is a local preflight. It inspects the repository, installed
tools, the explicit staging target, the release manifest, Compose files, and
previously verified release/rollback evidence without contacting GitHub, GHCR,
staging, or production. ``execute_live`` adds bounded read-only probes and
marks them as live evidence.

``PASS`` means only that every required prerequisite was verified for the
stated scope. It does not mean production-qualified and it never authorizes a
deployment. ``NOT_RUN``, ``UNAVAILABLE``, and ``SIMULATED`` never satisfy a
required readiness check.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from tools.release.deployment import (
    DeploymentError,
    deployment_config_checks,
    verification_report_errors,
)
from tools.release.identity import (
    COMMIT_PATTERN,
    DIGEST_PATTERN,
    REQUIRED_IMAGES,
    SOURCE_REPOSITORY_PATTERN,
    TAG_PATTERN,
    IdentityError,
    validate_tag,
)
from tools.release.manifest import (
    ManifestError,
    load_manifest,
    manifest_errors,
    sha256_file,
    utc_now_iso,
)
from tools.release.rehearsal import REHEARSAL_SCHEMA_VERSION, STEP_NAMES
from tools.release.staging import staging_target_errors
from tools.release.verification import (
    FAIL,
    NOT_RUN,
    PASS,
    SIMULATED,
    UNAVAILABLE,
    CommandRunner,
    default_runner,
    is_placeholder_digest,
)

READINESS_SCHEMA_VERSION = 1
READINESS_PROFILE = "staging_readiness"
READINESS_EVIDENCE_DIR_NAME = "readiness-evidence"
READINESS_MODES = ("preflight", "live-read-only")
CHECK_MODES = ("local", "live-read-only", "simulated")
CHECK_CATEGORIES = (
    "repository",
    "release",
    "tooling",
    "github",
    "target",
    "deployment",
    "gpu",
)
READINESS_CHECK_FIELDS = (
    "name",
    "category",
    "state",
    "required",
    "mode",
    "detail",
    "command",
)
READINESS_EVIDENCE_FIELDS = ("kind", "path", "sha256", "state")
READINESS_BINDING_FIELDS = ("kind", "path", "sha256", "state")
READINESS_BINDING_NAMES = (
    "target",
    "manifest",
    "previous_manifest",
    "previous_verification",
    "rollback_evidence",
)
READINESS_BINDING_KINDS = {
    "target": "staging-target",
    "manifest": "release-manifest",
    "previous_manifest": "previous-manifest",
    "previous_verification": "previous-verification",
    "rollback_evidence": "rollback-evidence",
}
READINESS_REPORT_FIELDS = (
    "schema_version",
    "profile",
    "generated_at",
    "mode",
    "repository",
    "staging_target",
    "release",
    "gpu_required",
    "gpu_ready",
    "state",
    "ready",
    "production_qualified",
    "deployment",
    "checks",
    "evidence",
    "bindings",
    "blockers",
    "limitations",
    "next_steps",
)
REPOSITORY_FIELDS = (
    "source_repository",
    "commit",
    "branch",
    "tag",
    "tag_source",
    "tag_resolved_locally",
    "tag_matches_commit",
    "commit_resolved_locally",
    "reachable_from_main",
    "worktree_clean",
    "remote_matches_source",
)
RELEASE_FIELDS = ("manifest_sha256", "subject", "digests")
SUBJECT_FIELDS = ("tag", "commit", "source_repository")
TARGET_FIELDS = (
    "name",
    "environment",
    "api_url",
    "web_url",
    "ws_url",
    "smoke_username",
    "smoke_password_env",
    "compose_project",
    "compose_files",
    "gpu",
)
DEPLOYMENT_FIELDS = ("authorized", "performed", "statement")
DEPLOYMENT_STATEMENT = (
    "No deployment was authorized or performed by this readiness assessment. "
    "Readiness is not deployment authorization and does not prove production qualification."
)
GPU_CHECKS = (
    "gpu-hardware",
    "gpu-driver",
    "gpu-container-runtime",
    "gpu-image-digest",
)
MANDATORY_READINESS_CHECKS = (
    "repository-identity",
    "source-commit",
    "source-branch",
    "worktree-clean",
    "main-reachability",
    "previous-release",
    "previous-verification",
    "rollback-evidence",
    "git-cli",
    "python-runtime",
    "pytest",
    "ruff",
    "node",
    "npm",
    "github-cli",
    "github-auth-config",
    "registry-auth-config",
    "staging-target",
    "staging-target-environment",
    "staging-target-urls",
    "staging-target-production-exclusion",
    "staging-target-release-binding",
    "staging-target-smoke-config",
    "smoke-credential",
    "gpu-profile",
    "manifest",
    "manifest-digests",
    "compose-files",
    "compose-config",
    "compose-pins",
    "database-config",
    "redis-config",
    "volume-declarations",
    "health-endpoints",
    "port-configuration",
    "environment-config",
)
OPTIONAL_READINESS_CHECKS = (
    "release-tag",
    "release-tag-remote",
    "network-github",
    "network-ghcr",
)
READINESS_CHECK_NAMES = MANDATORY_READINESS_CHECKS + OPTIONAL_READINESS_CHECKS + GPU_CHECKS
ROLLBACK_REQUIRED_CHECKS = (
    "target-manifest",
    "previous-manifest",
    "distinct-release",
    "execution",
    *STEP_NAMES,
)

TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
STAGING_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{2,62}$")
ENVIRONMENT_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
COMPOSE_PROJECT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
PRODUCTION_TOKENS = frozenset({"prod", "production", "prd"})
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|"
    r"private[_-]?key)\b\s*(?P<separator>[=:])\s*[\"']?"
    r"(?!\[redacted\]|\*{3,}|<redacted>|redacted\b)[^\s\"',}]{8,}"
)
PRIVATE_KEY_MATERIAL = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
URL_CREDENTIALS = re.compile(r"(?i)(https?|wss?)://[^/@\s]+:[^/@\s]+@")
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024


class ReadinessError(RuntimeError):
    """The readiness assessment request or report is invalid."""


def _check(
    name: str,
    category: str,
    state: str,
    required: bool,
    mode: str,
    detail: str,
    command: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "category": category,
        "state": state,
        "required": required,
        "mode": mode,
        "detail": _sanitize_detail(detail),
        "command": command,
    }


def _aggregate(checks: Sequence[Mapping[str, Any]]) -> str:
    required_states = {str(check.get("state")) for check in checks if check.get("required") is True}
    if FAIL in required_states:
        return FAIL
    if SIMULATED in required_states:
        return SIMULATED
    if UNAVAILABLE in required_states:
        return UNAVAILABLE
    if NOT_RUN in required_states:
        return NOT_RUN
    return PASS


def _sanitize_detail(detail: str) -> str:
    text = URL_CREDENTIALS.sub(r"\1://[redacted]@", str(detail))

    def _redact(match: re.Match[str]) -> str:
        separator = match.group("separator")
        key = match.group(0).split(separator, 1)[0]
        return f"{key}{separator}[redacted]"

    text = SECRET_ASSIGNMENT.sub(_redact, text)
    return text[:500]


def _run(
    runner: CommandRunner,
    args: Sequence[str],
    *,
    timeout: int = 60,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str] | None:
    try:
        return runner(list(args), timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def _tcp_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReadinessError(f"could not read {label} {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ReadinessError(f"{label} {path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ReadinessError(f"{label} must be a JSON object")
    return payload


def _production_marker(value: str) -> bool:
    lowered = value.lower()
    if "production" in lowered:
        return True
    tokens = re.split(r"[^a-z0-9]+", lowered)
    return any(token in PRODUCTION_TOKENS for token in tokens)


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


def _remote_repository(value: str) -> str | None:
    """Extract owner/repo from a git remote without retaining credentials."""
    text = value.strip()
    if not text or URL_CREDENTIALS.search(text):
        return None
    candidate = text
    if candidate.startswith("git@") and ":" in candidate:
        host, path = candidate.split(":", 1)
        if host != "git@github.com":
            return None
        candidate = path
    else:
        parts = urlsplit(candidate)
        if parts.scheme not in ("https", "ssh", "git"):
            return None
        if parts.hostname not in ("github.com", "www.github.com"):
            return None
        candidate = parts.path
    candidate = candidate.strip("/")
    if candidate.endswith(".git"):
        candidate = candidate[: -len(".git")]
    if SOURCE_REPOSITORY_PATTERN.fullmatch(candidate) is None:
        return None
    return candidate


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
    }


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


def _plain_file_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and "/" not in value
        and "\\" not in value
        and value not in {".", ".."}
    )


def _secret_material(text: str) -> bool:
    return bool(SECRET_ASSIGNMENT.search(text) or PRIVATE_KEY_MATERIAL.search(text))


def _retain_evidence(
    source: Path | None,
    evidence_dir: Path,
    *,
    kind: str,
    state: str,
    evidence: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Retain an input file under a content-addressed name.

    The report never embeds the file contents. Files that appear to contain
    secret assignments or private-key material are not copied.
    """
    if source is None or not source.is_file():
        return None
    try:
        if source.stat().st_size > MAX_EVIDENCE_BYTES:
            return None
        digest = sha256_file(source)
        text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    if _secret_material(text):
        return None
    evidence_dir.mkdir(parents=True, exist_ok=True)
    if source.resolve().parent == evidence_dir.resolve():
        name = source.name
    else:
        name = f"{kind}-{digest.split(':', 1)[1][:12]}{source.suffix or '.json'}"
        destination = evidence_dir / name
        if not destination.exists():
            destination.write_bytes(source.read_bytes())
        elif sha256_file(destination) != digest:
            return None
    item = {"kind": kind, "path": name, "sha256": digest, "state": state}
    if not any(existing.get("kind") == kind and existing.get("sha256") == digest for existing in evidence):
        evidence.append(item)
    return dict(item)


def _tool_check(
    name: str,
    executable: str,
    version_args: Sequence[str],
    *,
    category: str,
    required: bool,
    runner: CommandRunner,
    which: Callable[[str], str | None],
    mode: str = "local",
) -> dict[str, Any]:
    if which(executable) is None:
        return _check(
            name,
            category,
            UNAVAILABLE,
            required,
            mode,
            f"{executable} is not installed",
        )
    result = _run(runner, version_args)
    if result is None or result.returncode != 0:
        return _check(
            name,
            category,
            UNAVAILABLE,
            required,
            mode,
            f"{executable} could not be executed",
        )
    first_line = (result.stdout or executable).strip().splitlines()
    detail = first_line[0] if first_line else f"{executable} is available"
    return _check(name, category, PASS, required, mode, detail)


def _docker_checks(
    *,
    runner: CommandRunner,
    which: Callable[[str], str | None],
    required: bool,
) -> list[dict[str, Any]]:
    if which("docker") is None:
        return [
            _check("docker-cli", "tooling", UNAVAILABLE, required, "local", "docker is not installed"),
            _check(
                "docker-daemon",
                "tooling",
                UNAVAILABLE,
                required,
                "local",
                "docker daemon cannot be reached because the CLI is absent",
            ),
            _check(
                "docker-compose",
                "tooling",
                UNAVAILABLE,
                required,
                "local",
                "docker compose is unavailable because the CLI is absent",
            ),
        ]
    checks = [
        _tool_check(
            "docker-cli",
            "docker",
            ["docker", "--version"],
            category="tooling",
            required=required,
            runner=runner,
            which=which,
        )
    ]
    daemon = _run(runner, ["docker", "version", "--format", "{{.Server.Version}}"])
    daemon_ok = daemon is not None and daemon.returncode == 0 and bool((daemon.stdout or "").strip())
    checks.append(
        _check(
            "docker-daemon",
            "tooling",
            PASS if daemon_ok else UNAVAILABLE,
            required,
            "local",
            f"docker server {(daemon.stdout or '').strip()} is reachable"
            if daemon_ok and daemon is not None
            else "docker daemon is not reachable; a Docker CLI installation alone does not prove a daemon",
        )
    )
    compose = _run(runner, ["docker", "compose", "version"])
    compose_ok = compose is not None and compose.returncode == 0
    checks.append(
        _check(
            "docker-compose",
            "tooling",
            PASS if compose_ok else UNAVAILABLE,
            required,
            "local",
            (compose.stdout or "docker compose").strip()
            if compose_ok and compose is not None
            else "docker compose could not be executed",
        )
    )
    return checks


def _registry_reference(manifest: Mapping[str, Any] | None) -> str | None:
    if manifest is None:
        return None
    for image in manifest.get("images") or []:
        if not isinstance(image, Mapping) or image.get("name") != "api":
            continue
        repository = image.get("repository")
        digest = image.get("digest")
        if (
            isinstance(repository, str)
            and isinstance(digest, str)
            and DIGEST_PATTERN.fullmatch(digest) is not None
            and not is_placeholder_digest(digest)
        ):
            return f"{repository}@{digest}"
    return None


def _github_checks(
    *,
    runner: CommandRunner,
    which: Callable[[str], str | None],
    environment: Mapping[str, str],
    execute_live: bool,
    network_probe: Callable[[str, int], bool],
    manifest: Mapping[str, Any] | None,
    manifest_valid: bool,
) -> list[dict[str, Any]]:
    gh_available = which("gh") is not None
    checks = [
        _tool_check(
            "github-cli",
            "gh",
            ["gh", "--version"],
            category="github",
            required=True,
            runner=runner,
            which=which,
        )
    ]
    github_token = next(
        (name for name in ("GH_TOKEN", "GITHUB_TOKEN") if environment.get(name)),
        None,
    )
    registry_token = next(
        (name for name in ("GH_TOKEN", "GITHUB_TOKEN", "CR_PAT", "GHCR_TOKEN") if environment.get(name)),
        None,
    )
    if github_token is None:
        checks.append(
            _check(
                "github-auth-config",
                "github",
                UNAVAILABLE,
                True,
                "local",
                "neither GH_TOKEN nor GITHUB_TOKEN is set",
            )
        )
    elif not gh_available:
        checks.append(
            _check(
                "github-auth-config",
                "github",
                UNAVAILABLE,
                True,
                "local",
                f"{github_token} is set but gh is not installed, so the credential was not validated",
            )
        )
    elif not execute_live:
        checks.append(
            _check(
                "github-auth-config",
                "github",
                UNAVAILABLE,
                True,
                "local",
                f"{github_token} is set but was not validated; "
                "credentials are not assumed valid because a variable exists",
            )
        )
    else:
        result = _run(runner, ["gh", "auth", "status"], timeout=30)
        ok = result is not None and result.returncode == 0
        checks.append(
            _check(
                "github-auth-config",
                "github",
                PASS if ok else UNAVAILABLE,
                True,
                "live-read-only",
                "gh auth status succeeded; the credential value was not inspected"
                if ok
                else "gh auth status failed; the credential is not usable",
            )
        )
    if registry_token is None:
        checks.append(
            _check(
                "registry-auth-config",
                "github",
                UNAVAILABLE,
                True,
                "local",
                "no GHCR credential variable is set (GH_TOKEN, GITHUB_TOKEN, CR_PAT, GHCR_TOKEN)",
            )
        )
    elif not execute_live:
        checks.append(
            _check(
                "registry-auth-config",
                "github",
                UNAVAILABLE,
                True,
                "local",
                f"{registry_token} is set but registry access was not validated; "
                "live read-only checks were not requested",
            )
        )
    elif not manifest_valid or manifest is None:
        checks.append(
            _check(
                "registry-auth-config",
                "github",
                NOT_RUN,
                True,
                "live-read-only",
                "a valid manifest is required before registry read access can be probed",
            )
        )
    else:
        reference = _registry_reference(manifest)
        if reference is None:
            checks.append(
                _check(
                    "registry-auth-config",
                    "github",
                    NOT_RUN,
                    True,
                    "live-read-only",
                    "the manifest has no immutable api image reference to probe",
                )
            )
        elif which("docker") is None:
            checks.append(
                _check(
                    "registry-auth-config",
                    "github",
                    UNAVAILABLE,
                    True,
                    "live-read-only",
                    f"{registry_token} is set but docker is not installed, "
                    "so registry read access was not probed",
                )
            )
        else:
            result = _run(runner, ["docker", "manifest", "inspect", reference], timeout=60)
            ok = result is not None and result.returncode == 0
            checks.append(
                _check(
                    "registry-auth-config",
                    "github",
                    PASS if ok else UNAVAILABLE,
                    True,
                    "live-read-only",
                    "a read-only registry manifest probe succeeded; no credential value was inspected"
                    if ok
                    else "a read-only registry manifest probe failed; the credential or access is not usable",
                )
            )
    for name, host, required in (
        ("network-github", "api.github.com", execute_live),
        ("network-ghcr", "ghcr.io", execute_live),
    ):
        if not execute_live:
            checks.append(
                _check(
                    name,
                    "github",
                    NOT_RUN,
                    False,
                    "local",
                    "live network probing was not requested; default readiness stays offline",
                )
            )
            continue
        try:
            reachable = network_probe(host, 443)
        except OSError:
            reachable = False
        checks.append(
            _check(
                name,
                "github",
                PASS if reachable else UNAVAILABLE,
                required,
                "live-read-only",
                f"{host}:443 is reachable" if reachable else f"{host}:443 is not reachable",
            )
        )
    return checks


def _repository_checks(
    *,
    repo_root: Path,
    expected_tag: str | None,
    expected_commit: str | None,
    expected_repository: str | None,
    expected_branch: str | None,
    main_ref: str,
    runner: CommandRunner,
    which: Callable[[str], str | None],
    environment: Mapping[str, str],
    execute_live: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    identity: dict[str, Any] = {
        "source_repository": None,
        "commit": None,
        "branch": None,
        "tag": expected_tag,
        "tag_source": "explicit" if expected_tag is not None else None,
        "tag_resolved_locally": False,
        "tag_matches_commit": False,
        "commit_resolved_locally": False,
        "reachable_from_main": False,
        "worktree_clean": False,
        "remote_matches_source": False,
    }
    checks.append(
        _tool_check(
            "git-cli",
            "git",
            ["git", "--version"],
            category="tooling",
            required=True,
            runner=runner,
            which=which,
        )
    )
    git_missing = which("git") is None
    if git_missing:
        checks.append(
            _check(
                "repository-identity",
                "repository",
                FAIL,
                True,
                "local",
                "git is not installed; repository identity could not be resolved",
            )
        )
    else:
        remote = _run(runner, ["git", "-C", str(repo_root), "remote", "get-url", "origin"])
        remote_url = (remote.stdout or "").strip() if remote is not None and remote.returncode == 0 else ""
        repository = _remote_repository(remote_url) if remote_url else None
        if repository is None:
            checks.append(
                _check(
                    "repository-identity",
                    "repository",
                    FAIL,
                    True,
                    "local",
                    "origin remote is missing or is not a supported GitHub repository URL",
                )
            )
        elif expected_repository is not None and repository != expected_repository:
            checks.append(
                _check(
                    "repository-identity",
                    "repository",
                    FAIL,
                    True,
                    "local",
                    f"origin repository {repository!r} does not match the expected repository",
                )
            )
        else:
            identity["source_repository"] = repository
            identity["remote_matches_source"] = True
            checks.append(
                _check(
                    "repository-identity",
                    "repository",
                    PASS,
                    True,
                    "local",
                    f"origin repository is {repository}",
                )
            )

    commit: str | None = None
    if not git_missing:
        result = _run(runner, ["git", "-C", str(repo_root), "rev-parse", "HEAD"])
        if result is not None and result.returncode == 0:
            candidate = (result.stdout or "").strip()
            if COMMIT_PATTERN.fullmatch(candidate):
                commit = candidate
    if commit is None:
        checks.append(
            _check(
                "source-commit",
                "repository",
                FAIL,
                True,
                "local",
                "HEAD could not be resolved to a 40-character commit",
            )
        )
    elif expected_commit is not None and commit != expected_commit:
        checks.append(
            _check(
                "source-commit",
                "repository",
                FAIL,
                True,
                "local",
                f"HEAD {commit} does not match the expected commit",
            )
        )
    else:
        identity["commit"] = commit
        identity["commit_resolved_locally"] = True
        checks.append(
            _check(
                "source-commit",
                "repository",
                PASS,
                True,
                "local",
                f"HEAD is {commit}",
            )
        )

    branch: str | None = None
    if not git_missing:
        result = _run(runner, ["git", "-C", str(repo_root), "rev-parse", "--abbrev-ref", "HEAD"])
        if result is not None and result.returncode == 0:
            candidate = (result.stdout or "").strip()
            if candidate and candidate != "HEAD":
                branch = candidate
    if branch is None:
        checks.append(
            _check(
                "source-branch",
                "repository",
                FAIL,
                True,
                "local",
                "HEAD is detached or the branch could not be resolved",
            )
        )
    elif expected_branch is not None and branch != expected_branch:
        checks.append(
            _check(
                "source-branch",
                "repository",
                FAIL,
                True,
                "local",
                f"current branch {branch!r} does not match the expected branch",
            )
        )
    else:
        identity["branch"] = branch
        checks.append(
            _check(
                "source-branch",
                "repository",
                PASS,
                True,
                "local",
                f"current branch is {branch}",
            )
        )

    if git_missing:
        checks.append(
            _check(
                "worktree-clean",
                "repository",
                FAIL,
                True,
                "local",
                "git is not installed; the working tree could not be inspected",
            )
        )
    else:
        result = _run(
            runner,
            ["git", "-C", str(repo_root), "status", "--porcelain", "--untracked-files=normal"],
        )
        if result is None or result.returncode != 0:
            checks.append(
                _check(
                    "worktree-clean",
                    "repository",
                    FAIL,
                    True,
                    "local",
                    "git status could not be read",
                )
            )
        elif (result.stdout or "").strip():
            checks.append(
                _check(
                    "worktree-clean",
                    "repository",
                    FAIL,
                    True,
                    "local",
                    "working tree is not clean; commit or remove local changes before readiness",
                )
            )
        else:
            identity["worktree_clean"] = True
            checks.append(
                _check(
                    "worktree-clean",
                    "repository",
                    PASS,
                    True,
                    "local",
                    "working tree is clean",
                )
            )

    if commit is not None:
        result = _run(
            runner,
            ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", commit, main_ref],
        )
        if result is not None and result.returncode == 0:
            identity["reachable_from_main"] = True
            checks.append(
                _check(
                    "main-reachability",
                    "repository",
                    PASS,
                    True,
                    "local",
                    f"HEAD is reachable from {main_ref}",
                )
            )
        elif result is not None and result.returncode == 1:
            checks.append(
                _check(
                    "main-reachability",
                    "repository",
                    FAIL,
                    True,
                    "local",
                    f"HEAD is not reachable from {main_ref}",
                )
            )
        else:
            checks.append(
                _check(
                    "main-reachability",
                    "repository",
                    UNAVAILABLE,
                    True,
                    "local",
                    f"{main_ref} could not be resolved locally",
                )
            )
    else:
        checks.append(
            _check(
                "main-reachability",
                "repository",
                NOT_RUN,
                True,
                "local",
                "HEAD is unknown; reachability was not evaluated",
            )
        )

    if expected_tag is None:
        checks.append(
            _check(
                "release-tag",
                "release",
                NOT_RUN,
                False,
                "local",
                "no stable release tag was explicitly supplied",
            )
        )
    else:
        try:
            validate_tag(expected_tag)
        except IdentityError as exc:
            checks.append(
                _check("release-tag", "release", FAIL, True, "local", f"release tag is invalid: {exc}")
            )
        else:
            resolved: str | None = None
            if not git_missing:
                result = _run(
                    runner,
                    [
                        "git",
                        "-C",
                        str(repo_root),
                        "rev-parse",
                        "--verify",
                        f"refs/tags/{expected_tag}^{{commit}}",
                    ],
                )
                if result is not None and result.returncode == 0:
                    resolved = (result.stdout or "").strip()
            if resolved is None:
                checks.append(
                    _check(
                        "release-tag",
                        "release",
                        FAIL,
                        True,
                        "local",
                        f"tag {expected_tag} does not resolve locally; remote state is not assumed",
                    )
                )
            elif commit is not None and resolved != commit:
                checks.append(
                    _check(
                        "release-tag",
                        "release",
                        FAIL,
                        True,
                        "local",
                        f"tag {expected_tag} resolves to {resolved}, not HEAD",
                    )
                )
            else:
                identity["tag_resolved_locally"] = True
                identity["tag_matches_commit"] = commit is not None and resolved == commit
                checks.append(
                    _check(
                        "release-tag",
                        "release",
                        PASS,
                        True,
                        "local",
                        f"tag {expected_tag} resolves locally to {resolved}",
                    )
                )

    if not execute_live:
        checks.append(
            _check(
                "release-tag-remote",
                "release",
                NOT_RUN,
                False,
                "local",
                "remote release state was not queried; local tag evidence is not remote proof",
            )
        )
    elif expected_tag is None:
        checks.append(
            _check(
                "release-tag-remote",
                "release",
                FAIL,
                True,
                "live-read-only",
                "live release verification requires an explicit --tag",
            )
        )
    elif identity["source_repository"] is None:
        checks.append(
            _check(
                "release-tag-remote",
                "release",
                UNAVAILABLE,
                True,
                "live-read-only",
                "repository identity is unknown; the remote release cannot be checked",
            )
        )
    else:
        result = _run(
            runner,
            [
                "gh",
                "release",
                "view",
                expected_tag,
                "--repo",
                str(identity["source_repository"]),
                "--json",
                "tagName,isDraft,isPrerelease",
            ],
            timeout=30,
        )
        if result is None or result.returncode != 0:
            checks.append(
                _check(
                    "release-tag-remote",
                    "release",
                    UNAVAILABLE,
                    True,
                    "live-read-only",
                    "the remote release could not be read; absence is not inferred from an error",
                )
            )
        else:
            try:
                payload = json.loads(result.stdout or "")
            except json.JSONDecodeError:
                payload = None
            if not isinstance(payload, Mapping) or payload.get("tagName") != expected_tag:
                checks.append(
                    _check(
                        "release-tag-remote",
                        "release",
                        FAIL,
                        True,
                        "live-read-only",
                        "the remote release does not identify the expected tag",
                    )
                )
            elif payload.get("isDraft") is True or payload.get("isPrerelease") is True:
                checks.append(
                    _check(
                        "release-tag-remote",
                        "release",
                        FAIL,
                        True,
                        "live-read-only",
                        "the remote release is a draft or prerelease",
                    )
                )
            else:
                checks.append(
                    _check(
                        "release-tag-remote",
                        "release",
                        PASS,
                        True,
                        "live-read-only",
                        f"GitHub reports a published release for {expected_tag}",
                    )
                )
    return checks, identity


def _release_checks(
    *,
    manifest_path: Path | None,
    manifest: Mapping[str, Any] | None,
    load_error: str | None,
    expected_tag: str | None,
    expected_commit: str | None,
    expected_repository: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any], str | None, bool]:
    checks: list[dict[str, Any]] = []
    release: dict[str, Any] = {
        "manifest_sha256": None,
        "subject": {"tag": None, "commit": None, "source_repository": None},
        "digests": {},
    }
    if manifest_path is None:
        checks.append(
            _check(
                "manifest",
                "release",
                FAIL,
                True,
                "local",
                "no release manifest was supplied; immutable digests cannot be verified",
            )
        )
        checks.append(
            _check(
                "manifest-digests",
                "release",
                NOT_RUN,
                True,
                "local",
                "manifest is missing; digest inputs were not evaluated",
            )
        )
        return checks, release, None, False
    if manifest is None:
        checks.append(
            _check(
                "manifest",
                "release",
                FAIL,
                True,
                "local",
                load_error or "the release manifest could not be loaded",
            )
        )
        checks.append(
            _check(
                "manifest-digests",
                "release",
                NOT_RUN,
                True,
                "local",
                "manifest is unreadable; digest inputs were not evaluated",
            )
        )
        return checks, release, None, False
    try:
        manifest_sha = sha256_file(manifest_path)
    except OSError as exc:
        checks.append(_check("manifest", "release", FAIL, True, "local", f"could not hash manifest: {exc}"))
        checks.append(
            _check(
                "manifest-digests",
                "release",
                NOT_RUN,
                True,
                "local",
                "manifest could not be hashed; digest inputs were not evaluated",
            )
        )
        return checks, release, None, False

    subject = _subject(manifest)
    problems = manifest_errors(
        manifest,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
    )
    for field, supplied in (
        ("tag", expected_tag),
        ("commit", expected_commit),
        ("source_repository", expected_repository),
    ):
        if supplied is not None and subject.get(field) != supplied:
            problems.append(f"manifest release.{field} does not match the supplied {field}")
    if problems:
        checks.append(
            _check(
                "manifest",
                "release",
                FAIL,
                True,
                "local",
                "; ".join(problems[:8]),
            )
        )
        valid = False
    else:
        checks.append(
            _check(
                "manifest",
                "release",
                PASS,
                True,
                "local",
                f"manifest is valid and bound to {subject.get('tag')} at {subject.get('commit')}",
            )
        )
        valid = True

    images = manifest.get("images")
    by_name = (
        {
            image.get("name"): image
            for image in images
            if isinstance(image, Mapping) and isinstance(image.get("name"), str)
        }
        if isinstance(images, list)
        else {}
    )
    digest_problems: list[str] = []
    for name in REQUIRED_IMAGES:
        image = by_name.get(name)
        if not isinstance(image, Mapping):
            digest_problems.append(f"missing image {name}")
            continue
        digest = image.get("digest")
        if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
            digest_problems.append(f"{name} has no immutable digest")
        elif is_placeholder_digest(digest):
            digest_problems.append(f"{name} has a placeholder digest")
        repository = image.get("repository")
        if not isinstance(repository, str) or not repository.strip():
            digest_problems.append(f"{name} has no repository")
    if digest_problems:
        checks.append(
            _check(
                "manifest-digests",
                "release",
                FAIL,
                True,
                "local",
                "; ".join(digest_problems[:8]),
            )
        )
        valid = False
    else:
        checks.append(
            _check(
                "manifest-digests",
                "release",
                PASS,
                True,
                "local",
                "all required images have immutable, non-placeholder digests",
            )
        )
    release = {
        "manifest_sha256": manifest_sha,
        "subject": subject,
        "digests": _digests(manifest),
    }
    return checks, release, manifest_sha, valid


def _target_checks(
    *,
    target_path: Path | None,
    target: Mapping[str, Any] | None,
    target_error: str | None,
    repo_root: Path,
    manifest: Mapping[str, Any] | None,
    manifest_sha: str | None,
    expected_tag: str | None,
    expected_commit: str | None,
    expected_repository: str | None,
    require_gpu: bool,
    environment: Mapping[str, str],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None, bool, bool]:
    checks: list[dict[str, Any]] = []
    if target_path is None:
        checks.append(
            _check(
                "staging-target",
                "target",
                FAIL,
                True,
                "local",
                "no staging target was explicitly supplied; targets are never inferred",
            )
        )
        for name, detail in (
            ("staging-target-environment", "staging target is missing"),
            ("staging-target-urls", "staging target is missing"),
            ("staging-target-production-exclusion", "staging target is missing"),
            ("staging-target-release-binding", "staging target is missing"),
            ("staging-target-smoke-config", "staging target is missing"),
            ("smoke-credential", "staging target is missing"),
            ("compose-files", "staging target is missing"),
            ("gpu-profile", "staging target is missing"),
        ):
            checks.append(_check(name, "target", NOT_RUN, True, "local", detail))
        return checks, None, False, require_gpu
    if target is None:
        checks.append(
            _check(
                "staging-target",
                "target",
                FAIL,
                True,
                "local",
                target_error or "the staging target could not be loaded",
            )
        )
        for name in (
            "staging-target-environment",
            "staging-target-urls",
            "staging-target-production-exclusion",
            "staging-target-release-binding",
            "staging-target-smoke-config",
            "smoke-credential",
            "compose-files",
            "gpu-profile",
        ):
            checks.append(_check(name, "target", NOT_RUN, True, "local", "staging target is invalid"))
        return checks, None, False, require_gpu

    errors = staging_target_errors(target)
    if errors:
        checks.append(
            _check(
                "staging-target",
                "target",
                FAIL,
                True,
                "local",
                "staging target is invalid:\n- " + "\n- ".join(errors[:8]),
            )
        )
        for name in (
            "staging-target-environment",
            "staging-target-urls",
            "staging-target-production-exclusion",
            "staging-target-release-binding",
            "staging-target-smoke-config",
            "smoke-credential",
            "compose-files",
            "gpu-profile",
        ):
            checks.append(_check(name, "target", NOT_RUN, True, "local", "staging target is invalid"))
        return checks, None, False, require_gpu

    summary = _target_summary(target)
    checks.append(
        _check(
            "staging-target",
            "target",
            PASS,
            True,
            "local",
            f"staging target {summary['name']} was explicitly supplied and is well formed",
        )
    )
    checks.append(
        _check(
            "staging-target-environment",
            "target",
            PASS if target.get("environment") == "staging" else FAIL,
            True,
            "local",
            "target environment is staging"
            if target.get("environment") == "staging"
            else "target environment is not staging",
        )
    )
    url_problems: list[str] = []
    for field, scheme in (("api_url", "https"), ("web_url", "https"), ("ws_url", "wss")):
        url_problems.extend(_url_errors(target.get(field), field, scheme))
    checks.append(
        _check(
            "staging-target-urls",
            "target",
            FAIL if url_problems else PASS,
            True,
            "local",
            "; ".join(url_problems[:8])
            if url_problems
            else "target URLs use approved schemes and contain no credentials or query tokens",
        )
    )
    production_markers = [
        str(value)
        for value in (
            target.get("name"),
            urlsplit(str(target.get("api_url", ""))).hostname or "",
            urlsplit(str(target.get("web_url", ""))).hostname or "",
            urlsplit(str(target.get("ws_url", ""))).hostname or "",
        )
        if _production_marker(value)
    ]
    checks.append(
        _check(
            "staging-target-production-exclusion",
            "target",
            FAIL if production_markers else PASS,
            True,
            "local",
            "target has production markers: " + ", ".join(production_markers)
            if production_markers
            else "target name and hosts contain no production markers",
        )
    )

    release = target.get("release") if isinstance(target.get("release"), Mapping) else {}
    binding_problems: list[str] = []
    if manifest is None:
        checks.append(
            _check(
                "staging-target-release-binding",
                "target",
                NOT_RUN,
                True,
                "local",
                "a release manifest is required to bind the target",
            )
        )
    else:
        subject = _subject(manifest)
        for field in SUBJECT_FIELDS:
            if release.get(field) != subject.get(field):
                binding_problems.append(field)
        for field, supplied in (
            ("tag", expected_tag),
            ("commit", expected_commit),
            ("source_repository", expected_repository),
        ):
            if supplied is not None and release.get(field) != supplied:
                binding_problems.append(field)
        checks.append(
            _check(
                "staging-target-release-binding",
                "target",
                FAIL if binding_problems else PASS,
                True,
                "local",
                "target release binding does not match the manifest: "
                + ", ".join(sorted(set(binding_problems)))
                if binding_problems
                else "target release binding matches the manifest",
            )
        )

    smoke_problems: list[str] = []
    if not isinstance(target.get("smoke_username"), str) or not str(target.get("smoke_username")).strip():
        smoke_problems.append("smoke_username is missing")
    password_env = target.get("smoke_password_env")
    if not isinstance(password_env, str) or ENVIRONMENT_NAME_PATTERN.fullmatch(password_env) is None:
        smoke_problems.append("smoke_password_env is not an environment variable name")
    checks.append(
        _check(
            "staging-target-smoke-config",
            "target",
            FAIL if smoke_problems else PASS,
            True,
            "local",
            "; ".join(smoke_problems)
            if smoke_problems
            else f"smoke account is configured and the password is read from {password_env}",
        )
    )
    if isinstance(password_env, str) and ENVIRONMENT_NAME_PATTERN.fullmatch(password_env):
        present = bool(environment.get(password_env))
        checks.append(
            _check(
                "smoke-credential",
                "target",
                PASS if present else UNAVAILABLE,
                True,
                "local",
                f"{password_env} is set; the value was not inspected"
                if present
                else f"{password_env} is not set in this environment",
            )
        )
    else:
        checks.append(
            _check(
                "smoke-credential",
                "target",
                NOT_RUN,
                True,
                "local",
                "smoke password environment variable is not configured",
            )
        )

    compose_problems: list[str] = []
    root = repo_root.resolve()
    for name in target.get("compose_files") or []:
        candidate = (root / str(name)).resolve()
        if not candidate.is_relative_to(root):
            compose_problems.append(f"{name} escapes the repository root")
        elif not candidate.is_file():
            compose_problems.append(f"{name} does not exist")
    checks.append(
        _check(
            "compose-files",
            "target",
            FAIL if compose_problems else PASS,
            True,
            "local",
            "; ".join(compose_problems[:8])
            if compose_problems
            else "all target Compose files exist under the repository root",
        )
    )

    target_gpu = bool(target.get("gpu"))
    gpu_required = require_gpu or target_gpu
    if require_gpu and not target_gpu:
        checks.append(
            _check(
                "gpu-profile",
                "gpu",
                FAIL,
                True,
                "local",
                "GPU readiness was requested but the staging target is CPU-only",
            )
        )
    elif target_gpu:
        checks.append(
            _check(
                "gpu-profile",
                "gpu",
                PASS,
                True,
                "local",
                "the staging target enables GPU, so GPU readiness is required",
            )
        )
    else:
        checks.append(
            _check(
                "gpu-profile",
                "gpu",
                PASS,
                True,
                "local",
                "CPU staging profile selected; GPU readiness is optional and reported separately",
            )
        )
    return checks, summary, True, gpu_required


def _environment_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, Mapping):
        keys.update(str(key) for key in value)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str) and "=" in item:
                keys.add(item.split("=", 1)[0])
    return keys


def _healthcheck_text(value: Any) -> str:
    if not isinstance(value, Mapping):
        return ""
    test = value.get("test")
    if isinstance(test, str):
        return test
    if isinstance(test, list):
        return " ".join(str(part) for part in test)
    return ""


def _port_entries(value: Any) -> list[Mapping[str, Any]]:
    entries: list[Mapping[str, Any]] = []
    if not isinstance(value, list):
        return entries
    for item in value:
        if isinstance(item, Mapping):
            entries.append(item)
        elif isinstance(item, str):
            entries.append({"raw": item})
    return entries


def _compose_payload_checks(
    payload: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    if payload is None:
        return [
            _check(
                name,
                "deployment",
                NOT_RUN,
                True,
                "local",
                "Compose configuration did not resolve; this prerequisite was not evaluated",
            )
            for name in (
                "database-config",
                "redis-config",
                "volume-declarations",
                "health-endpoints",
                "port-configuration",
                "environment-config",
            )
        ]
    services = payload.get("services")
    services = services if isinstance(services, Mapping) else {}
    volumes = payload.get("volumes")
    named_volumes = set(volumes) if isinstance(volumes, Mapping) else set()
    postgres = services.get("postgres")
    redis = services.get("redis")
    api = services.get("api")
    web = services.get("web")

    database_problems: list[str] = []
    if not isinstance(postgres, Mapping):
        database_problems.append("postgres service is missing")
    else:
        image = postgres.get("image")
        if not isinstance(image, str) or "postgres" not in image.lower():
            database_problems.append("postgres service does not use a PostgreSQL image")
        if "POSTGRES_PASSWORD" not in _environment_keys(postgres.get("environment")):
            database_problems.append("postgres service has no POSTGRES_PASSWORD reference")
        if not _healthcheck_text(postgres.get("healthcheck")):
            database_problems.append("postgres service has no healthcheck")
    checks = [
        _check(
            "database-config",
            "deployment",
            FAIL if database_problems else PASS,
            True,
            "local",
            "; ".join(database_problems)
            if database_problems
            else "postgres service, password reference, and healthcheck are configured",
        )
    ]

    redis_problems: list[str] = []
    if not isinstance(redis, Mapping):
        redis_problems.append("redis service is missing")
    else:
        image = redis.get("image")
        if not isinstance(image, str) or "redis" not in image.lower():
            redis_problems.append("redis service does not use a Redis image")
        if not _healthcheck_text(redis.get("healthcheck")):
            redis_problems.append("redis service has no healthcheck")
    checks.append(
        _check(
            "redis-config",
            "deployment",
            FAIL if redis_problems else PASS,
            True,
            "local",
            "; ".join(redis_problems) if redis_problems else "redis service and healthcheck are configured",
        )
    )

    def mounted_named(service: Any) -> set[str]:
        mounted: set[str] = set()
        if not isinstance(service, Mapping):
            return mounted
        for mount in service.get("volumes") or []:
            if isinstance(mount, Mapping):
                source = mount.get("source")
                if isinstance(source, str) and source in named_volumes:
                    mounted.add(source)
            elif isinstance(mount, str):
                source = mount.split(":", 1)[0]
                if source in named_volumes:
                    mounted.add(source)
        return mounted

    postgres_volumes = mounted_named(postgres)
    redis_volumes = mounted_named(redis)
    volume_problems: list[str] = []
    if not postgres_volumes:
        volume_problems.append("postgres does not mount a named volume")
    if isinstance(redis, Mapping) and not redis_volumes:
        volume_problems.append("redis does not mount a named volume")
    checks.append(
        _check(
            "volume-declarations",
            "deployment",
            FAIL if volume_problems else PASS,
            True,
            "local",
            "; ".join(volume_problems)
            if volume_problems
            else "PostgreSQL and Redis data are declared on named volumes",
        )
    )

    api_health = _healthcheck_text(api.get("healthcheck") if isinstance(api, Mapping) else None)
    web_health = _healthcheck_text(web.get("healthcheck") if isinstance(web, Mapping) else None)
    health_problems: list[str] = []
    if "/ready" not in api_health and "/live" not in api_health:
        health_problems.append("api healthcheck does not probe /ready or /live")
    if not web_health:
        health_problems.append("web healthcheck is missing")
    checks.append(
        _check(
            "health-endpoints",
            "deployment",
            FAIL if health_problems else PASS,
            True,
            "local",
            "; ".join(health_problems)
            if health_problems
            else "api and web healthchecks are configured; values are not printed",
        )
    )

    port_problems: list[str] = []
    for service_name, service in services.items():
        entries = _port_entries(service.get("ports") if isinstance(service, Mapping) else None)
        if service_name in ("postgres", "redis") and entries:
            port_problems.append(f"{service_name} publishes ports")
            continue
        for entry in entries:
            host_ip = entry.get("host_ip")
            if host_ip not in ("127.0.0.1", "::1"):
                port_problems.append(f"{service_name} publishes a port on all interfaces")
                break
    checks.append(
        _check(
            "port-configuration",
            "deployment",
            FAIL if port_problems else PASS,
            True,
            "local",
            "; ".join(port_problems[:8])
            if port_problems
            else "all published ports are loopback-only; postgres and redis publish no ports",
        )
    )

    api_keys = _environment_keys(api.get("environment") if isinstance(api, Mapping) else None)
    postgres_keys = _environment_keys(postgres.get("environment") if isinstance(postgres, Mapping) else None)
    environment_problems: list[str] = []
    if "DATABASE_URL" not in api_keys:
        environment_problems.append("api has no DATABASE_URL reference")
    if "REDIS_URL" not in api_keys and "REDIS_ENABLED" not in api_keys:
        environment_problems.append("api has no Redis configuration reference")
    if "POSTGRES_PASSWORD" not in postgres_keys:
        environment_problems.append("postgres has no POSTGRES_PASSWORD reference")
    checks.append(
        _check(
            "environment-config",
            "deployment",
            FAIL if environment_problems else PASS,
            True,
            "local",
            "; ".join(environment_problems)
            if environment_problems
            else (
                "required environment variable names and secret references are present; "
                "values are not printed"
            ),
        )
    )
    return checks


def _deployment_checks(
    *,
    manifest_path: Path | None,
    manifest: Mapping[str, Any] | None,
    manifest_valid: bool,
    target: Mapping[str, Any] | None,
    target_valid: bool,
    repo_root: Path,
    gpu_required: bool,
    runner: CommandRunner,
    which: Callable[[str], str | None],
    environment: Mapping[str, str],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    if not manifest_valid or manifest_path is None:
        checks.append(
            _check(
                "compose-config",
                "deployment",
                NOT_RUN,
                True,
                "local",
                "a valid release manifest is required before Compose can resolve digests",
            )
        )
        checks.append(
            _check(
                "compose-pins",
                "deployment",
                NOT_RUN,
                True,
                "local",
                "a valid release manifest is required before Compose pins can be checked",
            )
        )
        checks.extend(_compose_payload_checks(None))
        return checks
    if not target_valid or target is None:
        checks.append(
            _check(
                "compose-config",
                "deployment",
                NOT_RUN,
                True,
                "local",
                "a valid staging target is required before Compose can be resolved",
            )
        )
        checks.append(
            _check(
                "compose-pins",
                "deployment",
                NOT_RUN,
                True,
                "local",
                "a valid staging target is required before Compose pins can be checked",
            )
        )
        checks.extend(_compose_payload_checks(None))
        return checks
    compose_files = [repo_root / str(name) for name in target.get("compose_files") or []]
    try:
        _, config_checks, _, payload = deployment_config_checks(
            manifest_path,
            compose_files=compose_files,
            gpu=gpu_required,
            project=str(target.get("compose_project") or ""),
            runner=runner,
            which=which,
            base_environment=environment,
        )
    except DeploymentError as exc:
        checks.append(_check("compose-config", "deployment", FAIL, True, "local", str(exc)))
        checks.append(
            _check(
                "compose-pins",
                "deployment",
                NOT_RUN,
                True,
                "local",
                "Compose configuration did not resolve",
            )
        )
        checks.extend(_compose_payload_checks(None))
        return checks

    config = next(
        (item for item in config_checks if item.get("name") == "compose-config"),
        None,
    )
    if config is None:
        checks.append(
            _check(
                "compose-config",
                "deployment",
                UNAVAILABLE,
                True,
                "local",
                "docker compose did not report a configuration result",
            )
        )
    else:
        checks.append(
            _check(
                "compose-config",
                "deployment",
                str(config.get("state")),
                True,
                "local",
                str(config.get("detail") or "compose configuration result"),
                config.get("command") if isinstance(config.get("command"), str) else None,
            )
        )
    pins = [item for item in config_checks if str(item.get("name", "")).startswith("compose-pin:")]
    pin_problems = [str(item.get("detail")) for item in pins if item.get("state") != PASS]
    if not pins:
        checks.append(
            _check(
                "compose-pins",
                "deployment",
                NOT_RUN,
                True,
                "local",
                "no Compose service pins were reported",
            )
        )
    elif pin_problems:
        checks.append(
            _check(
                "compose-pins",
                "deployment",
                FAIL,
                True,
                "local",
                "; ".join(pin_problems[:8]),
            )
        )
    else:
        checks.append(
            _check(
                "compose-pins",
                "deployment",
                PASS,
                True,
                "local",
                "every Compose service is pinned to the manifest digest and has no local build",
            )
        )
    checks.extend(_compose_payload_checks(payload))
    return checks


def _previous_release_checks(
    *,
    previous_manifest_path: Path | None,
    previous_verification_report_path: Path | None,
    rollback_evidence_path: Path | None,
    manifest: Mapping[str, Any] | None,
    manifest_sha: str | None,
    manifest_valid: bool,
    now: Callable[[], str],
) -> tuple[list[dict[str, Any]], Mapping[str, Any] | None, str | None, bool]:
    del now
    checks: list[dict[str, Any]] = []
    previous: Mapping[str, Any] | None = None
    previous_sha: str | None = None
    previous_valid = False
    if previous_manifest_path is None:
        checks.append(
            _check(
                "previous-release",
                "release",
                FAIL,
                True,
                "local",
                "no previous known-good release manifest was supplied",
            )
        )
    elif not previous_manifest_path.is_file():
        checks.append(
            _check(
                "previous-release",
                "release",
                FAIL,
                True,
                "local",
                f"previous manifest does not exist: {previous_manifest_path}",
            )
        )
    else:
        try:
            loaded = load_manifest(previous_manifest_path)
            loaded_sha = sha256_file(previous_manifest_path)
            problems = manifest_errors(loaded)
        except (ManifestError, OSError) as exc:
            checks.append(_check("previous-release", "release", FAIL, True, "local", str(exc)))
        else:
            if problems:
                checks.append(
                    _check(
                        "previous-release",
                        "release",
                        FAIL,
                        True,
                        "local",
                        "; ".join(problems[:8]),
                    )
                )
            elif manifest_sha is not None and loaded_sha == manifest_sha:
                checks.append(
                    _check(
                        "previous-release",
                        "release",
                        FAIL,
                        True,
                        "local",
                        "previous and target manifests are identical; "
                        "rollback cannot restore a distinct release",
                    )
                )
            else:
                previous = loaded
                previous_sha = loaded_sha
                previous_valid = True
                checks.append(
                    _check(
                        "previous-release",
                        "release",
                        PASS,
                        True,
                        "local",
                        f"previous release {_subject(loaded).get('tag')} is known and distinct",
                    )
                )

    if previous_verification_report_path is None:
        checks.append(
            _check(
                "previous-verification",
                "release",
                FAIL,
                True,
                "local",
                "no previous production verification report was supplied",
            )
        )
    elif not previous_verification_report_path.is_file():
        checks.append(
            _check(
                "previous-verification",
                "release",
                FAIL,
                True,
                "local",
                f"previous verification report does not exist: {previous_verification_report_path}",
            )
        )
    elif not previous_valid or previous is None or previous_manifest_path is None:
        checks.append(
            _check(
                "previous-verification",
                "release",
                NOT_RUN,
                True,
                "local",
                "previous release manifest is not valid; verification was not evaluated",
            )
        )
    else:
        try:
            report = _load_json_object(previous_verification_report_path, "previous verification report")
        except ReadinessError as exc:
            checks.append(_check("previous-verification", "release", FAIL, True, "local", str(exc)))
        else:
            errors = verification_report_errors(
                report,
                previous,
                manifest_path=previous_manifest_path,
                require_production=True,
            )
            checks.append(
                _check(
                    "previous-verification",
                    "release",
                    FAIL if errors else PASS,
                    True,
                    "local",
                    "; ".join(errors[:8])
                    if errors
                    else "previous release has a production verification report bound to its bytes",
                )
            )

    if rollback_evidence_path is None:
        checks.append(
            _check(
                "rollback-evidence",
                "release",
                FAIL,
                True,
                "local",
                "no rollback rehearsal evidence was supplied",
            )
        )
    elif not rollback_evidence_path.is_file():
        checks.append(
            _check(
                "rollback-evidence",
                "release",
                FAIL,
                True,
                "local",
                f"rollback evidence does not exist: {rollback_evidence_path}",
            )
        )
    elif not manifest_valid or manifest is None or manifest_sha is None:
        checks.append(
            _check(
                "rollback-evidence",
                "release",
                NOT_RUN,
                True,
                "local",
                "target manifest is not valid; rollback evidence was not evaluated",
            )
        )
    elif not previous_valid or previous is None or previous_sha is None:
        checks.append(
            _check(
                "rollback-evidence",
                "release",
                NOT_RUN,
                True,
                "local",
                "previous manifest is not valid; rollback evidence was not evaluated",
            )
        )
    else:
        try:
            payload = _load_json_object(rollback_evidence_path, "rollback evidence")
        except ReadinessError as exc:
            checks.append(_check("rollback-evidence", "release", FAIL, True, "local", str(exc)))
        else:
            errors = _rollback_report_errors(
                payload,
                rollback_evidence_path,
                manifest=manifest,
                manifest_sha=manifest_sha,
                previous=previous,
                previous_sha=previous_sha,
            )
            checks.append(
                _check(
                    "rollback-evidence",
                    "release",
                    FAIL if errors else PASS,
                    True,
                    "local",
                    "; ".join(errors[:8])
                    if errors
                    else "rollback rehearsal executed, passed, and is bound to both releases",
                )
            )
    return checks, previous, previous_sha, previous_valid


def _subject_errors(subject: Any, manifest: Mapping[str, Any], label: str) -> list[str]:
    expected = _subject(manifest)
    if not isinstance(subject, Mapping):
        return [f"{label} subject is missing"]
    return [
        f"{label} subject.{field} does not match the manifest release"
        for field in SUBJECT_FIELDS
        if subject.get(field) != expected.get(field)
    ]


def _evidence_errors(
    payload: Mapping[str, Any],
    report_path: Path,
    label: str,
) -> list[str]:
    evidence = payload.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return [f"{label} evidence is missing"]
    errors: list[str] = []
    for item in evidence:
        if not isinstance(item, Mapping):
            errors.append(f"{label} evidence contains a malformed entry")
            continue
        name = item.get("path")
        digest = item.get("sha256")
        if not _plain_file_name(name):
            errors.append(f"{label} evidence path is invalid")
            continue
        if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
            errors.append(f"{label} evidence hash is invalid")
            continue
        path = report_path.parent / str(name)
        if not path.is_file():
            errors.append(f"{label} evidence file is missing: {name}")
            continue
        try:
            actual = sha256_file(path)
        except OSError as exc:
            errors.append(f"{label} evidence file could not be hashed: {exc}")
            continue
        if actual != digest:
            errors.append(f"{label} evidence hash does not match {name}")
    return errors


def _rollback_report_errors(
    payload: Mapping[str, Any],
    report_path: Path,
    *,
    manifest: Mapping[str, Any],
    manifest_sha: str,
    previous: Mapping[str, Any],
    previous_sha: str,
    require_evidence: bool = True,
) -> list[str]:
    errors: list[str] = []
    if payload.get("schema_version") != REHEARSAL_SCHEMA_VERSION:
        errors.append(f"rollback evidence schema_version must be {REHEARSAL_SCHEMA_VERSION}")
    if payload.get("executed") is not True:
        errors.append("rollback evidence was not executed")
    if payload.get("state") != PASS or payload.get("verified") is not True:
        errors.append("rollback evidence did not pass")
    if payload.get("manifest_sha256") != manifest_sha:
        errors.append("rollback evidence is not bound to the target manifest")
    errors.extend(_subject_errors(payload.get("subject"), manifest, "rollback evidence"))
    previous_bound = payload.get("previous_manifest_sha256")
    if previous_bound != previous_sha:
        errors.append("rollback evidence is not bound to the previous manifest")
    elif previous_bound == manifest_sha:
        errors.append("rollback evidence target and previous manifests are identical")
    errors.extend(_subject_errors(payload.get("previous_subject"), previous, "rollback previous"))

    checks = payload.get("checks")
    by_check = (
        {
            item.get("name"): item
            for item in checks
            if isinstance(item, Mapping) and isinstance(item.get("name"), str)
        }
        if isinstance(checks, list)
        else {}
    )
    for name in ROLLBACK_REQUIRED_CHECKS:
        item = by_check.get(name)
        if item is None:
            errors.append(f"rollback evidence has no {name} check")
        elif item.get("state") != PASS:
            errors.append(f"rollback evidence check {name} is {item.get('state')!r}, not PASS")
    if isinstance(checks, list):
        for item in checks:
            if (
                isinstance(item, Mapping)
                and item.get("required") is True
                and item.get("name") not in ROLLBACK_REQUIRED_CHECKS
                and item.get("state") != PASS
            ):
                errors.append(
                    f"rollback evidence required check {item.get('name')} is {item.get('state')!r}, not PASS"
                )

    steps = payload.get("steps")
    by_step = (
        {
            item.get("name"): item
            for item in steps
            if isinstance(item, Mapping) and isinstance(item.get("name"), str)
        }
        if isinstance(steps, list)
        else {}
    )
    for name in STEP_NAMES:
        item = by_step.get(name)
        if item is None:
            errors.append(f"rollback evidence has no {name} step")
        elif item.get("state") != PASS:
            errors.append(f"rollback evidence step {name} is {item.get('state')!r}, not PASS")

    target = payload.get("target")
    if not isinstance(target, Mapping):
        errors.append("rollback evidence target binding is missing")
    else:
        if target.get("manifest_sha256") != manifest_sha:
            errors.append("rollback evidence target binding is not bound to the target manifest")
        errors.extend(_subject_errors(target.get("subject"), manifest, "rollback target"))
        digests = target.get("digests")
        if not isinstance(digests, Mapping):
            errors.append("rollback evidence target digests are missing")
        else:
            for name, digest in _digests(manifest).items():
                if digests.get(name) != digest:
                    errors.append(f"rollback evidence target digest for {name} does not match")
    previous_binding = payload.get("previous")
    if not isinstance(previous_binding, Mapping):
        errors.append("rollback evidence previous binding is missing")
    else:
        if previous_binding.get("manifest_sha256") != previous_sha:
            errors.append("rollback evidence previous binding is not bound to the previous manifest")
        errors.extend(_subject_errors(previous_binding.get("subject"), previous, "rollback previous binding"))
        previous_digests = previous_binding.get("digests")
        if not isinstance(previous_digests, Mapping):
            errors.append("rollback evidence previous digests are missing")
        elif isinstance(target, Mapping) and isinstance(target.get("digests"), Mapping):
            target_digests = target.get("digests")
            shared = set(target_digests) & set(previous_digests)
            if not shared or all(target_digests[name] == previous_digests[name] for name in shared):
                errors.append("rollback evidence target and previous digests are not different")
    if require_evidence:
        errors.extend(_evidence_errors(payload, report_path, "rollback evidence"))
    return errors


def _gpu_checks(
    *,
    manifest: Mapping[str, Any] | None,
    manifest_valid: bool,
    gpu_required: bool,
    runner: CommandRunner,
    which: Callable[[str], str | None],
) -> list[dict[str, Any]]:
    if not gpu_required:
        return [
            _check(
                name,
                "gpu",
                NOT_RUN,
                False,
                "local",
                "GPU readiness is optional for the CPU staging profile; "
                "CPU readiness does not imply GPU readiness",
            )
            for name in GPU_CHECKS
        ]
    checks: list[dict[str, Any]] = []
    if which("nvidia-smi") is None:
        checks.append(
            _check(
                "gpu-hardware",
                "gpu",
                UNAVAILABLE,
                True,
                "local",
                "nvidia-smi is not installed; no NVIDIA GPU runtime was proven",
            )
        )
        checks.append(
            _check(
                "gpu-driver",
                "gpu",
                UNAVAILABLE,
                True,
                "local",
                "NVIDIA driver state could not be read without nvidia-smi",
            )
        )
    else:
        hardware = _run(
            runner,
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            timeout=30,
        )
        hardware_ok = (
            hardware is not None and hardware.returncode == 0 and bool((hardware.stdout or "").strip())
        )
        checks.append(
            _check(
                "gpu-hardware",
                "gpu",
                PASS if hardware_ok else UNAVAILABLE,
                True,
                "local",
                (hardware.stdout or "NVIDIA GPU").strip().splitlines()[0]
                if hardware_ok and hardware is not None
                else "nvidia-smi did not report an NVIDIA GPU",
            )
        )
        driver = _run(
            runner,
            ["nvidia-smi", "--query-gpu=driver_version", "--format=csv,noheader"],
            timeout=30,
        )
        driver_ok = driver is not None and driver.returncode == 0 and bool((driver.stdout or "").strip())
        checks.append(
            _check(
                "gpu-driver",
                "gpu",
                PASS if driver_ok else UNAVAILABLE,
                True,
                "local",
                f"NVIDIA driver {(driver.stdout or '').strip()} is reported"
                if driver_ok and driver is not None
                else "NVIDIA driver version could not be read",
            )
        )
    if which("docker") is None:
        checks.append(
            _check(
                "gpu-container-runtime",
                "gpu",
                UNAVAILABLE,
                True,
                "local",
                "docker is not installed; the NVIDIA container runtime cannot be checked",
            )
        )
    else:
        runtime = _run(runner, ["docker", "info", "--format", "{{json .Runtimes}}"], timeout=30)
        runtime_ok = (
            runtime is not None and runtime.returncode == 0 and "nvidia" in (runtime.stdout or "").lower()
        )
        checks.append(
            _check(
                "gpu-container-runtime",
                "gpu",
                PASS if runtime_ok else UNAVAILABLE,
                True,
                "local",
                "NVIDIA container runtime is registered"
                if runtime_ok
                else "NVIDIA container runtime is not registered or Docker is unreachable",
            )
        )
    if not manifest_valid or manifest is None:
        checks.append(
            _check(
                "gpu-image-digest",
                "gpu",
                NOT_RUN,
                True,
                "local",
                "a valid manifest is required to verify the api-gpu digest",
            )
        )
    else:
        image = next(
            (
                item
                for item in manifest.get("images") or []
                if isinstance(item, Mapping) and item.get("name") == "api-gpu"
            ),
            None,
        )
        digest = image.get("digest") if isinstance(image, Mapping) else None
        if (
            not isinstance(digest, str)
            or DIGEST_PATTERN.fullmatch(digest) is None
            or is_placeholder_digest(digest)
        ):
            checks.append(
                _check(
                    "gpu-image-digest",
                    "gpu",
                    FAIL,
                    True,
                    "local",
                    "manifest has no immutable, non-placeholder api-gpu digest",
                )
            )
        else:
            checks.append(
                _check(
                    "gpu-image-digest",
                    "gpu",
                    PASS,
                    True,
                    "local",
                    "manifest has an immutable api-gpu digest",
                )
            )
    return checks


def _next_steps(checks: Sequence[Mapping[str, Any]]) -> list[str]:
    actions = {
        "staging-target": (
            "Create an explicit staging target JSON from release/staging-target.schema.json "
            "and pass --target."
        ),
        "manifest": "Supply the immutable release manifest with --manifest.",
        "manifest-digests": (
            "Regenerate the release manifest with immutable, non-placeholder image digests."
        ),
        "previous-release": ("Supply the previous known-good release manifest with --previous-manifest."),
        "previous-verification": (
            "Supply the previous release's production verification report with "
            "--previous-verification-report."
        ),
        "rollback-evidence": (
            "Run the V24 rollback rehearsal on the staging host and supply its report "
            "with --rollback-evidence."
        ),
        "git-cli": "Install git on the staging host.",
        "python-runtime": "Use Python 3.11 or newer on the staging host.",
        "pytest": "Install pytest in the authorized environment.",
        "ruff": "Install ruff in the authorized environment.",
        "node": "Install Node.js on the staging host.",
        "npm": "Install npm on the staging host.",
        "github-cli": "Install GitHub CLI (gh) on the staging host.",
        "github-auth-config": (
            "Configure GH_TOKEN or GITHUB_TOKEN in the authorized execution environment; "
            "never paste it into chat or commit it."
        ),
        "registry-auth-config": (
            "Configure a GHCR read credential and run with --execute-live on the staging host."
        ),
        "docker-cli": "Install Docker on the staging host.",
        "docker-daemon": (
            "Start the Docker daemon on the staging host; a CLI installation alone is not readiness."
        ),
        "docker-compose": "Install the Docker Compose plugin.",
        "compose-files": ("Fix the target's compose_files so every file exists under the repository root."),
        "compose-config": (
            "Resolve the digest-pinned Compose configuration with the target's compose "
            "files and release digests."
        ),
        "compose-pins": (
            "Use compose.release.yaml or compose.gpu.release.yaml and remove local build definitions."
        ),
        "database-config": (
            "Review the PostgreSQL service, password reference, and healthcheck in Compose; "
            "values are not printed."
        ),
        "redis-config": "Review the Redis service and healthcheck in Compose.",
        "volume-declarations": "Declare PostgreSQL and Redis data on named volumes.",
        "health-endpoints": (
            "Configure api and web healthchecks; the api healthcheck should probe /ready or /live."
        ),
        "port-configuration": (
            "Bind published ports to loopback only and publish no postgres or redis ports."
        ),
        "environment-config": (
            "Provide the required environment variable names and secret references in the "
            "authorized environment."
        ),
        "smoke-credential": (
            "Set the target's smoke password environment variable in the authorized execution environment."
        ),
        "staging-target-smoke-config": (
            "Configure a dedicated smoke account in the staging target definition."
        ),
        "gpu-profile": (
            "Use a CPU staging target for CPU readiness, or enable GPU on the target and "
            "rerun with --require-gpu."
        ),
        "release-tag": (
            "Create and verify the stable release tag through the separately authorized "
            "release process; V26 never creates tags."
        ),
        "release-tag-remote": ("Run with --execute-live and an explicit --tag after the release exists."),
        "network-github": ("Run with --execute-live on a host with network access to api.github.com."),
        "network-ghcr": "Run with --execute-live on a host with network access to ghcr.io.",
    }
    steps: list[str] = []
    for check in checks:
        if check.get("required") is not True or check.get("state") == PASS:
            continue
        name = str(check.get("name"))
        if name.startswith("gpu-"):
            action = (
                "Run on a host with an NVIDIA GPU, driver, and Container Toolkit, or use the CPU profile; "
                "CPU readiness does not imply GPU readiness."
            )
        else:
            action = actions.get(
                name,
                f"Resolve {name} on the staging host; readiness never fixes blockers automatically.",
            )
        if action not in steps:
            steps.append(action)
    if not steps:
        steps.append(
            "Every required prerequisite is verified. Deployment still requires a separate "
            "authorization step; readiness never deploys automatically."
        )
    return steps


def assess_staging_readiness(
    *,
    repo_root: Path,
    evidence_dir: Path,
    manifest_path: Path | None = None,
    target_path: Path | None = None,
    previous_manifest_path: Path | None = None,
    previous_verification_report_path: Path | None = None,
    rollback_evidence_path: Path | None = None,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    expected_repository: str | None = None,
    expected_branch: str | None = None,
    main_ref: str = "origin/main",
    require_gpu: bool = False,
    execute_live: bool = False,
    env: Mapping[str, str] | None = None,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None] = shutil.which,
    network_probe: Callable[[str, int], bool] = _tcp_reachable,
    now: Callable[[], str] = utc_now_iso,
) -> dict[str, Any]:
    """Assess readiness without deploying, publishing, or authorizing anything."""
    environment = os.environ if env is None else env
    mode = "live-read-only" if execute_live else "preflight"
    if not repo_root.is_dir():
        raise ReadinessError(f"repository root does not exist: {repo_root}")

    manifest: Mapping[str, Any] | None = None
    load_error: str | None = None
    if manifest_path is not None:
        if not manifest_path.is_file():
            load_error = f"manifest does not exist: {manifest_path}"
        else:
            try:
                manifest = load_manifest(manifest_path)
            except (ManifestError, OSError) as exc:
                load_error = str(exc)

    target: Mapping[str, Any] | None = None
    target_error: str | None = None
    if target_path is not None:
        if not target_path.is_file():
            target_error = f"staging target does not exist: {target_path}"
        else:
            try:
                target = _load_json_object(target_path, "staging target")
            except ReadinessError as exc:
                target_error = str(exc)
            else:
                target_problems = staging_target_errors(target)
                if target_problems:
                    target = None
                    target_error = "staging target is invalid:\n- " + "\n- ".join(target_problems)

    checks, repository = _repository_checks(
        repo_root=repo_root,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
        expected_repository=expected_repository,
        expected_branch=expected_branch,
        main_ref=main_ref,
        runner=runner,
        which=which,
        environment=environment,
        execute_live=execute_live,
    )
    release_checks, release, manifest_sha, manifest_valid = _release_checks(
        manifest_path=manifest_path,
        manifest=manifest,
        load_error=load_error,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
        expected_repository=expected_repository,
    )
    checks.extend(release_checks)

    checks.append(
        _check(
            "python-runtime",
            "tooling",
            PASS if sys.version_info >= (3, 11) else FAIL,
            True,
            "local",
            f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} is available",
        )
    )
    for name, executable, args in (
        ("pytest", "pytest", ["pytest", "--version"]),
        ("ruff", "ruff", ["ruff", "--version"]),
        ("node", "node", ["node", "--version"]),
        ("npm", "npm", ["npm", "--version"]),
    ):
        checks.append(
            _tool_check(
                name,
                executable,
                args,
                category="tooling",
                required=True,
                runner=runner,
                which=which,
            )
        )
    checks.extend(_docker_checks(runner=runner, which=which, required=True))
    checks.extend(
        _github_checks(
            runner=runner,
            which=which,
            environment=environment,
            execute_live=execute_live,
            network_probe=network_probe,
            manifest=manifest,
            manifest_valid=manifest_valid,
        )
    )

    target_checks, target_summary, target_valid, gpu_required = _target_checks(
        target_path=target_path,
        target=target,
        target_error=target_error,
        repo_root=repo_root,
        manifest=manifest,
        manifest_sha=manifest_sha,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
        expected_repository=expected_repository,
        require_gpu=require_gpu,
        environment=environment,
    )
    checks.extend(target_checks)
    checks.extend(
        _deployment_checks(
            manifest_path=manifest_path,
            manifest=manifest,
            manifest_valid=manifest_valid,
            target=target,
            target_valid=target_valid,
            repo_root=repo_root,
            gpu_required=gpu_required,
            runner=runner,
            which=which,
            environment=environment,
        )
    )

    previous_checks, previous, previous_sha, previous_valid = _previous_release_checks(
        previous_manifest_path=previous_manifest_path,
        previous_verification_report_path=previous_verification_report_path,
        rollback_evidence_path=rollback_evidence_path,
        manifest=manifest,
        manifest_sha=manifest_sha,
        manifest_valid=manifest_valid,
        now=now,
    )
    checks.extend(previous_checks)
    checks.extend(
        _gpu_checks(
            manifest=manifest,
            manifest_valid=manifest_valid,
            gpu_required=gpu_required,
            runner=runner,
            which=which,
        )
    )

    state = _aggregate(checks)
    ready = state == PASS and all(
        check.get("state") == PASS for check in checks if check.get("required") is True
    )
    gpu_ready = gpu_required and all(
        check.get("state") == PASS for check in checks if check.get("name") in GPU_CHECKS
    )

    evidence: list[dict[str, Any]] = []
    check_by_name = {str(check.get("name")): check for check in checks}
    bindings: dict[str, Any] = {}
    for binding_name, kind, source, check_name in (
        ("target", "staging-target", target_path, "staging-target"),
        ("manifest", "release-manifest", manifest_path, "manifest"),
        ("previous_manifest", "previous-manifest", previous_manifest_path, "previous-release"),
        (
            "previous_verification",
            "previous-verification",
            previous_verification_report_path,
            "previous-verification",
        ),
        ("rollback_evidence", "rollback-evidence", rollback_evidence_path, "rollback-evidence"),
    ):
        check = check_by_name.get(check_name)
        binding_state = str(check.get("state")) if isinstance(check, Mapping) else FAIL
        bindings[binding_name] = _retain_evidence(
            source,
            evidence_dir,
            kind=kind,
            state=binding_state,
            evidence=evidence,
        )

    retention_blockers: list[str] = []
    if ready:
        for binding_name in READINESS_BINDING_NAMES:
            binding = bindings.get(binding_name)
            if not isinstance(binding, Mapping):
                retention_blockers.append(
                    f"evidence-retention: {binding_name} evidence could not be retained safely"
                )
            elif binding.get("state") != PASS:
                retention_blockers.append(f"evidence-retention: {binding_name} evidence is not PASS")
    if retention_blockers:
        state = FAIL
        ready = False

    blockers = [
        f"{check['name']}: {check['state']} - {check['detail']}"
        for check in checks
        if check.get("required") is True and check.get("state") != PASS
    ]
    blockers.extend(retention_blockers)
    limitations = [
        f"{check['name']}: {check['state']} - {check['detail']}"
        for check in checks
        if check.get("required") is not True and check.get("state") != PASS
    ]
    if gpu_required and not gpu_ready:
        limitations.append(
            "GPU readiness is required but not proven; CPU readiness does not imply GPU readiness."
        )
    return {
        "schema_version": READINESS_SCHEMA_VERSION,
        "profile": READINESS_PROFILE,
        "generated_at": now(),
        "mode": mode,
        "repository": repository,
        "staging_target": target_summary,
        "release": release,
        "gpu_required": gpu_required,
        "gpu_ready": gpu_ready,
        "state": state,
        "ready": ready,
        "production_qualified": False,
        "deployment": {
            "authorized": False,
            "performed": False,
            "statement": DEPLOYMENT_STATEMENT,
        },
        "checks": checks,
        "evidence": evidence,
        "bindings": bindings,
        "blockers": blockers,
        "limitations": limitations,
        "next_steps": _next_steps(checks),
    }


def write_readiness_report(report: Mapping[str, Any], path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return sha256_file(path)


def readiness_report_sha256(path: Path) -> str:
    """Return the SHA-256 of the exact readiness report bytes."""
    try:
        return sha256_file(path)
    except OSError as exc:
        raise ReadinessError(f"could not hash readiness report {path}: {exc}") from exc


def _check_errors(check: Any, report_mode: str, gpu_required: bool) -> list[str]:
    if not isinstance(check, Mapping):
        return ["readiness report contains a malformed check"]
    errors: list[str] = []
    unknown = sorted(set(check) - set(READINESS_CHECK_FIELDS))
    missing = [field for field in READINESS_CHECK_FIELDS if field not in check]
    if unknown:
        errors.append(f"readiness check has unknown fields: {', '.join(unknown)}")
    if missing:
        errors.append(f"readiness check is missing fields: {', '.join(missing)}")
    name = check.get("name")
    if not isinstance(name, str) or not name:
        errors.append("readiness check name is invalid")
    if check.get("category") not in CHECK_CATEGORIES:
        errors.append(f"readiness check {name} category is invalid")
    if check.get("state") not in (PASS, FAIL, NOT_RUN, UNAVAILABLE, SIMULATED):
        errors.append(f"readiness check {name} state is invalid")
    if not isinstance(check.get("required"), bool):
        errors.append(f"readiness check {name} required flag is not boolean")
    if check.get("mode") not in CHECK_MODES:
        errors.append(f"readiness check {name} mode is invalid")
    if not isinstance(check.get("detail"), str) or not check.get("detail"):
        errors.append(f"readiness check {name} detail is missing")
    if check.get("command") is not None and not isinstance(check.get("command"), str):
        errors.append(f"readiness check {name} command is invalid")
    if check.get("mode") == "simulated" and check.get("state") != SIMULATED:
        errors.append(f"readiness check {name} claims simulated mode without SIMULATED state")
    if check.get("state") == SIMULATED and check.get("mode") != "simulated":
        errors.append(f"readiness check {name} is SIMULATED but does not declare simulated mode")
    if check.get("required") is True and check.get("state") == SIMULATED:
        errors.append(f"readiness required check {name} is SIMULATED, not PASS")
    if report_mode == "preflight" and check.get("mode") == "live-read-only":
        errors.append(f"readiness preflight report contains live check {name}")
    if name in GPU_CHECKS:
        if check.get("required") is not gpu_required:
            errors.append(f"readiness GPU check {name} required flag contradicts gpu_required")
        if gpu_required and check.get("state") != PASS:
            errors.append(f"readiness required GPU check {name} is {check.get('state')!r}, not PASS")
        if not gpu_required and check.get("state") != NOT_RUN:
            errors.append(f"readiness optional GPU check {name} must be NOT_RUN")
    return errors


def _retained_json(directory: Path, item: Mapping[str, Any]) -> dict[str, Any] | None:
    path = directory / str(item.get("path"))
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def readiness_report_errors(
    report: Any,
    *,
    manifest_path: Path,
    report_path: Path | None = None,
    evidence_dir: Path | None = None,
    expected_report_sha256: str | None = None,
) -> list[str]:
    """Return every reason a readiness report is not a valid PASS."""
    if not isinstance(report, Mapping):
        return ["readiness report must be a JSON object"]
    errors: list[str] = []
    unknown = sorted(set(report) - set(READINESS_REPORT_FIELDS))
    missing = [field for field in READINESS_REPORT_FIELDS if field not in report]
    if unknown:
        errors.append("readiness report has unknown fields: " + ", ".join(unknown))
    if missing:
        errors.append("readiness report is missing fields: " + ", ".join(missing))
    if report.get("schema_version") != READINESS_SCHEMA_VERSION:
        errors.append(f"readiness report schema_version must be {READINESS_SCHEMA_VERSION}")
    if report.get("profile") != READINESS_PROFILE:
        errors.append(f"readiness report profile must be {READINESS_PROFILE!r}")
    generated_at = report.get("generated_at")
    if not isinstance(generated_at, str) or TIMESTAMP_PATTERN.fullmatch(generated_at) is None:
        errors.append("readiness report generated_at is not a UTC timestamp")
    mode = report.get("mode")
    if mode not in READINESS_MODES:
        errors.append(f"readiness report mode {mode!r} is not recognized")
    if not isinstance(report.get("gpu_required"), bool):
        errors.append("readiness report gpu_required is not boolean")
    if not isinstance(report.get("gpu_ready"), bool):
        errors.append("readiness report gpu_ready is not boolean")
    gpu_required = report.get("gpu_required") is True
    if report.get("state") != PASS:
        errors.append(f"readiness report state is {report.get('state')!r}, not PASS")
    if report.get("ready") is not True:
        errors.append("readiness report ready is not true")
    if report.get("production_qualified") is not False:
        errors.append("readiness report must never claim production qualification")
    deployment = report.get("deployment")
    if not isinstance(deployment, Mapping):
        errors.append("readiness report deployment statement is missing")
    else:
        if sorted(deployment) != sorted(DEPLOYMENT_FIELDS):
            errors.append("readiness report deployment statement has unexpected fields")
        if deployment.get("authorized") is not False:
            errors.append("readiness report must never authorize deployment")
        if deployment.get("performed") is not False:
            errors.append("readiness report must never claim a deployment was performed")
        if not isinstance(deployment.get("statement"), str) or "No deployment" not in str(
            deployment.get("statement")
        ):
            errors.append("readiness report deployment statement is not explicit")

    repository = report.get("repository")
    if not isinstance(repository, Mapping):
        errors.append("readiness report repository identity is missing")
    else:
        if sorted(repository) != sorted(REPOSITORY_FIELDS):
            errors.append("readiness report repository identity has unexpected fields")
        if (
            not isinstance(repository.get("source_repository"), str)
            or SOURCE_REPOSITORY_PATTERN.fullmatch(str(repository.get("source_repository"))) is None
        ):
            errors.append("readiness report repository source_repository is invalid")
        if (
            not isinstance(repository.get("commit"), str)
            or COMMIT_PATTERN.fullmatch(str(repository.get("commit"))) is None
        ):
            errors.append("readiness report repository commit is invalid")
        if not isinstance(repository.get("branch"), str) or not repository.get("branch"):
            errors.append("readiness report repository branch is missing")
        tag = repository.get("tag")
        if tag is not None and (not isinstance(tag, str) or TAG_PATTERN.fullmatch(tag) is None):
            errors.append("readiness report repository tag is invalid")
        if tag is not None:
            if repository.get("tag_source") != "explicit":
                errors.append("readiness report tag was not explicitly supplied")
            if repository.get("tag_resolved_locally") is not True:
                errors.append("readiness report tag was not resolved locally")
            if repository.get("tag_matches_commit") is not True:
                errors.append("readiness report tag does not match the source commit")
        else:
            if repository.get("tag_source") is not None:
                errors.append("readiness report tag_source contradicts a missing tag")
            if repository.get("tag_resolved_locally") is not False:
                errors.append("readiness report tag_resolved_locally contradicts a missing tag")
            if repository.get("tag_matches_commit") is not False:
                errors.append("readiness report tag_matches_commit contradicts a missing tag")
        if repository.get("commit_resolved_locally") is not True:
            errors.append("readiness report source commit was not resolved locally")
        if repository.get("worktree_clean") is not True:
            errors.append("readiness report working tree is not clean")
        if repository.get("reachable_from_main") is not True:
            errors.append("readiness report source commit is not reachable from main")
        if repository.get("remote_matches_source") is not True:
            errors.append("readiness report origin remote does not match the source repository")

    release = report.get("release")
    if not isinstance(release, Mapping):
        errors.append("readiness report release binding is missing")
    else:
        if sorted(release) != sorted(RELEASE_FIELDS):
            errors.append("readiness report release binding has unexpected fields")
        manifest_sha = release.get("manifest_sha256")
        if not isinstance(manifest_sha, str) or DIGEST_PATTERN.fullmatch(manifest_sha) is None:
            errors.append("readiness report manifest_sha256 is invalid")
        subject = release.get("subject")
        if not isinstance(subject, Mapping):
            errors.append("readiness report release subject is missing")
        else:
            if sorted(subject) != sorted(SUBJECT_FIELDS):
                errors.append("readiness report release subject has unexpected fields")
            if (
                not isinstance(subject.get("tag"), str)
                or TAG_PATTERN.fullmatch(str(subject.get("tag"))) is None
            ):
                errors.append("readiness report release subject tag is invalid")
            if (
                not isinstance(subject.get("commit"), str)
                or COMMIT_PATTERN.fullmatch(str(subject.get("commit"))) is None
            ):
                errors.append("readiness report release subject commit is invalid")
            if (
                not isinstance(subject.get("source_repository"), str)
                or SOURCE_REPOSITORY_PATTERN.fullmatch(str(subject.get("source_repository"))) is None
            ):
                errors.append("readiness report release subject source_repository is invalid")
            if isinstance(repository, Mapping):
                if subject.get("commit") != repository.get("commit"):
                    errors.append("readiness report release commit does not match the source commit")
                if subject.get("source_repository") != repository.get("source_repository"):
                    errors.append("readiness report release repository does not match the source repository")
                if repository.get("tag") is not None and subject.get("tag") != repository.get("tag"):
                    errors.append("readiness report release tag does not match the supplied tag")
        digests = release.get("digests")
        if not isinstance(digests, Mapping):
            errors.append("readiness report release digests are missing")
        else:
            if set(digests) != set(REQUIRED_IMAGES):
                errors.append("readiness report release digests do not cover the required images")
            for name, digest in digests.items():
                if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
                    errors.append(f"readiness report digest for {name} is invalid")
                elif is_placeholder_digest(digest):
                    errors.append(f"readiness report digest for {name} is a placeholder")
        try:
            expected_sha = sha256_file(manifest_path)
        except OSError as exc:
            errors.append(f"could not hash manifest {manifest_path}: {exc}")
        else:
            if manifest_sha != expected_sha:
                errors.append("readiness report is not bound to the supplied manifest")
            try:
                manifest = load_manifest(manifest_path)
            except (ManifestError, OSError) as exc:
                errors.append(f"could not load supplied manifest: {exc}")
            else:
                if isinstance(subject, Mapping):
                    for field in SUBJECT_FIELDS:
                        if subject.get(field) != _subject(manifest).get(field):
                            errors.append(
                                f"readiness report release subject.{field} does not match the manifest"
                            )
                if isinstance(digests, Mapping):
                    for name, digest in _digests(manifest).items():
                        if digests.get(name) != digest:
                            errors.append(f"readiness report digest for {name} does not match the manifest")

    target = report.get("staging_target")
    if not isinstance(target, Mapping):
        errors.append("readiness report staging target is missing")
    else:
        if sorted(target) != sorted(TARGET_FIELDS):
            errors.append("readiness report staging target has unexpected fields")
        if (
            not isinstance(target.get("name"), str)
            or STAGING_NAME_PATTERN.fullmatch(str(target.get("name"))) is None
        ):
            errors.append("readiness report staging target name is invalid")
        elif _production_marker(str(target.get("name"))):
            errors.append("readiness report staging target name looks like production")
        if target.get("environment") != "staging":
            errors.append("readiness report staging target environment is not staging")
        for field, scheme in (("api_url", "https"), ("web_url", "https"), ("ws_url", "wss")):
            for problem in _url_errors(target.get(field), field, scheme):
                errors.append(f"readiness report staging target {problem}")
        if not isinstance(target.get("smoke_username"), str) or not target.get("smoke_username"):
            errors.append("readiness report staging target smoke_username is missing")
        if (
            not isinstance(target.get("smoke_password_env"), str)
            or ENVIRONMENT_NAME_PATTERN.fullmatch(str(target.get("smoke_password_env"))) is None
        ):
            errors.append("readiness report staging target smoke_password_env is invalid")
        if (
            not isinstance(target.get("compose_project"), str)
            or COMPOSE_PROJECT_PATTERN.fullmatch(str(target.get("compose_project"))) is None
        ):
            errors.append("readiness report staging target compose_project is invalid")
        compose_files = target.get("compose_files")
        if not isinstance(compose_files, list) or not compose_files:
            errors.append("readiness report staging target compose_files is missing")
        else:
            for index, item in enumerate(compose_files):
                for problem in _relative_path_errors(item, f"compose_files[{index}]"):
                    errors.append(f"readiness report staging target {problem}")
        if not isinstance(target.get("gpu"), bool):
            errors.append("readiness report staging target gpu flag is invalid")
        elif target.get("gpu") is True and not gpu_required:
            errors.append("readiness report target enables GPU but gpu_required is false")

    checks = report.get("checks")
    if not isinstance(checks, list):
        errors.append("readiness report checks are missing")
        checks = []
    names: list[str] = []
    for check in checks:
        errors.extend(_check_errors(check, str(mode), gpu_required))
        if isinstance(check, Mapping) and isinstance(check.get("name"), str):
            names.append(str(check["name"]))
    if len(names) != len(set(names)):
        errors.append("readiness report contains duplicate check names")
    for name in MANDATORY_READINESS_CHECKS:
        if name not in names:
            errors.append(f"readiness report has no {name} check")
    checks_by_name = {str(check.get("name")): check for check in checks if isinstance(check, Mapping)}
    for name in MANDATORY_READINESS_CHECKS:
        check = checks_by_name.get(name)
        if isinstance(check, Mapping) and check.get("required") is not True:
            errors.append(f"readiness check {name} must be required")
    required_checks = [
        check for check in checks if isinstance(check, Mapping) and check.get("required") is True
    ]
    not_passed = [str(check.get("name")) for check in required_checks if check.get("state") != PASS]
    if not_passed:
        errors.append("readiness report required checks are not PASS: " + ", ".join(sorted(not_passed)))
    computed_state = _aggregate([check for check in checks if isinstance(check, Mapping)])
    if report.get("state") != computed_state:
        errors.append("readiness report state contradicts its checks")
    computed_ready = computed_state == PASS and all(check.get("state") == PASS for check in required_checks)
    if report.get("ready") is not computed_ready:
        errors.append("readiness report ready flag contradicts its checks")
    tag = repository.get("tag") if isinstance(repository, Mapping) else None
    release_tag_check = checks_by_name.get("release-tag")
    if isinstance(release_tag_check, Mapping):
        if release_tag_check.get("required") is not (tag is not None):
            errors.append("readiness check release-tag required flag contradicts the supplied tag")
    else:
        errors.append("readiness report has no release-tag check")
    for name in ("release-tag-remote", "network-github", "network-ghcr"):
        check = checks_by_name.get(name)
        if not isinstance(check, Mapping):
            errors.append(f"readiness report has no {name} check")
            continue
        if check.get("required") is not (mode == "live-read-only"):
            errors.append(f"readiness check {name} required flag contradicts the report mode")
    for name in GPU_CHECKS:
        if name not in names:
            errors.append(f"readiness report has no {name} check")
    if gpu_required:
        if report.get("gpu_ready") is not True:
            errors.append("readiness report gpu_ready is not true for a GPU-required profile")
    elif report.get("gpu_ready") is not False:
        errors.append("readiness report gpu_ready must be false when GPU is optional")

    evidence = report.get("evidence")
    if not isinstance(evidence, list):
        errors.append("readiness report evidence is missing")
        evidence = []
    evidence_by_kind: dict[str, Mapping[str, Any]] = {}
    directory = evidence_dir or (report_path.parent if report_path is not None else manifest_path.parent)
    for item in evidence:
        if not isinstance(item, Mapping):
            errors.append("readiness report evidence contains a malformed entry")
            continue
        if sorted(item) != sorted(READINESS_EVIDENCE_FIELDS):
            errors.append("readiness report evidence entry has unexpected fields")
            continue
        kind = item.get("kind")
        if not isinstance(kind, str) or not kind:
            errors.append("readiness report evidence kind is invalid")
            continue
        if kind in evidence_by_kind:
            errors.append(f"readiness report evidence kind {kind} is duplicated")
        evidence_by_kind[kind] = item
        if item.get("state") != PASS:
            errors.append(f"readiness report evidence {kind} state is not PASS")
        if not _plain_file_name(item.get("path")):
            errors.append("readiness report evidence path is invalid")
            continue
        digest = item.get("sha256")
        if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
            errors.append("readiness report evidence hash is invalid")
            continue
        path = directory / str(item.get("path"))
        if not path.is_file():
            errors.append(f"readiness report evidence file is missing: {item.get('path')}")
            continue
        try:
            actual = sha256_file(path)
        except OSError as exc:
            errors.append(f"readiness report evidence file could not be hashed: {exc}")
            continue
        if actual != digest:
            errors.append(f"readiness report evidence hash does not match {item.get('path')}")
    expected_kinds = set(READINESS_BINDING_KINDS.values())
    if set(evidence_by_kind) != expected_kinds:
        errors.append("readiness report evidence kinds do not match the required bindings")

    try:
        supplied_manifest = load_manifest(manifest_path)
    except (ManifestError, OSError):
        supplied_manifest = None

    target_evidence = evidence_by_kind.get("staging-target")
    if isinstance(target_evidence, Mapping):
        target_payload = _retained_json(directory, target_evidence)
        if target_payload is None:
            errors.append("readiness report target evidence is unreadable")
        else:
            for problem in staging_target_errors(target_payload):
                errors.append(f"readiness report target evidence is invalid: {problem}")
            if isinstance(target, Mapping):
                for field in TARGET_FIELDS:
                    if target_payload.get(field) != target.get(field):
                        errors.append(f"readiness report staging target {field} does not match its evidence")
            release_binding = target_payload.get("release")
            expected_subject = (
                _subject(supplied_manifest)
                if supplied_manifest is not None
                else (release.get("subject") if isinstance(release, Mapping) else None)
            )
            if isinstance(release_binding, Mapping) and isinstance(expected_subject, Mapping):
                for field in SUBJECT_FIELDS:
                    if release_binding.get(field) != expected_subject.get(field):
                        errors.append(
                            f"readiness report target evidence release.{field} does not match the manifest"
                        )

    previous_evidence = evidence_by_kind.get("previous-manifest")
    previous_payload: dict[str, Any] | None = None
    previous_path: Path | None = None
    previous_sha: str | None = None
    if isinstance(previous_evidence, Mapping):
        previous_path = directory / str(previous_evidence.get("path"))
        previous_sha = previous_evidence.get("sha256")
        previous_payload = _retained_json(directory, previous_evidence)
        if previous_payload is None:
            errors.append("readiness report previous manifest evidence is unreadable")
        else:
            for problem in manifest_errors(previous_payload):
                errors.append(f"readiness report previous manifest evidence is invalid: {problem}")
            if isinstance(release, Mapping) and release.get("manifest_sha256") == previous_sha:
                errors.append("readiness report previous manifest is identical to the target manifest")

    verification_evidence = evidence_by_kind.get("previous-verification")
    if (
        isinstance(verification_evidence, Mapping)
        and previous_payload is not None
        and previous_path is not None
    ):
        verification_payload = _retained_json(directory, verification_evidence)
        if verification_payload is None:
            errors.append("readiness report previous verification evidence is unreadable")
        else:
            for problem in verification_report_errors(
                verification_payload,
                previous_payload,
                manifest_path=previous_path,
                require_production=True,
            ):
                errors.append(f"readiness report previous verification evidence is invalid: {problem}")

    rollback_evidence = evidence_by_kind.get("rollback-evidence")
    if (
        isinstance(rollback_evidence, Mapping)
        and supplied_manifest is not None
        and previous_payload is not None
        and previous_sha is not None
    ):
        rollback_payload = _retained_json(directory, rollback_evidence)
        if rollback_payload is None:
            errors.append("readiness report rollback evidence is unreadable")
        elif isinstance(release, Mapping) and isinstance(release.get("manifest_sha256"), str):
            for problem in _rollback_report_errors(
                rollback_payload,
                directory / str(rollback_evidence.get("path")),
                manifest=supplied_manifest,
                manifest_sha=str(release["manifest_sha256"]),
                previous=previous_payload,
                previous_sha=previous_sha,
                require_evidence=False,
            ):
                errors.append(f"readiness report rollback evidence is invalid: {problem}")

    bindings = report.get("bindings")
    if not isinstance(bindings, Mapping):
        errors.append("readiness report bindings are missing")
    else:
        if sorted(bindings) != sorted(READINESS_BINDING_NAMES):
            errors.append("readiness report bindings have unexpected fields")
        for name in READINESS_BINDING_NAMES:
            binding = bindings.get(name)
            if not isinstance(binding, Mapping):
                errors.append(f"readiness report {name} binding is missing")
                continue
            if sorted(binding) != sorted(READINESS_BINDING_FIELDS):
                errors.append(f"readiness report {name} binding has unexpected fields")
                continue
            if binding.get("state") != PASS:
                errors.append(f"readiness report {name} binding state is not PASS")
            kind = binding.get("kind")
            if kind != READINESS_BINDING_KINDS[name]:
                errors.append(f"readiness report {name} binding has the wrong evidence kind")
            evidence_item = evidence_by_kind.get(str(kind))
            if evidence_item is None:
                errors.append(f"readiness report {name} binding has no matching evidence")
            elif evidence_item.get("path") != binding.get("path") or evidence_item.get(
                "sha256"
            ) != binding.get("sha256"):
                errors.append(f"readiness report {name} binding does not match its evidence")
            if not _plain_file_name(binding.get("path")):
                errors.append(f"readiness report {name} binding path is invalid")
            digest = binding.get("sha256")
            if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
                errors.append(f"readiness report {name} binding hash is invalid")

    blockers = report.get("blockers")
    if not isinstance(blockers, list):
        errors.append("readiness report blockers are missing")
    elif blockers:
        errors.append("readiness report has blockers and cannot be ready")
    limitations = report.get("limitations")
    if not isinstance(limitations, list):
        errors.append("readiness report limitations are missing")
    next_steps = report.get("next_steps")
    if not isinstance(next_steps, list) or not next_steps:
        errors.append("readiness report next_steps are missing")

    if expected_report_sha256 is not None:
        if report_path is None:
            errors.append("expected report hash requires a report path")
        elif DIGEST_PATTERN.fullmatch(expected_report_sha256) is None:
            errors.append("expected report hash is invalid")
        else:
            try:
                actual_report_sha = sha256_file(report_path)
            except OSError as exc:
                errors.append(f"could not hash readiness report: {exc}")
            else:
                if actual_report_sha != expected_report_sha256:
                    errors.append("readiness report bytes changed after generation")
    return errors


def render_readiness_summary(report: Mapping[str, Any]) -> str:
    repository = report.get("repository") or {}
    target = report.get("staging_target") or {}
    release = report.get("release") or {}
    subject = release.get("subject") or {}
    lines = [
        f"Staging readiness: {report.get('state')} "
        f"(profile={report.get('profile')}, mode={report.get('mode')}, "
        f"ready={report.get('ready')}, gpu_required={report.get('gpu_required')}, "
        f"gpu_ready={report.get('gpu_ready')})",
        "Readiness PASS means prerequisites were verified for this scope; it does not "
        "authorize deployment and does not prove production qualification.",
        f"Repository: {repository.get('source_repository')} at {repository.get('commit')} "
        f"(branch={repository.get('branch')}, tag={repository.get('tag')})",
        f"Release: {subject.get('tag')} at {subject.get('commit')} from {subject.get('source_repository')}",
        f"Manifest: {release.get('manifest_sha256')}",
    ]
    if target:
        lines.append(
            f"Staging target: {target.get('name')} ({target.get('environment')}) "
            f"api={target.get('api_url')} web={target.get('web_url')} ws={target.get('ws_url')}"
        )
    for check in report.get("checks") or []:
        required = "required" if check.get("required") else "optional"
        lines.append(
            f"- {check.get('name')}: {check.get('state')} ({required}, {check.get('mode')}) "
            f"- {check.get('detail')}"
        )
    evidence = report.get("evidence") or []
    if evidence:
        lines.append("Evidence:")
        lines.extend(f"- {item.get('kind')}: {item.get('path')} ({item.get('sha256')})" for item in evidence)
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
        lines.append("Next safe actions:")
        lines.extend(f"- {item}" for item in next_steps)
    deployment = report.get("deployment") or {}
    lines.append(
        f"Deployment authorization: authorized={deployment.get('authorized')} "
        f"performed={deployment.get('performed')} - {deployment.get('statement')}"
    )
    return "\n".join(lines) + "\n"
