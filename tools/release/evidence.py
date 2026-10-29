"""Release evidence collection for controlled staging qualification (V25).

The collector never invents evidence. Local artifacts are hashed and checked
offline. Live GitHub Release, GHCR digest, and attestation checks only run when
``execute`` is true, and a missing CLI, token, release, or attestation is
reported as ``UNAVAILABLE`` or ``FAIL``. The embedded V23 verification report is
the authoritative artifact/attestation record; this module adds the GitHub
Release binding and per-image SBOM/scan hashes.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from tools.release.identity import REQUIRED_IMAGES, verify_tag_commit
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
    VerificationError,
    default_runner,
    verify_release,
)

EVIDENCE_SCHEMA_VERSION = 1
EVIDENCE_REPORT_FIELDS = (
    "schema_version",
    "generated_at",
    "executed",
    "manifest_sha256",
    "subject",
    "digests",
    "state",
    "verified",
    "production_verified",
    "github_release",
    "verification",
    "artifacts",
    "checks",
    "blockers",
    "limitations",
)
EVIDENCE_SUBJECT_FIELDS = ("tag", "commit", "source_repository")
EVIDENCE_CHECK_FIELDS = ("name", "state", "required", "detail", "command")
EVIDENCE_ARTIFACT_FIELDS = (
    "name",
    "digest",
    "sbom_file",
    "sbom_sha256",
    "scan_log_file",
    "scan_log_sha256",
)


class EvidenceError(RuntimeError):
    """The evidence request or its inputs are invalid."""


def _check(name: str, state: str, required: bool, detail: str, command: str | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "state": state,
        "required": required,
        "detail": detail,
        "command": command,
    }


def _aggregate(checks: list[Mapping[str, Any]]) -> str:
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


def _digests(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        image.get("name"): image.get("digest")
        for image in manifest.get("images") or []
        if isinstance(image, Mapping) and isinstance(image.get("name"), str)
    }


def _release_identity(manifest: Mapping[str, Any]) -> tuple[str, str, str]:
    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    tag = release.get("tag")
    commit = release.get("commit")
    repository = release.get("source_repository")
    if not all(isinstance(value, str) and value for value in (tag, commit, repository)):
        raise EvidenceError("manifest release identity is incomplete")
    return tag, commit, repository


def _github_release_check(
    tag: str,
    repository: str,
    *,
    runner: CommandRunner,
    which: Callable[[str], str | None],
) -> dict[str, Any]:
    if which("gh") is None:
        return _check(
            "github-release",
            UNAVAILABLE,
            True,
            "GitHub CLI is not installed; GitHub Release evidence was not collected",
        )
    args = [
        "gh",
        "release",
        "view",
        tag,
        "--repo",
        repository,
        "--json",
        "tagName,isDraft,isPrerelease,url",
    ]
    command = " ".join(args)
    try:
        result = runner(args, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return _check(
            "github-release",
            UNAVAILABLE,
            True,
            f"GitHub Release query could not run: {exc}",
            command,
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "no output").strip()
        return _check("github-release", FAIL, True, detail[:500], command)
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        return _check("github-release", FAIL, True, f"invalid GitHub Release JSON: {exc}", command)
    if not isinstance(payload, Mapping):
        return _check("github-release", FAIL, True, "GitHub Release response is not an object", command)
    problems: list[str] = []
    if payload.get("tagName") != tag:
        problems.append(f"tagName is {payload.get('tagName')!r}, expected {tag!r}")
    if payload.get("isDraft") is not False:
        problems.append("release is still a draft")
    if payload.get("isPrerelease") is not False:
        problems.append("release is a pre-release")
    url = payload.get("url")
    expected_prefix = f"https://github.com/{repository}/releases/tag/"
    if not isinstance(url, str) or not url.startswith(expected_prefix):
        problems.append("release URL does not belong to the manifest repository")
    if problems:
        return _check("github-release", FAIL, True, "; ".join(problems), command)
    return _check("github-release", PASS, True, f"published GitHub Release {tag} is immutable", command)


def _artifact_entries(manifest: Mapping[str, Any], artifacts_dir: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    images = {
        image.get("name"): image
        for image in manifest.get("images") or []
        if isinstance(image, Mapping) and isinstance(image.get("name"), str)
    }
    for name in REQUIRED_IMAGES:
        image = images.get(name)
        if not isinstance(image, Mapping):
            continue
        sbom = image.get("sbom") if isinstance(image.get("sbom"), Mapping) else {}
        scan = image.get("scan") if isinstance(image.get("scan"), Mapping) else {}
        scan_log = scan.get("log") if isinstance(scan.get("log"), Mapping) else {}
        sbom_file = sbom.get("path")
        scan_file = scan_log.get("path")
        entry: dict[str, Any] = {
            "name": name,
            "digest": image.get("digest"),
            "sbom_file": sbom_file,
            "sbom_sha256": None,
            "scan_log_file": scan_file,
            "scan_log_sha256": None,
        }
        for filename, hash_field in (
            (sbom_file, "sbom_sha256"),
            (scan_file, "scan_log_sha256"),
        ):
            if isinstance(filename, str) and filename:
                path = artifacts_dir / filename
                if path.is_file():
                    entry[hash_field] = sha256_file(path)
        entries.append(entry)
    return entries


def collect_release_evidence(
    manifest_path: Path,
    *,
    artifacts_dir: Path,
    repo_root: Path | None = None,
    main_ref: str = "origin/main",
    execute: bool = False,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    expected_repository: str | None = None,
    runner: CommandRunner = default_runner,
    which: Callable[[str], str | None] = shutil.which,
    identity_verifier: Callable[..., None] = verify_tag_commit,
    now: Callable[[], str] = utc_now_iso,
) -> dict[str, Any]:
    """Collect local and, when explicitly requested, live release evidence."""
    if not manifest_path.is_file():
        raise EvidenceError(f"manifest does not exist: {manifest_path}")
    if not artifacts_dir.is_dir():
        raise EvidenceError(f"artifacts directory does not exist: {artifacts_dir}")
    try:
        manifest = load_manifest(manifest_path)
        manifest_sha = sha256_file(manifest_path)
    except (ManifestError, OSError) as exc:
        raise EvidenceError(str(exc)) from exc
    tag, commit, repository = _release_identity(manifest)
    for label, supplied, observed in (
        ("tag", expected_tag, tag),
        ("commit", expected_commit, commit),
        ("repository", expected_repository, repository),
    ):
        if supplied is not None and supplied != observed:
            raise EvidenceError(
                f"supplied {label} {supplied!r} does not match the manifest release {observed!r}"
            )
    local_errors = manifest_errors(
        manifest,
        artifacts_dir=artifacts_dir,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
    )
    if local_errors:
        raise EvidenceError("manifest is invalid:\n- " + "\n- ".join(local_errors))

    local_verification = verify_release(
        manifest_path,
        artifacts_dir=artifacts_dir,
        profile="local",
        expected_tag=None,
        expected_commit=None,
        repo_root=None,
        runner=runner,
        which=which,
        now=now,
    )
    verification = local_verification
    checks: list[dict[str, Any]] = list(local_verification.get("checks") or [])
    if execute:
        if repo_root is None:
            raise EvidenceError("live evidence collection requires --repo-root for tag reachability")
        try:
            verification = verify_release(
                manifest_path,
                artifacts_dir=artifacts_dir,
                profile="production",
                expected_tag=tag,
                expected_commit=commit,
                repo_root=repo_root,
                main_ref=main_ref,
                runner=runner,
                which=which,
                identity_verifier=identity_verifier,
                now=now,
            )
        except VerificationError as exc:
            raise EvidenceError(str(exc)) from exc
        checks = list(verification.get("checks") or [])
        checks.append(_github_release_check(tag, repository, runner=runner, which=which))
    else:
        checks.append(
            _check(
                "github-release",
                NOT_RUN,
                True,
                "live GitHub Release evidence was not requested; pass --execute",
            )
        )

    state = _aggregate(checks)
    verified = state == PASS and all(
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
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "generated_at": now(),
        "executed": execute,
        "manifest_sha256": manifest_sha,
        "subject": _subject(manifest),
        "digests": _digests(manifest),
        "state": state,
        "verified": verified,
        "production_verified": bool(execute and verification.get("production_verified") is True),
        "github_release": next((check for check in checks if check.get("name") == "github-release"), None),
        "verification": verification,
        "artifacts": _artifact_entries(manifest, artifacts_dir),
        "checks": checks,
        "blockers": blockers,
        "limitations": limitations,
    }


def write_evidence_report(report: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _artifact_errors(
    report: Mapping[str, Any],
    artifacts_dir: Path,
) -> list[str]:
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, list):
        return ["release evidence artifacts are missing"]
    errors: list[str] = []
    names = {
        item.get("name")
        for item in artifacts
        if isinstance(item, Mapping) and isinstance(item.get("name"), str)
    }
    missing = [name for name in REQUIRED_IMAGES if name not in names]
    if missing:
        errors.append("release evidence is missing artifacts: " + ", ".join(missing))
    for item in artifacts:
        if not isinstance(item, Mapping):
            errors.append("release evidence contains a malformed artifact")
            continue
        for filename_field, hash_field in (
            ("sbom_file", "sbom_sha256"),
            ("scan_log_file", "scan_log_sha256"),
        ):
            filename = item.get(filename_field)
            digest = item.get(hash_field)
            if not isinstance(filename, str) or not isinstance(digest, str):
                errors.append(f"release evidence artifact {item.get('name')} has no {hash_field}")
                continue
            path = artifacts_dir / filename
            if not path.is_file():
                errors.append(f"release evidence artifact file is missing: {filename}")
                continue
            try:
                actual = sha256_file(path)
            except OSError as exc:
                errors.append(f"release evidence artifact could not be hashed: {exc}")
                continue
            if actual != digest:
                errors.append(f"release evidence artifact hash does not match {filename}")
    return errors


def evidence_report_errors(
    report: Any,
    manifest: Mapping[str, Any],
    *,
    manifest_path: Path,
    artifacts_dir: Path | None = None,
    require_live: bool = True,
) -> list[str]:
    """Return every reason a release-evidence report cannot authorize staging."""
    if not isinstance(report, Mapping):
        return ["release evidence report must be a JSON object"]
    errors: list[str] = []
    if report.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        errors.append(f"release evidence schema_version must be {EVIDENCE_SCHEMA_VERSION}")
    try:
        expected_sha = sha256_file(manifest_path)
    except OSError as exc:
        return [f"could not hash manifest {manifest_path}: {exc}"]
    if report.get("manifest_sha256") != expected_sha:
        errors.append("release evidence is not bound to the supplied manifest")
    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    subject = report.get("subject")
    if not isinstance(subject, Mapping):
        errors.append("release evidence subject is missing")
    else:
        for field in EVIDENCE_SUBJECT_FIELDS:
            if subject.get(field) != release.get(field):
                errors.append(f"release evidence subject.{field} does not match the manifest release")
    if require_live:
        if report.get("executed") is not True:
            errors.append("release evidence was not collected with live execution")
        if report.get("state") != PASS:
            errors.append(f"release evidence state is {report.get('state')!r}, not PASS")
        if report.get("verified") is not True:
            errors.append("release evidence verified is not true")
        if report.get("production_verified") is not True:
            errors.append("release evidence production_verified is not true")
        github_release = report.get("github_release")
        if not isinstance(github_release, Mapping) or github_release.get("state") != PASS:
            errors.append("release evidence does not prove a published GitHub Release")
    verification = report.get("verification")
    if not isinstance(verification, Mapping):
        errors.append("release evidence verification report is missing")
    else:
        if verification.get("overall_state") != PASS:
            errors.append("embedded verification report is not PASS")
        if verification.get("verified") is not True:
            errors.append("embedded verification report is not verified")
        if require_live and verification.get("production_verified") is not True:
            errors.append("embedded verification report is not production verified")
    if artifacts_dir is not None:
        errors.extend(_artifact_errors(report, artifacts_dir))
    return errors


def render_evidence_summary(report: Mapping[str, Any]) -> str:
    subject = report.get("subject") or {}
    lines = [
        f"Release evidence: {report.get('state')} "
        f"(executed={report.get('executed')}, verified={report.get('verified')}, "
        f"production_verified={report.get('production_verified')})",
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
    return "\n".join(lines) + "\n"
