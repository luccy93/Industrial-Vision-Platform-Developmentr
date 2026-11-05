"""V30 read-only evidence verification and integrity-manifest binding.

This module consumes the V23-V29 report formats without changing them. It
extracts the evidence references a report already declares, resolves each path
safely under an evidence root, re-hashes the exact stored bytes, and optionally
cross-checks a V30 integrity sidecar and its append-only audit chain.

Verification never repairs, rewrites, quarantines, or deletes evidence. It only
reads files and, when explicitly requested, writes a new diagnostic result to
stdout or a caller-supplied output path.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.app.core.redaction import dump_sanitized_json, redact_structure, redact_text
from tools.release.identity import DIGEST_PATTERN
from tools.release.integrity import (
    AUDIT_CHAIN_INVALID,
    AUDIT_EVENT_TYPES,
    AUDIT_PROFILE,
    AUDIT_SCHEMA_VERSION,
    EVIDENCE_CREATED,
    EVIDENCE_MISSING,
    EVIDENCE_MODIFIED,
    EVIDENCE_PATH_INVALID,
    EVIDENCE_REJECTED,
    EVIDENCE_REPLACED,
    EVIDENCE_VERIFIED,
    GENESIS_PREVIOUS_HASH,
    INTEGRITY_PROFILE,
    INTEGRITY_SCHEMA_VERSION,
    MANIFEST_BINDING_MISMATCH,
    MAX_INTEGRITY_BYTES,
    AuditChainError,
    AuditProblem,
    AuditVerification,
    EvidenceChangedDuringVerification,
    EvidencePathError,
    EvidenceRecord,
    IntegrityError,
    append_audit_event,
    build_audit_chain,
    canonical_json_bytes,
    create_checkpoint,
    evidence_record_for_file,
    hash_evidence_file,
    is_redacted_diagnostic_path,
    load_checkpoint,
    normalize_timestamp,
    normalized_path_key,
    read_audit_chain,
    render_audit_chain,
    resolve_evidence_path,
    sha256_bytes,
    validate_checkpoint,
    validate_relative_directory,
    validate_relative_path,
    verify_audit_chain,
    write_audit_chain,
    write_checkpoint,
)
from tools.release.manifest import sha256_file, utc_now_iso
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

VERIFICATION_SCHEMA_VERSION = 1
VERIFICATION_PROFILE = "evidence_verification"
MAX_REPORT_BYTES = 16 * 1024 * 1024

MUTATION_STATEMENT = (
    "Verification is read-only: no evidence file, report, manifest, audit chain, or checkpoint was modified."
)
TRUST_BOUNDARY = (
    "SHA-256 proves byte integrity relative to the expected digest. It does not "
    "prove authenticity, truthfulness, or completeness, and a local hash chain can "
    "be rewritten by an attacker with write access to both the evidence and the chain."
)

INTEGRITY_MANIFEST_FIELDS = (
    "schema_version",
    "profile",
    "generated_at",
    "report",
    "parent_id",
    "evidence_root",
    "evidence",
    "audit",
    "authorized_reuse",
    "limitations",
)
INTEGRITY_REPORT_FIELDS = ("path", "sha256", "schema_version", "profile")
INTEGRITY_AUDIT_FIELDS = ("path", "sha256", "record_count", "head", "checkpoint")
AUTHORIZED_REUSE_FIELDS = ("sha256", "reason")

DEFAULT_LIMITATIONS = (
    "SHA-256 proves byte integrity relative to the expected digest; it does not prove "
    "authenticity, truthfulness, or completeness.",
    "A local audit chain is tamper-evident, not immutable: an attacker with write access "
    "to both evidence and chain can recompute every hash. Use an independent checkpoint "
    "for stronger guarantees.",
    "Verification is read-only and does not repair, rewrite, quarantine, or delete evidence.",
    "File-change detection is best-effort on platforms without descriptor-relative path "
    "walking; a hostile writer with concurrent access remains a residual risk.",
    "Symlinks and junctions below the evidence root are rejected. The evidence root itself may be a symlink.",
)


class EvidenceVerificationError(RuntimeError):
    """The verification request or integrity manifest is invalid."""


@dataclass(frozen=True)
class BoundEvidence:
    """One evidence reference declared by a report or an integrity manifest."""

    evidence_id: str
    kind: str
    path: str
    sha256: str
    size: int | None = None
    state: str | None = None
    source: str = ""
    aliases: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerificationCheck:
    """One stable verification outcome."""

    name: str
    outcome: str
    required: bool
    detail: str
    evidence_id: str | None = None
    expected: str | None = None
    actual: str | None = None
    event_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "outcome": self.outcome,
            "required": self.required,
            "detail": redact_text(self.detail)[:500],
            "evidence_id": self.evidence_id,
            "expected": redact_text(self.expected)[:500] if self.expected is not None else None,
            "actual": redact_text(self.actual)[:500] if self.actual is not None else None,
            "event_type": self.event_type,
        }


@dataclass(frozen=True)
class VerificationIssue:
    """One sanitized integrity incident."""

    event_type: str
    outcome: str
    evidence_id: str | None
    detail: str
    expected: str | None = None
    actual: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "outcome": self.outcome,
            "evidence_id": self.evidence_id,
            "detail": redact_text(self.detail)[:500],
            "expected": redact_text(self.expected)[:500] if self.expected is not None else None,
            "actual": redact_text(self.actual)[:500] if self.actual is not None else None,
        }


@dataclass
class VerificationResult:
    """Complete read-only verification result."""

    outcome: str
    checks: list[VerificationCheck] = field(default_factory=list)
    issues: list[VerificationIssue] = field(default_factory=list)
    report: dict[str, Any] | None = None
    integrity: dict[str, Any] | None = None
    audit: dict[str, Any] | None = None
    manifest: dict[str, Any] | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    generated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        limitations = list(DEFAULT_LIMITATIONS)
        for item in self.limitations:
            if item not in limitations:
                limitations.append(item)
        payload = {
            "schema_version": VERIFICATION_SCHEMA_VERSION,
            "profile": VERIFICATION_PROFILE,
            "generated_at": normalize_timestamp(self.generated_at),
            "outcome": self.outcome,
            "report": self.report,
            "integrity": self.integrity,
            "audit": self.audit,
            "manifest": self.manifest,
            "evidence": self.evidence,
            "checks": [check.to_dict() for check in self.checks],
            "issues": [issue.to_dict() for issue in self.issues],
            "limitations": [redact_text(item)[:500] for item in limitations],
            "mutation": {"performed": False, "statement": MUTATION_STATEMENT},
            "trust_boundary": TRUST_BOUNDARY,
        }
        cleaned = redact_structure(payload)
        if not isinstance(cleaned, dict):
            raise EvidenceVerificationError("verification result could not be sanitized")
        return cleaned


@dataclass(frozen=True)
class IntegrityManifest:
    """Validated V30 integrity sidecar."""

    payload: dict[str, Any]
    report: dict[str, Any]
    parent_id: str
    evidence_root: str
    evidence: tuple[EvidenceRecord, ...]
    audit: dict[str, Any]
    authorized_reuse: tuple[dict[str, Any], ...]
    limitations: tuple[str, ...]


def aggregate_outcome(checks: Sequence[VerificationCheck]) -> str:
    """Aggregate required checks without ever upgrading a missing result."""
    required = [check for check in checks if check.required]
    if not required:
        return NOT_RUN
    outcomes = {check.outcome for check in required}
    for state in (FAIL, UNAVAILABLE, NOT_RUN):
        if state in outcomes:
            return state
    return PASS


def verification_exit_code(outcome: str) -> int:
    """Map a stable outcome to a process exit code."""
    return {
        PASS: 0,
        FAIL: 1,
        UNAVAILABLE: 2,
        NOT_RUN: 3,
    }.get(outcome, 4)


def _check(
    name: str,
    outcome: str,
    detail: str,
    *,
    required: bool = True,
    evidence_id: str | None = None,
    expected: str | None = None,
    actual: str | None = None,
    event_type: str | None = None,
) -> VerificationCheck:
    return VerificationCheck(
        name=name,
        outcome=outcome,
        required=required,
        detail=detail,
        evidence_id=evidence_id,
        expected=expected,
        actual=actual,
        event_type=event_type,
    )


def _issue(
    event_type: str,
    outcome: str,
    detail: str,
    *,
    evidence_id: str | None = None,
    expected: str | None = None,
    actual: str | None = None,
) -> VerificationIssue:
    return VerificationIssue(
        event_type=event_type,
        outcome=outcome,
        evidence_id=evidence_id,
        detail=detail,
        expected=expected,
        actual=actual,
    )


def _safe_identifier(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 512:
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None
    return value


def _canonical_evidence_id(kind: str, path: str, explicit: Any = None) -> str:
    explicit_id = _safe_identifier(explicit)
    if explicit_id is not None:
        return explicit_id
    candidate = f"{kind}:{path}"
    if _safe_identifier(candidate) is not None:
        return candidate
    safe_kind = (
        "".join(character if character.isalnum() or character in "_.-" else "-" for character in kind).strip(
            "-"
        )
        or "evidence"
    )
    digest = sha256_bytes(canonical_json_bytes({"kind": kind, "path": path}))
    return f"{safe_kind}:{digest.split(':', 1)[1][:24]}"


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and DIGEST_PATTERN.fullmatch(value) is not None


def extract_bound_evidence(report: Mapping[str, Any]) -> tuple[list[BoundEvidence], list[str]]:
    """Extract every evidence reference a V23-V29 report already declares.

    Aliases that point at the same path and digest are merged. A path bound to
    two different digests, or an identifier reused for different bytes, is a
    conflict rather than a silent merge.
    """
    entries: list[BoundEvidence] = []
    conflicts: list[str] = []
    by_key: dict[tuple[str, str], int] = {}
    by_id: dict[str, tuple[str, str]] = {}

    def add(
        *,
        kind: str,
        path: str,
        digest: str,
        state: str | None,
        source: str,
        evidence_id: str | None = None,
        size: int | None = None,
    ) -> None:
        kind = kind if isinstance(kind, str) and kind else "evidence"
        path = path if isinstance(path, str) else ""
        digest = digest if isinstance(digest, str) else ""
        identifier = _canonical_evidence_id(kind, path, evidence_id)
        key = (path, digest)
        if identifier in by_id and by_id[identifier] != key:
            conflicts.append(f"evidence identifier {identifier!r} is bound to more than one path or digest")
            return
        if key in by_key:
            index = by_key[key]
            existing = entries[index]
            aliases = tuple(sorted(set(existing.aliases) | ({identifier} - {existing.evidence_id})))
            kinds = tuple(sorted(set(existing.kinds) | {kind}))
            entries[index] = BoundEvidence(
                evidence_id=existing.evidence_id,
                kind=existing.kind,
                path=existing.path,
                sha256=existing.sha256,
                size=existing.size,
                state=existing.state,
                source=existing.source,
                aliases=aliases,
                kinds=kinds,
            )
            return
        path_conflict = next(
            (existing for existing in entries if existing.path == path and existing.sha256 != digest),
            None,
        )
        if path_conflict is not None:
            conflicts.append(f"evidence path {path!r} is bound to more than one digest")
        by_key[key] = len(entries)
        by_id[identifier] = key
        entries.append(
            BoundEvidence(
                evidence_id=identifier,
                kind=kind,
                path=path,
                sha256=digest,
                size=size if isinstance(size, int) and not isinstance(size, bool) else None,
                state=state if isinstance(state, str) else None,
                source=source,
                kinds=(kind,),
            )
        )

    evidence = report.get("evidence")
    if isinstance(evidence, list):
        for index, item in enumerate(evidence):
            if not isinstance(item, Mapping):
                conflicts.append(f"report evidence[{index}] is malformed")
                continue
            if "path" not in item or "sha256" not in item:
                conflicts.append(f"report evidence[{index}] lacks path or sha256")
                continue
            add(
                kind=str(item.get("kind") or "evidence"),
                path=str(item.get("path")),
                digest=str(item.get("sha256")),
                state=item.get("state") if isinstance(item.get("state"), str) else None,
                source=f"evidence[{index}]",
                evidence_id=item.get("evidence_id"),
                size=item.get("size"),
            )

    bindings = report.get("bindings")
    if isinstance(bindings, Mapping):
        for name, binding in bindings.items():
            if not isinstance(binding, Mapping):
                continue
            if "path" not in binding or "sha256" not in binding:
                conflicts.append(f"report binding {name!r} lacks path or sha256")
                continue
            kind = str(binding.get("kind") or name)
            add(
                kind=kind,
                path=str(binding.get("path")),
                digest=str(binding.get("sha256")),
                state=binding.get("state") if isinstance(binding.get("state"), str) else None,
                source=f"bindings.{name}",
                evidence_id=f"binding:{name}:{kind}",
                size=binding.get("size"),
            )

    artifacts = report.get("artifacts")
    if isinstance(artifacts, list):
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, Mapping):
                continue
            name = str(artifact.get("name") or f"artifact-{index}")
            for filename_field, digest_field, label in (
                ("sbom_file", "sbom_sha256", "sbom"),
                ("scan_log_file", "scan_log_sha256", "scan"),
            ):
                filename = artifact.get(filename_field)
                digest = artifact.get(digest_field)
                if isinstance(filename, str) and isinstance(digest, str):
                    add(
                        kind=f"{label}:{name}",
                        path=filename,
                        digest=digest,
                        state=None,
                        source=f"artifacts[{index}].{filename_field}",
                        evidence_id=f"artifact:{name}:{label}",
                    )

    entries.sort(key=lambda item: (item.evidence_id, item.path, item.sha256))
    return entries, conflicts


def _default_evidence_root(report_path: Path, report: Mapping[str, Any]) -> Path:
    readiness = report_path.parent / "readiness-evidence"
    if isinstance(report.get("bindings"), Mapping) and readiness.is_dir():
        return readiness
    return report_path.parent


def _default_integrity_path(report_path: Path) -> Path:
    if report_path.suffix.lower() == ".json":
        return report_path.with_name(f"{report_path.stem}.integrity.json")
    return report_path.with_name(f"{report_path.name}.integrity.json")


def _default_audit_path(report_path: Path) -> Path:
    if report_path.suffix.lower() == ".json":
        return report_path.with_name(f"{report_path.stem}.audit.jsonl")
    return report_path.with_name(f"{report_path.name}.audit.jsonl")


def default_integrity_path(report_path: Path) -> Path:
    """Return the conventional sidecar path for a report."""
    return _default_integrity_path(Path(report_path))


def default_audit_path(report_path: Path) -> Path:
    """Return the conventional audit-chain path for a report."""
    return _default_audit_path(Path(report_path))


def _verify_one(
    bound: BoundEvidence,
    *,
    evidence_root: Path,
    required: bool = True,
) -> tuple[list[VerificationCheck], list[VerificationIssue], dict[str, Any]]:
    checks: list[VerificationCheck] = []
    issues: list[VerificationIssue] = []
    summary: dict[str, Any] = {
        "evidence_id": bound.evidence_id,
        "kind": bound.kind,
        "path": bound.path,
        "expected_sha256": bound.sha256,
        "actual_sha256": None,
        "expected_size": bound.size,
        "actual_size": None,
        "outcome": NOT_RUN,
        "aliases": list(bound.aliases),
    }
    name = f"evidence:{bound.evidence_id}"
    if bound.state is not None and bound.state != PASS:
        checks.append(
            _check(
                name,
                FAIL,
                f"evidence binding state is {bound.state!r}, not PASS",
                required=required,
                evidence_id=bound.evidence_id,
                event_type=EVIDENCE_REJECTED,
            )
        )
        issues.append(
            _issue(
                EVIDENCE_REJECTED,
                FAIL,
                f"evidence binding state is {bound.state!r}, not PASS",
                evidence_id=bound.evidence_id,
            )
        )
    if is_redacted_diagnostic_path(bound.path):
        checks.append(
            _check(
                name,
                FAIL,
                "redacted diagnostic copy cannot be verified as original evidence",
                required=required,
                evidence_id=bound.evidence_id,
                event_type=EVIDENCE_REJECTED,
            )
        )
        issues.append(
            _issue(
                EVIDENCE_REJECTED,
                FAIL,
                "redacted diagnostic copy cannot be verified as original evidence",
                evidence_id=bound.evidence_id,
            )
        )
        summary["outcome"] = FAIL
        return checks, issues, summary
    if not _valid_digest(bound.sha256):
        checks.append(
            _check(
                name,
                FAIL,
                "expected evidence digest is not sha256:<64 lowercase hex>",
                required=required,
                evidence_id=bound.evidence_id,
                expected=bound.sha256,
                event_type=EVIDENCE_REJECTED,
            )
        )
        issues.append(
            _issue(
                EVIDENCE_REJECTED,
                FAIL,
                "expected evidence digest is invalid",
                evidence_id=bound.evidence_id,
                expected=bound.sha256,
            )
        )
        summary["outcome"] = FAIL
        return checks, issues, summary

    try:
        resolved = resolve_evidence_path(evidence_root, bound.path)
    except EvidencePathError as exc:
        checks.append(
            _check(
                name,
                FAIL if exc.code != UNAVAILABLE else UNAVAILABLE,
                exc.detail,
                required=required,
                evidence_id=bound.evidence_id,
                expected=bound.path,
                event_type=exc.code,
            )
        )
        issues.append(
            _issue(
                exc.code,
                FAIL if exc.code != UNAVAILABLE else UNAVAILABLE,
                exc.detail,
                evidence_id=bound.evidence_id,
                expected=bound.path,
            )
        )
        summary["outcome"] = checks[-1].outcome
        return checks, issues, summary

    if not resolved.exists():
        detail = "evidence file is missing"
        checks.append(
            _check(
                name,
                FAIL,
                detail,
                required=required,
                evidence_id=bound.evidence_id,
                expected=bound.path,
                event_type=EVIDENCE_MISSING,
            )
        )
        issues.append(
            _issue(EVIDENCE_MISSING, FAIL, detail, evidence_id=bound.evidence_id, expected=bound.path)
        )
        summary["outcome"] = FAIL
        return checks, issues, summary
    if not resolved.is_file():
        detail = "evidence path is not a regular file"
        checks.append(
            _check(
                name,
                FAIL,
                detail,
                required=required,
                evidence_id=bound.evidence_id,
                expected=bound.path,
                event_type=EVIDENCE_REJECTED,
            )
        )
        issues.append(
            _issue(EVIDENCE_REJECTED, FAIL, detail, evidence_id=bound.evidence_id, expected=bound.path)
        )
        summary["outcome"] = FAIL
        return checks, issues, summary

    try:
        digest = hash_evidence_file(resolved)
    except EvidenceChangedDuringVerification as exc:
        detail = str(exc)
        checks.append(
            _check(
                name,
                UNAVAILABLE,
                detail,
                required=required,
                evidence_id=bound.evidence_id,
                expected=bound.sha256,
                event_type=EVIDENCE_REJECTED,
            )
        )
        issues.append(
            _issue(
                EVIDENCE_REJECTED,
                UNAVAILABLE,
                detail,
                evidence_id=bound.evidence_id,
                expected=bound.sha256,
            )
        )
        summary["outcome"] = UNAVAILABLE
        return checks, issues, summary
    except EvidencePathError as exc:
        checks.append(
            _check(
                name,
                FAIL if exc.code != UNAVAILABLE else UNAVAILABLE,
                exc.detail,
                required=required,
                evidence_id=bound.evidence_id,
                expected=bound.sha256,
                event_type=exc.code,
            )
        )
        issues.append(
            _issue(
                exc.code,
                FAIL if exc.code != UNAVAILABLE else UNAVAILABLE,
                exc.detail,
                evidence_id=bound.evidence_id,
                expected=bound.sha256,
            )
        )
        summary["outcome"] = checks[-1].outcome
        return checks, issues, summary
    except OSError:
        detail = "evidence file could not be read"
        checks.append(
            _check(
                name,
                UNAVAILABLE,
                detail,
                required=required,
                evidence_id=bound.evidence_id,
                expected=bound.sha256,
                event_type=EVIDENCE_REJECTED,
            )
        )
        issues.append(
            _issue(
                EVIDENCE_REJECTED,
                UNAVAILABLE,
                detail,
                evidence_id=bound.evidence_id,
                expected=bound.sha256,
            )
        )
        summary["outcome"] = UNAVAILABLE
        return checks, issues, summary

    summary["actual_sha256"] = digest.sha256
    summary["actual_size"] = digest.size
    size_mismatch = bound.size is not None and digest.size != bound.size
    digest_mismatch = digest.sha256 != bound.sha256
    if digest_mismatch:
        event_type = (
            EVIDENCE_REPLACED if bound.size is None or digest.size == bound.size else EVIDENCE_MODIFIED
        )
        detail = (
            "evidence digest does not match the expected digest"
            if event_type == EVIDENCE_REPLACED
            else "evidence content and size do not match the expected record"
        )
        checks.append(
            _check(
                name,
                FAIL,
                detail,
                required=required,
                evidence_id=bound.evidence_id,
                expected=bound.sha256,
                actual=digest.sha256,
                event_type=event_type,
            )
        )
        issues.append(
            _issue(
                event_type,
                FAIL,
                detail,
                evidence_id=bound.evidence_id,
                expected=bound.sha256,
                actual=digest.sha256,
            )
        )
        summary["outcome"] = FAIL
    elif size_mismatch:
        checks.append(
            _check(
                name,
                FAIL,
                "evidence size does not match the expected record",
                required=required,
                evidence_id=bound.evidence_id,
                expected=str(bound.size),
                actual=str(digest.size),
                event_type=EVIDENCE_MODIFIED,
            )
        )
        issues.append(
            _issue(
                EVIDENCE_MODIFIED,
                FAIL,
                "evidence size does not match the expected record",
                evidence_id=bound.evidence_id,
                expected=str(bound.size),
                actual=str(digest.size),
            )
        )
        summary["outcome"] = FAIL
    else:
        checks.append(
            _check(
                name,
                PASS,
                "evidence exists and its SHA-256 matches the exact stored bytes",
                required=required,
                evidence_id=bound.evidence_id,
                expected=bound.sha256,
                actual=digest.sha256,
                event_type=EVIDENCE_VERIFIED,
            )
        )
        summary["outcome"] = PASS
    return checks, issues, summary


def verify_evidence_set(
    entries: Sequence[BoundEvidence],
    *,
    evidence_root: Path,
    authorized_reuse: Sequence[str] = (),
) -> tuple[list[VerificationCheck], list[VerificationIssue], list[dict[str, Any]]]:
    """Verify a set of evidence references and detect path/content aliasing."""
    checks: list[VerificationCheck] = []
    issues: list[VerificationIssue] = []
    summaries: list[dict[str, Any]] = []
    if not entries:
        checks.append(
            _check(
                "report-evidence",
                NOT_RUN,
                "report has no supported evidence bindings",
                event_type=EVIDENCE_REJECTED,
            )
        )
        return checks, issues, summaries

    path_owners: dict[str, str] = {}
    for entry in entries:
        try:
            resolved = resolve_evidence_path(evidence_root, entry.path)
        except EvidencePathError:
            resolved = None
        if resolved is not None:
            key = normalized_path_key(resolved)
            owner = path_owners.get(key)
            if owner is not None and owner != entry.evidence_id:
                detail = "duplicate normalized evidence path is bound to more than one identifier"
                checks.append(
                    _check(
                        f"path-alias:{entry.evidence_id}",
                        FAIL,
                        detail,
                        evidence_id=entry.evidence_id,
                        expected=owner,
                        actual=entry.evidence_id,
                        event_type=MANIFEST_BINDING_MISMATCH,
                    )
                )
                issues.append(
                    _issue(
                        MANIFEST_BINDING_MISMATCH,
                        FAIL,
                        detail,
                        evidence_id=entry.evidence_id,
                        expected=owner,
                        actual=entry.evidence_id,
                    )
                )
            else:
                path_owners[key] = entry.evidence_id
        entry_checks, entry_issues, summary = _verify_one(entry, evidence_root=evidence_root)
        checks.extend(entry_checks)
        issues.extend(entry_issues)
        summaries.append(summary)

    allowed = {digest for digest in authorized_reuse if _valid_digest(digest)}
    content_paths: dict[str, set[str]] = {}
    for summary in summaries:
        if summary.get("actual_sha256"):
            content_paths.setdefault(str(summary["actual_sha256"]), set()).add(str(summary["path"]))
    for digest, paths in sorted(content_paths.items()):
        if len(paths) > 1 and digest not in allowed:
            detail = "evidence content is reused under more than one identifier"
            checks.append(
                _check(
                    f"reuse:{digest}",
                    FAIL,
                    detail,
                    expected="one authorized evidence path",
                    actual=", ".join(sorted(paths)),
                    event_type=EVIDENCE_REJECTED,
                )
            )
            issues.append(
                _issue(
                    EVIDENCE_REJECTED,
                    FAIL,
                    detail,
                    expected="one authorized evidence path",
                    actual=", ".join(sorted(paths)),
                )
            )
    return checks, issues, summaries


def _report_manifest_hash(report: Mapping[str, Any]) -> str | None:
    for value in (
        report.get("manifest_sha256"),
        (report.get("release") or {}).get("manifest_sha256")
        if isinstance(report.get("release"), Mapping)
        else None,
        (report.get("manifest") or {}).get("sha256") if isinstance(report.get("manifest"), Mapping) else None,
    ):
        if isinstance(value, str):
            return value
    return None


def _report_subject(report: Mapping[str, Any]) -> Mapping[str, Any] | None:
    subject = report.get("subject")
    if isinstance(subject, Mapping):
        return subject
    release = report.get("release")
    if isinstance(release, Mapping):
        nested = release.get("subject")
        if isinstance(nested, Mapping):
            return nested
        return release
    return None


def verify_manifest_binding(
    report: Mapping[str, Any],
    *,
    manifest_path: Path | None,
    entries: Sequence[BoundEvidence],
) -> tuple[list[VerificationCheck], list[VerificationIssue], dict[str, Any] | None]:
    """Verify report-to-manifest binding against the exact manifest bytes."""
    if manifest_path is None:
        return (
            [
                _check(
                    "manifest-binding",
                    NOT_RUN,
                    "no release manifest was supplied; manifest binding was not evaluated",
                    required=False,
                )
            ],
            [],
            None,
        )
    try:
        if manifest_path.stat().st_size > MAX_INTEGRITY_BYTES:
            raise EvidenceVerificationError("manifest exceeds the maximum supported size")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except OSError:
        detail = "release manifest is missing or unreadable"
        return (
            [_check("manifest-binding", UNAVAILABLE, detail, event_type=MANIFEST_BINDING_MISMATCH)],
            [
                _issue(
                    MANIFEST_BINDING_MISMATCH,
                    UNAVAILABLE,
                    detail,
                    expected=str(manifest_path),
                )
            ],
            None,
        )
    except json.JSONDecodeError:
        detail = "release manifest is not valid JSON"
        return (
            [_check("manifest-binding", FAIL, detail, event_type=MANIFEST_BINDING_MISMATCH)],
            [_issue(MANIFEST_BINDING_MISMATCH, FAIL, detail, expected=str(manifest_path))],
            None,
        )
    if not isinstance(manifest, Mapping):
        detail = "release manifest is not a JSON object"
        return (
            [_check("manifest-binding", FAIL, detail, event_type=MANIFEST_BINDING_MISMATCH)],
            [_issue(MANIFEST_BINDING_MISMATCH, FAIL, detail, expected=str(manifest_path))],
            None,
        )

    actual_manifest_sha = sha256_file(manifest_path)
    details: dict[str, Any] = {
        "path": str(manifest_path),
        "sha256": actual_manifest_sha,
        "report_sha256": _report_manifest_hash(report),
    }
    checks: list[VerificationCheck] = []
    issues: list[VerificationIssue] = []
    report_sha = _report_manifest_hash(report)
    if report_sha is None:
        checks.append(
            _check(
                "manifest-binding",
                NOT_RUN,
                "report does not declare a release-manifest hash",
                required=False,
                expected=actual_manifest_sha,
            )
        )
        return checks, issues, details
    if report_sha != actual_manifest_sha:
        detail = "report is not bound to the supplied release manifest"
        checks.append(
            _check(
                "manifest-binding",
                FAIL,
                detail,
                expected=actual_manifest_sha,
                actual=report_sha,
                event_type=MANIFEST_BINDING_MISMATCH,
            )
        )
        issues.append(
            _issue(
                MANIFEST_BINDING_MISMATCH,
                FAIL,
                detail,
                expected=actual_manifest_sha,
                actual=report_sha,
            )
        )
        return checks, issues, details

    release = manifest.get("release") if isinstance(manifest.get("release"), Mapping) else {}
    subject = _report_subject(report)
    if isinstance(subject, Mapping) and release:
        mismatches = [
            field
            for field in ("tag", "commit", "source_repository")
            if subject.get(field) is not None and subject.get(field) != release.get(field)
        ]
        if mismatches:
            detail = "report subject does not match the release manifest: " + ", ".join(mismatches)
            checks.append(
                _check(
                    "manifest-subject",
                    FAIL,
                    detail,
                    event_type=MANIFEST_BINDING_MISMATCH,
                )
            )
            issues.append(_issue(MANIFEST_BINDING_MISMATCH, FAIL, detail))
        else:
            checks.append(
                _check(
                    "manifest-subject",
                    PASS,
                    "report subject matches the release manifest",
                    event_type=EVIDENCE_VERIFIED,
                )
            )
    else:
        checks.append(
            _check(
                "manifest-subject",
                NOT_RUN,
                "report does not declare a release subject",
                required=False,
            )
        )

    manifest_evidence = [
        entry
        for entry in entries
        if entry.kind in ("release-manifest", "manifest") or Path(entry.path).name == manifest_path.name
    ]
    if manifest_evidence:
        matching = [entry for entry in manifest_evidence if entry.sha256 == actual_manifest_sha]
        if len(matching) != len(manifest_evidence):
            detail = "report evidence for the release manifest does not match the supplied manifest bytes"
            checks.append(
                _check(
                    "manifest-evidence",
                    FAIL,
                    detail,
                    expected=actual_manifest_sha,
                    actual=", ".join(sorted({entry.sha256 for entry in manifest_evidence})),
                    event_type=MANIFEST_BINDING_MISMATCH,
                )
            )
            issues.append(
                _issue(
                    MANIFEST_BINDING_MISMATCH,
                    FAIL,
                    detail,
                    expected=actual_manifest_sha,
                    actual=", ".join(sorted({entry.sha256 for entry in manifest_evidence})),
                )
            )
        else:
            checks.append(
                _check(
                    "manifest-evidence",
                    PASS,
                    "report evidence for the release manifest matches the supplied manifest bytes",
                    event_type=EVIDENCE_VERIFIED,
                )
            )
    checks.append(
        _check(
            "manifest-binding",
            PASS,
            "report is bound to the exact release manifest bytes",
            expected=actual_manifest_sha,
            actual=report_sha,
            event_type=EVIDENCE_VERIFIED,
        )
    )
    return checks, issues, details


def _read_json_file(path: Path, *, label: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        if path.stat().st_size > MAX_REPORT_BYTES:
            return None, f"{label} exceeds the maximum supported size"
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        return None, f"{label} is missing or unreadable"
    except json.JSONDecodeError:
        return None, f"{label} is not valid JSON"
    if not isinstance(payload, dict):
        return None, f"{label} is not a JSON object"
    return payload, None


def load_integrity_manifest(path: Path) -> IntegrityManifest:
    """Load and validate a V30 integrity sidecar."""
    payload, error = _read_json_file(Path(path), label="integrity manifest")
    if payload is None:
        raise EvidenceVerificationError(error or "integrity manifest is invalid")
    if sorted(payload) != sorted(INTEGRITY_MANIFEST_FIELDS):
        raise EvidenceVerificationError("integrity manifest has unexpected or missing fields")
    if payload.get("schema_version") != INTEGRITY_SCHEMA_VERSION:
        raise EvidenceVerificationError(
            f"integrity manifest schema_version must be {INTEGRITY_SCHEMA_VERSION}"
        )
    if payload.get("profile") != INTEGRITY_PROFILE:
        raise EvidenceVerificationError(f"integrity manifest profile must be {INTEGRITY_PROFILE!r}")
    try:
        generated_at = normalize_timestamp(payload.get("generated_at"))
    except IntegrityError as exc:
        raise EvidenceVerificationError("integrity manifest generated_at is invalid") from exc

    report = payload.get("report")
    if not isinstance(report, Mapping) or sorted(report) != sorted(INTEGRITY_REPORT_FIELDS):
        raise EvidenceVerificationError("integrity manifest report binding is malformed")
    try:
        report_path = validate_relative_path(report.get("path"))
    except EvidencePathError as exc:
        raise EvidenceVerificationError("integrity manifest report path is invalid") from exc
    if not _valid_digest(report.get("sha256")):
        raise EvidenceVerificationError("integrity manifest report hash is invalid")
    report_schema_version = report.get("schema_version")
    if isinstance(report_schema_version, bool) or not isinstance(report_schema_version, int):
        raise EvidenceVerificationError("integrity manifest report schema_version is invalid")
    if report_schema_version < 1:
        raise EvidenceVerificationError("integrity manifest report schema_version must be positive")
    if not isinstance(report.get("profile"), str) or not report.get("profile"):
        raise EvidenceVerificationError("integrity manifest report profile is invalid")

    parent_id = payload.get("parent_id")
    if not isinstance(parent_id, str) or not parent_id or len(parent_id) > 512:
        raise EvidenceVerificationError("integrity manifest parent_id is invalid")
    try:
        evidence_root = validate_relative_directory(payload.get("evidence_root"))
    except EvidencePathError as exc:
        raise EvidenceVerificationError("integrity manifest evidence_root is invalid") from exc

    evidence_payload = payload.get("evidence")
    if not isinstance(evidence_payload, list) or not evidence_payload:
        raise EvidenceVerificationError("integrity manifest must contain at least one evidence record")
    evidence: list[EvidenceRecord] = []
    seen_ids: set[str] = set()
    seen_paths: dict[str, str] = {}
    for item in evidence_payload:
        try:
            record = EvidenceRecord.from_dict(item)
        except IntegrityError as exc:
            raise EvidenceVerificationError("integrity manifest evidence record is malformed") from exc
        if record.parent_id != parent_id:
            raise EvidenceVerificationError(
                f"evidence record {record.evidence_id!r} is not bound to the manifest parent"
            )
        if is_redacted_diagnostic_path(record.path):
            raise EvidenceVerificationError(
                f"evidence record {record.evidence_id!r} points at a redacted diagnostic copy"
            )
        if record.evidence_id in seen_ids:
            raise EvidenceVerificationError(
                f"integrity manifest evidence identifier {record.evidence_id!r} is duplicated"
            )
        seen_ids.add(record.evidence_id)
        if record.path in seen_paths and seen_paths[record.path] != record.sha256:
            raise EvidenceVerificationError(
                f"integrity manifest path {record.path!r} is bound to more than one digest"
            )
        seen_paths[record.path] = record.sha256
        evidence.append(record)

    audit = payload.get("audit")
    if not isinstance(audit, Mapping) or sorted(audit) != sorted(INTEGRITY_AUDIT_FIELDS):
        raise EvidenceVerificationError("integrity manifest audit binding is malformed")
    try:
        audit_path = validate_relative_path(audit.get("path"))
    except EvidencePathError as exc:
        raise EvidenceVerificationError("integrity manifest audit path is invalid") from exc
    if not _valid_digest(audit.get("sha256")):
        raise EvidenceVerificationError("integrity manifest audit hash is invalid")
    record_count = audit.get("record_count")
    if isinstance(record_count, bool) or not isinstance(record_count, int) or record_count < 1:
        raise EvidenceVerificationError("integrity manifest audit record_count is invalid")
    if not _valid_digest(audit.get("head")):
        raise EvidenceVerificationError("integrity manifest audit head is invalid")
    checkpoint = audit.get("checkpoint")
    if checkpoint is not None:
        try:
            checkpoint = validate_checkpoint(checkpoint)
        except IntegrityError as exc:
            raise EvidenceVerificationError("integrity manifest checkpoint is invalid") from exc

    reuse_payload = payload.get("authorized_reuse")
    if not isinstance(reuse_payload, list):
        raise EvidenceVerificationError("integrity manifest authorized_reuse must be a list")
    authorized_reuse: list[dict[str, Any]] = []
    seen_reuse: set[str] = set()
    for item in reuse_payload:
        if not isinstance(item, Mapping) or sorted(item) != sorted(AUTHORIZED_REUSE_FIELDS):
            raise EvidenceVerificationError("authorized_reuse entry is malformed")
        if not _valid_digest(item.get("sha256")) or item.get("sha256") in seen_reuse:
            raise EvidenceVerificationError("authorized_reuse digest is invalid or duplicated")
        reason = item.get("reason")
        if not isinstance(reason, str) or not reason:
            raise EvidenceVerificationError("authorized_reuse reason is invalid")
        seen_reuse.add(item["sha256"])
        authorized_reuse.append({"sha256": item["sha256"], "reason": redact_text(reason)[:500]})

    limitations_payload = payload.get("limitations")
    if not isinstance(limitations_payload, list) or not all(
        isinstance(item, str) for item in limitations_payload
    ):
        raise EvidenceVerificationError("integrity manifest limitations must be a list of strings")

    return IntegrityManifest(
        payload={
            **payload,
            "generated_at": generated_at,
            "report": {**report, "path": report_path},
            "audit": {**audit, "path": audit_path, "checkpoint": checkpoint},
            "authorized_reuse": authorized_reuse,
        },
        report={**report, "path": report_path},
        parent_id=parent_id,
        evidence_root=evidence_root,
        evidence=tuple(evidence),
        audit={**audit, "path": audit_path, "checkpoint": checkpoint},
        authorized_reuse=tuple(authorized_reuse),
        limitations=tuple(redact_text(item)[:500] for item in limitations_payload),
    )


def _resolve_manifest_path(base: Path, relative: str, *, label: str) -> Path:
    try:
        return resolve_evidence_path(base, relative)
    except EvidencePathError as exc:
        raise EvidenceVerificationError(f"{label} path is unsafe: {exc.detail}") from exc


def _audit_incidents(records: Sequence[Mapping[str, Any]]) -> list[VerificationIssue]:
    incidents: list[VerificationIssue] = []
    for record in records:
        event_type = record.get("event_type")
        outcome = record.get("outcome")
        evidence_id = record.get("evidence_id")
        if event_type == EVIDENCE_VERIFIED and outcome == FAIL:
            incidents.append(
                _issue(
                    EVIDENCE_REJECTED,
                    FAIL,
                    "audit chain records a failed evidence verification",
                    evidence_id=evidence_id if isinstance(evidence_id, str) else None,
                )
            )
        elif event_type in (
            EVIDENCE_MODIFIED,
            EVIDENCE_MISSING,
            EVIDENCE_REPLACED,
            EVIDENCE_REJECTED,
            EVIDENCE_PATH_INVALID,
            MANIFEST_BINDING_MISMATCH,
            AUDIT_CHAIN_INVALID,
        ):
            incidents.append(
                _issue(
                    str(event_type),
                    FAIL,
                    f"audit chain records {event_type}",
                    evidence_id=evidence_id if isinstance(evidence_id, str) else None,
                )
            )
    return incidents


def _cross_check_created_events(
    entries: Sequence[BoundEvidence],
    records: Sequence[Mapping[str, Any]],
) -> tuple[list[VerificationCheck], list[VerificationIssue]]:
    checks: list[VerificationCheck] = []
    issues: list[VerificationIssue] = []
    created: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if record.get("event_type") != EVIDENCE_CREATED:
            continue
        evidence = record.get("evidence")
        if not isinstance(evidence, Mapping):
            continue
        evidence_id = evidence.get("evidence_id")
        if isinstance(evidence_id, str):
            created[evidence_id] = evidence
    entry_ids = {entry.evidence_id for entry in entries}
    for entry in entries:
        created_record = created.get(entry.evidence_id)
        if created_record is None:
            detail = "audit chain has no EVIDENCE_CREATED record for this evidence"
            checks.append(
                _check(
                    f"audit-created:{entry.evidence_id}",
                    FAIL,
                    detail,
                    evidence_id=entry.evidence_id,
                    event_type=AUDIT_CHAIN_INVALID,
                )
            )
            issues.append(
                _issue(
                    AUDIT_CHAIN_INVALID,
                    FAIL,
                    detail,
                    evidence_id=entry.evidence_id,
                )
            )
            continue
        if (
            created_record.get("path") != entry.path
            or created_record.get("sha256") != entry.sha256
            or created_record.get("kind") != entry.kind
        ):
            detail = "audit creation record does not match the report evidence binding"
            checks.append(
                _check(
                    f"audit-created:{entry.evidence_id}",
                    FAIL,
                    detail,
                    evidence_id=entry.evidence_id,
                    expected=entry.sha256,
                    actual=str(created_record.get("sha256")),
                    event_type=MANIFEST_BINDING_MISMATCH,
                )
            )
            issues.append(
                _issue(
                    MANIFEST_BINDING_MISMATCH,
                    FAIL,
                    detail,
                    evidence_id=entry.evidence_id,
                    expected=entry.sha256,
                    actual=str(created_record.get("sha256")),
                )
            )
    for evidence_id in sorted(set(created) - entry_ids):
        detail = "audit chain contains evidence that the report does not reference"
        checks.append(
            _check(
                f"audit-extra:{evidence_id}",
                FAIL,
                detail,
                evidence_id=evidence_id,
                event_type=MANIFEST_BINDING_MISMATCH,
            )
        )
        issues.append(
            _issue(
                MANIFEST_BINDING_MISMATCH,
                FAIL,
                detail,
                evidence_id=evidence_id,
            )
        )
    if not issues:
        checks.append(
            _check(
                "audit-events",
                PASS,
                "audit chain creation records match the report evidence",
                event_type=EVIDENCE_VERIFIED,
            )
        )
    return checks, issues


def _verify_audit_for_entries(
    entries: Sequence[BoundEvidence],
    *,
    audit_path: Path,
    checkpoint_path: Path | None,
    checkpoint: Mapping[str, Any] | None = None,
) -> tuple[list[VerificationCheck], list[VerificationIssue], AuditVerification, list[dict[str, Any]]]:
    checks: list[VerificationCheck] = []
    issues: list[VerificationIssue] = []
    if not audit_path.is_file():
        detail = "audit chain is missing"
        checks.append(_check("audit-chain", UNAVAILABLE, detail, event_type=AUDIT_CHAIN_INVALID))
        issues.append(_issue(AUDIT_CHAIN_INVALID, UNAVAILABLE, detail))
        return (
            checks,
            issues,
            AuditVerification(
                outcome=UNAVAILABLE,
                record_count=0,
                head=None,
                anchored=False,
                checkpoint=None,
                problems=[AuditProblem(AUDIT_CHAIN_INVALID, detail)],
            ),
            [],
        )
    try:
        actual_audit_sha = sha256_file(audit_path)
    except OSError:
        actual_audit_sha = None
    selected_checkpoint = checkpoint
    if checkpoint_path is not None:
        try:
            selected_checkpoint = load_checkpoint(checkpoint_path)
        except (AuditChainError, IntegrityError):
            detail = "trusted checkpoint is missing or invalid"
            checks.append(_check("audit-checkpoint", FAIL, detail, event_type=AUDIT_CHAIN_INVALID))
            issues.append(_issue(AUDIT_CHAIN_INVALID, FAIL, detail))
            return (
                checks,
                issues,
                AuditVerification(
                    outcome=FAIL,
                    record_count=0,
                    head=None,
                    anchored=False,
                    checkpoint=None,
                    problems=[AuditProblem(AUDIT_CHAIN_INVALID, detail)],
                ),
                [],
            )
    verification = verify_audit_chain(audit_path, checkpoint=selected_checkpoint)
    checks.append(
        _check(
            "audit-chain",
            verification.outcome,
            f"audit chain verification: {verification.outcome}",
            expected=str(verification.record_count),
            actual=str(verification.record_count),
            event_type=AUDIT_CHAIN_INVALID,
        )
    )
    for problem in verification.problems:
        issues.append(
            _issue(
                AUDIT_CHAIN_INVALID,
                verification.outcome if verification.outcome != PASS else FAIL,
                problem.detail,
            )
        )
    if selected_checkpoint is not None:
        checks.append(
            _check(
                "audit-checkpoint",
                verification.outcome,
                "audit chain was checked against the trusted checkpoint"
                if verification.outcome == PASS
                else "audit chain does not match the trusted checkpoint",
                event_type=AUDIT_CHAIN_INVALID,
            )
        )
    else:
        checks.append(
            _check(
                "audit-checkpoint",
                NOT_RUN,
                "no trusted checkpoint was supplied; chain termination was not anchored",
                required=False,
            )
        )
    records: list[dict[str, Any]] = []
    if verification.outcome != UNAVAILABLE:
        try:
            records = read_audit_chain(audit_path)
        except AuditChainError:
            records = []
    incidents = _audit_incidents(records)
    if incidents:
        checks.append(
            _check(
                "audit-incidents",
                FAIL,
                "audit chain records one or more evidence-integrity incidents",
                event_type=AUDIT_CHAIN_INVALID,
            )
        )
        issues.extend(incidents)
    else:
        checks.append(
            _check(
                "audit-incidents",
                PASS,
                "audit chain records no evidence-integrity incidents",
                event_type=EVIDENCE_VERIFIED,
            )
        )
    if entries:
        event_checks, event_issues = _cross_check_created_events(entries, records)
        checks.extend(event_checks)
        issues.extend(event_issues)
    if actual_audit_sha is not None:
        verification_dict = verification.to_dict()
        verification_dict["sha256"] = actual_audit_sha
        verification_dict["incidents"] = [incident.to_dict() for incident in incidents]
        return checks, issues, verification, [verification_dict]
    return checks, issues, verification, [verification.to_dict()]


def verify_report(
    report_path: Path,
    *,
    manifest_path: Path | None = None,
    integrity_path: Path | None = None,
    evidence_root: Path | None = None,
    audit_path: Path | None = None,
    checkpoint_path: Path | None = None,
    expected_report_sha256: str | None = None,
    generated_at: str | None = None,
) -> VerificationResult:
    """Verify a report's evidence, optional integrity sidecar, and audit chain."""
    report_path = Path(report_path)
    result = VerificationResult(
        outcome=NOT_RUN,
        generated_at=normalize_timestamp(generated_at or utc_now_iso()),
    )
    report, error = _read_json_file(report_path, label="report")
    if report is None:
        detail = error or "report is invalid"
        result.checks.append(_check("report-exists", UNAVAILABLE, detail, event_type=EVIDENCE_MISSING))
        result.issues.append(_issue(EVIDENCE_MISSING, UNAVAILABLE, detail))
        result.outcome = aggregate_outcome(result.checks)
        return result
    result.checks.append(
        _check("report-exists", PASS, "report is readable JSON", event_type=EVIDENCE_VERIFIED)
    )
    try:
        report_sha = sha256_file(report_path)
    except OSError:
        detail = "report bytes could not be hashed"
        result.checks.append(_check("report-readable", UNAVAILABLE, detail, event_type=EVIDENCE_REJECTED))
        result.issues.append(_issue(EVIDENCE_REJECTED, UNAVAILABLE, detail))
        result.outcome = aggregate_outcome(result.checks)
        return result
    result.report = {
        "path": str(report_path),
        "sha256": report_sha,
        "schema_version": report.get("schema_version"),
        "profile": report.get("profile"),
    }
    if expected_report_sha256 is not None and report_sha != expected_report_sha256:
        detail = "report bytes changed after the expected digest was recorded"
        result.checks.append(
            _check(
                "report-sha256",
                FAIL,
                detail,
                expected=expected_report_sha256,
                actual=report_sha,
                event_type=EVIDENCE_MODIFIED,
            )
        )
        result.issues.append(
            _issue(
                EVIDENCE_MODIFIED,
                FAIL,
                detail,
                expected=expected_report_sha256,
                actual=report_sha,
            )
        )
    elif expected_report_sha256 is not None:
        result.checks.append(
            _check(
                "report-sha256",
                PASS,
                "report SHA-256 matches the expected digest",
                expected=expected_report_sha256,
                actual=report_sha,
                event_type=EVIDENCE_VERIFIED,
            )
        )
    else:
        result.checks.append(
            _check(
                "report-sha256",
                NOT_RUN,
                "no expected report digest was supplied",
                required=False,
            )
        )

    schema_version = report.get("schema_version")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int) or schema_version < 1:
        detail = "report schema_version is missing or invalid"
        result.checks.append(_check("report-schema", FAIL, detail, event_type=EVIDENCE_REJECTED))
        result.issues.append(_issue(EVIDENCE_REJECTED, FAIL, detail))
    else:
        result.checks.append(
            _check(
                "report-schema",
                PASS,
                f"report schema_version {schema_version} is compatible with V30 verification",
                event_type=EVIDENCE_VERIFIED,
            )
        )

    entries, conflicts = extract_bound_evidence(report)
    for conflict in conflicts:
        result.checks.append(
            _check(
                "report-evidence-conflict",
                FAIL,
                conflict,
                event_type=MANIFEST_BINDING_MISMATCH,
            )
        )
        result.issues.append(_issue(MANIFEST_BINDING_MISMATCH, FAIL, conflict))

    resolved_integrity = Path(integrity_path) if integrity_path is not None else None
    if resolved_integrity is None:
        candidate = default_integrity_path(report_path)
        if candidate.is_file():
            resolved_integrity = candidate
    if resolved_integrity is not None:
        result.checks.append(
            _check(
                "integrity-manifest",
                PASS,
                "integrity sidecar was supplied or discovered",
                expected=str(resolved_integrity),
                event_type=EVIDENCE_VERIFIED,
            )
        )
        try:
            integrity = load_integrity_manifest(resolved_integrity)
        except EvidenceVerificationError as exc:
            detail = str(exc)
            result.checks[-1] = _check(
                "integrity-manifest",
                FAIL,
                detail,
                expected=str(resolved_integrity),
                event_type=MANIFEST_BINDING_MISMATCH,
            )
            result.issues.append(_issue(MANIFEST_BINDING_MISMATCH, FAIL, detail))
            result.outcome = aggregate_outcome(result.checks)
            result.limitations.extend(DEFAULT_LIMITATIONS)
            return result
        result.integrity = integrity.payload
        if integrity.report["sha256"] != report_sha:
            detail = "integrity manifest is bound to different report bytes"
            result.checks.append(
                _check(
                    "integrity-report-binding",
                    FAIL,
                    detail,
                    expected=report_sha,
                    actual=str(integrity.report["sha256"]),
                    event_type=MANIFEST_BINDING_MISMATCH,
                )
            )
            result.issues.append(
                _issue(
                    MANIFEST_BINDING_MISMATCH,
                    FAIL,
                    detail,
                    expected=report_sha,
                    actual=str(integrity.report["sha256"]),
                )
            )
        elif integrity.report["schema_version"] != schema_version or integrity.report[
            "profile"
        ] != report.get("profile"):
            detail = "integrity manifest report schema or profile does not match the report"
            result.checks.append(
                _check(
                    "integrity-report-binding",
                    FAIL,
                    detail,
                    event_type=MANIFEST_BINDING_MISMATCH,
                )
            )
            result.issues.append(_issue(MANIFEST_BINDING_MISMATCH, FAIL, detail))
        elif Path(integrity.report["path"]).name != report_path.name:
            detail = "integrity manifest references a different report path"
            result.checks.append(
                _check(
                    "integrity-report-binding",
                    FAIL,
                    detail,
                    expected=report_path.name,
                    actual=Path(integrity.report["path"]).name,
                    event_type=MANIFEST_BINDING_MISMATCH,
                )
            )
            result.issues.append(
                _issue(
                    MANIFEST_BINDING_MISMATCH,
                    FAIL,
                    detail,
                    expected=report_path.name,
                    actual=Path(integrity.report["path"]).name,
                )
            )
        elif integrity.parent_id != f"report:{report_sha}":
            detail = "integrity manifest parent identifier does not match the report bytes"
            result.checks.append(
                _check(
                    "integrity-report-binding",
                    FAIL,
                    detail,
                    expected=f"report:{report_sha}",
                    actual=integrity.parent_id,
                    event_type=MANIFEST_BINDING_MISMATCH,
                )
            )
            result.issues.append(
                _issue(
                    MANIFEST_BINDING_MISMATCH,
                    FAIL,
                    detail,
                    expected=f"report:{report_sha}",
                    actual=integrity.parent_id,
                )
            )
        else:
            result.checks.append(
                _check(
                    "integrity-report-binding",
                    PASS,
                    "integrity manifest is bound to the exact report bytes",
                    expected=report_sha,
                    actual=str(integrity.report["sha256"]),
                    event_type=EVIDENCE_VERIFIED,
                )
            )
            base = resolved_integrity.parent
            recorded_root = (
                Path(evidence_root)
                if evidence_root is not None
                else _resolve_manifest_path(base, integrity.evidence_root, label="evidence root")
            )
            if evidence_root is not None:
                result.limitations.append(
                    "The command-line evidence root overrides the root recorded in the integrity manifest."
                )
            manifest_entries = [
                BoundEvidence(
                    evidence_id=record.evidence_id,
                    kind=record.kind,
                    path=record.path,
                    sha256=record.sha256,
                    size=record.size,
                    state=PASS,
                    source="integrity-manifest",
                )
                for record in integrity.evidence
            ]
            evidence_checks, evidence_issues, evidence_summaries = verify_evidence_set(
                manifest_entries,
                evidence_root=recorded_root,
                authorized_reuse=[item["sha256"] for item in integrity.authorized_reuse],
            )
            result.checks.extend(evidence_checks)
            result.issues.extend(evidence_issues)
            result.evidence = evidence_summaries
            audit_target = (
                Path(audit_path)
                if audit_path is not None
                else _resolve_manifest_path(base, integrity.audit["path"], label="audit chain")
            )
            audit_checks, audit_issues, audit_verification, audit_payload = _verify_audit_for_entries(
                manifest_entries,
                audit_path=audit_target,
                checkpoint_path=checkpoint_path,
                checkpoint=integrity.audit["checkpoint"],
            )
            result.checks.extend(audit_checks)
            result.issues.extend(audit_issues)
            result.audit = audit_payload[0] if audit_payload else audit_verification.to_dict()
            if audit_verification.outcome == PASS:
                try:
                    actual_audit_sha = sha256_file(audit_target)
                except OSError:
                    actual_audit_sha = None
                if actual_audit_sha != integrity.audit["sha256"]:
                    detail = "audit chain bytes do not match the integrity manifest"
                    result.checks.append(
                        _check(
                            "integrity-audit-binding",
                            FAIL,
                            detail,
                            expected=str(integrity.audit["sha256"]),
                            actual=actual_audit_sha,
                            event_type=AUDIT_CHAIN_INVALID,
                        )
                    )
                    result.issues.append(
                        _issue(
                            AUDIT_CHAIN_INVALID,
                            FAIL,
                            detail,
                            expected=str(integrity.audit["sha256"]),
                            actual=actual_audit_sha,
                        )
                    )
                elif audit_verification.record_count != integrity.audit["record_count"]:
                    detail = "audit chain record count does not match the integrity manifest"
                    result.checks.append(
                        _check(
                            "integrity-audit-binding",
                            FAIL,
                            detail,
                            expected=str(integrity.audit["record_count"]),
                            actual=str(audit_verification.record_count),
                            event_type=AUDIT_CHAIN_INVALID,
                        )
                    )
                    result.issues.append(
                        _issue(
                            AUDIT_CHAIN_INVALID,
                            FAIL,
                            detail,
                            expected=str(integrity.audit["record_count"]),
                            actual=str(audit_verification.record_count),
                        )
                    )
                elif audit_verification.head != integrity.audit["head"]:
                    detail = "audit chain head does not match the integrity manifest"
                    result.checks.append(
                        _check(
                            "integrity-audit-binding",
                            FAIL,
                            detail,
                            expected=str(integrity.audit["head"]),
                            actual=audit_verification.head,
                            event_type=AUDIT_CHAIN_INVALID,
                        )
                    )
                    result.issues.append(
                        _issue(
                            AUDIT_CHAIN_INVALID,
                            FAIL,
                            detail,
                            expected=str(integrity.audit["head"]),
                            actual=audit_verification.head,
                        )
                    )
                else:
                    result.checks.append(
                        _check(
                            "integrity-audit-binding",
                            PASS,
                            "audit chain bytes, record count, and head match the integrity manifest",
                            event_type=EVIDENCE_VERIFIED,
                        )
                    )
            # Cross-check the report's own bindings against the sidecar.
            report_entries, _ = extract_bound_evidence(report)
            report_by_key = {(entry.path, entry.sha256): entry for entry in report_entries}
            manifest_by_key = {(entry.path, entry.sha256): entry for entry in manifest_entries}
            for key, entry in report_by_key.items():
                if key not in manifest_by_key:
                    detail = "report evidence is not present in the integrity manifest"
                    result.checks.append(
                        _check(
                            f"integrity-report-evidence:{entry.evidence_id}",
                            FAIL,
                            detail,
                            evidence_id=entry.evidence_id,
                            expected=entry.sha256,
                            event_type=MANIFEST_BINDING_MISMATCH,
                        )
                    )
                    result.issues.append(
                        _issue(
                            MANIFEST_BINDING_MISMATCH,
                            FAIL,
                            detail,
                            evidence_id=entry.evidence_id,
                            expected=entry.sha256,
                        )
                    )
            for key, entry in manifest_by_key.items():
                if key not in report_by_key:
                    detail = "integrity manifest evidence is not referenced by the report"
                    result.checks.append(
                        _check(
                            f"integrity-manifest-evidence:{entry.evidence_id}",
                            FAIL,
                            detail,
                            evidence_id=entry.evidence_id,
                            expected=entry.sha256,
                            event_type=MANIFEST_BINDING_MISMATCH,
                        )
                    )
                    result.issues.append(
                        _issue(
                            MANIFEST_BINDING_MISMATCH,
                            FAIL,
                            detail,
                            evidence_id=entry.evidence_id,
                            expected=entry.sha256,
                        )
                    )
            if not any(issue.event_type == MANIFEST_BINDING_MISMATCH for issue in result.issues):
                result.checks.append(
                    _check(
                        "integrity-report-evidence",
                        PASS,
                        "report evidence and integrity manifest reference the same bytes",
                        event_type=EVIDENCE_VERIFIED,
                    )
                )
    else:
        result.checks.append(
            _check(
                "integrity-manifest",
                NOT_RUN,
                "no integrity sidecar was supplied or discovered",
                required=False,
            )
        )
        root = (
            Path(evidence_root) if evidence_root is not None else _default_evidence_root(report_path, report)
        )
        evidence_checks, evidence_issues, evidence_summaries = verify_evidence_set(
            entries,
            evidence_root=root,
        )
        result.checks.extend(evidence_checks)
        result.issues.extend(evidence_issues)
        result.evidence = evidence_summaries
        if audit_path is not None:
            audit_checks, audit_issues, audit_verification, audit_payload = _verify_audit_for_entries(
                entries,
                audit_path=Path(audit_path),
                checkpoint_path=checkpoint_path,
            )
            result.checks.extend(audit_checks)
            result.issues.extend(audit_issues)
            result.audit = audit_payload[0] if audit_payload else audit_verification.to_dict()

    manifest_checks, manifest_issues, manifest_details = verify_manifest_binding(
        report,
        manifest_path=manifest_path,
        entries=entries,
    )
    result.checks.extend(manifest_checks)
    result.issues.extend(manifest_issues)
    result.manifest = manifest_details
    result.outcome = aggregate_outcome(result.checks)
    return result


def verify_audit_file(
    audit_path: Path,
    *,
    checkpoint_path: Path | None = None,
    generated_at: str | None = None,
) -> VerificationResult:
    """Verify only an audit chain and an optional trusted checkpoint."""
    result = VerificationResult(
        outcome=NOT_RUN,
        generated_at=normalize_timestamp(generated_at or utc_now_iso()),
    )
    audit_path = Path(audit_path)
    if not audit_path.is_file():
        detail = "audit chain is missing"
        result.checks.append(_check("audit-chain", UNAVAILABLE, detail, event_type=AUDIT_CHAIN_INVALID))
        result.issues.append(_issue(AUDIT_CHAIN_INVALID, UNAVAILABLE, detail))
        result.outcome = aggregate_outcome(result.checks)
        return result
    checkpoint: dict[str, Any] | None = None
    if checkpoint_path is not None:
        try:
            checkpoint = load_checkpoint(checkpoint_path)
        except (AuditChainError, IntegrityError):
            detail = "trusted checkpoint is missing or invalid"
            result.checks.append(_check("audit-checkpoint", FAIL, detail, event_type=AUDIT_CHAIN_INVALID))
            result.issues.append(_issue(AUDIT_CHAIN_INVALID, FAIL, detail))
            result.outcome = aggregate_outcome(result.checks)
            return result
    verification = verify_audit_chain(audit_path, checkpoint=checkpoint)
    result.checks.append(
        _check(
            "audit-chain",
            verification.outcome,
            f"audit chain verification: {verification.outcome}",
            event_type=AUDIT_CHAIN_INVALID,
        )
    )
    for problem in verification.problems:
        result.issues.append(
            _issue(
                AUDIT_CHAIN_INVALID,
                verification.outcome if verification.outcome != PASS else FAIL,
                problem.detail,
            )
        )
    if checkpoint is not None:
        result.checks.append(
            _check(
                "audit-checkpoint",
                verification.outcome,
                "audit chain matches the trusted checkpoint"
                if verification.outcome == PASS
                else "audit chain does not match the trusted checkpoint",
                event_type=AUDIT_CHAIN_INVALID,
            )
        )
    else:
        result.checks.append(
            _check(
                "audit-checkpoint",
                NOT_RUN,
                "no trusted checkpoint was supplied; chain termination was not anchored",
                required=False,
            )
        )
    try:
        records = read_audit_chain(audit_path)
    except AuditChainError:
        records = []
    incidents = _audit_incidents(records)
    if incidents:
        result.checks.append(
            _check(
                "audit-incidents",
                FAIL,
                "audit chain records one or more evidence-integrity incidents",
                event_type=AUDIT_CHAIN_INVALID,
            )
        )
        result.issues.extend(incidents)
    else:
        result.checks.append(
            _check(
                "audit-incidents",
                PASS,
                "audit chain records no evidence-integrity incidents",
                event_type=EVIDENCE_VERIFIED,
            )
        )
    payload = verification.to_dict()
    payload["incidents"] = [incident.to_dict() for incident in incidents]
    try:
        payload["sha256"] = sha256_file(audit_path)
    except OSError:
        payload["sha256"] = None
    result.audit = payload
    result.outcome = aggregate_outcome(result.checks)
    return result


def verify_individual_evidence(
    evidence_path: Path,
    *,
    expected_sha256: str,
    expected_size: int | None = None,
    evidence_id: str | None = None,
    evidence_root: Path | None = None,
    generated_at: str | None = None,
) -> VerificationResult:
    """Verify one evidence file against an expected digest."""
    result = VerificationResult(
        outcome=NOT_RUN,
        generated_at=normalize_timestamp(generated_at or utc_now_iso()),
    )
    identifier = evidence_id or Path(evidence_path).name
    if evidence_root is not None:
        root = Path(evidence_root)
        try:
            relative = _relative_inside(root, Path(evidence_path), label="evidence")
        except EvidenceVerificationError as exc:
            detail = str(exc)
            result.checks.append(
                _check(
                    f"evidence:{identifier}",
                    FAIL,
                    detail,
                    event_type=EVIDENCE_PATH_INVALID,
                )
            )
            result.issues.append(
                _issue(
                    EVIDENCE_PATH_INVALID,
                    FAIL,
                    detail,
                    evidence_id=identifier,
                )
            )
            result.outcome = aggregate_outcome(result.checks)
            return result
        bound = BoundEvidence(
            evidence_id=identifier,
            kind="individual",
            path=relative,
            sha256=expected_sha256,
            size=expected_size,
            state=PASS,
            source="command-line",
        )
        checks, issues, summaries = verify_evidence_set([bound], evidence_root=evidence_root)
        result.checks.extend(checks)
        result.issues.extend(issues)
        result.evidence = summaries
        result.outcome = aggregate_outcome(result.checks)
        return result
    path = Path(evidence_path)
    if not path.is_file():
        detail = "evidence file is missing"
        result.checks.append(_check(f"evidence:{identifier}", FAIL, detail, event_type=EVIDENCE_MISSING))
        result.issues.append(_issue(EVIDENCE_MISSING, FAIL, detail, evidence_id=identifier))
        result.outcome = aggregate_outcome(result.checks)
        return result
    try:
        digest = hash_evidence_file(path)
    except (EvidenceChangedDuringVerification, EvidencePathError, OSError):
        detail = "evidence file could not be hashed reliably"
        result.checks.append(
            _check(f"evidence:{identifier}", UNAVAILABLE, detail, event_type=EVIDENCE_REJECTED)
        )
        result.issues.append(_issue(EVIDENCE_REJECTED, UNAVAILABLE, detail, evidence_id=identifier))
        result.outcome = aggregate_outcome(result.checks)
        return result
    summary = {
        "evidence_id": identifier,
        "kind": "individual",
        "path": path.name,
        "expected_sha256": expected_sha256,
        "actual_sha256": digest.sha256,
        "expected_size": expected_size,
        "actual_size": digest.size,
        "outcome": NOT_RUN,
        "aliases": [],
    }
    if digest.sha256 != expected_sha256:
        event_type = (
            EVIDENCE_REPLACED if expected_size is None or digest.size == expected_size else EVIDENCE_MODIFIED
        )
        detail = "evidence digest does not match the expected digest"
        result.checks.append(
            _check(
                f"evidence:{identifier}",
                FAIL,
                detail,
                expected=expected_sha256,
                actual=digest.sha256,
                event_type=event_type,
            )
        )
        result.issues.append(
            _issue(
                event_type,
                FAIL,
                detail,
                evidence_id=identifier,
                expected=expected_sha256,
                actual=digest.sha256,
            )
        )
        summary["outcome"] = FAIL
    elif expected_size is not None and digest.size != expected_size:
        detail = "evidence size does not match the expected size"
        result.checks.append(
            _check(
                f"evidence:{identifier}",
                FAIL,
                detail,
                expected=str(expected_size),
                actual=str(digest.size),
                event_type=EVIDENCE_MODIFIED,
            )
        )
        result.issues.append(
            _issue(
                EVIDENCE_MODIFIED,
                FAIL,
                detail,
                evidence_id=identifier,
                expected=str(expected_size),
                actual=str(digest.size),
            )
        )
        summary["outcome"] = FAIL
    else:
        result.checks.append(
            _check(
                f"evidence:{identifier}",
                PASS,
                "evidence exists and its SHA-256 matches the expected digest",
                expected=expected_sha256,
                actual=digest.sha256,
                event_type=EVIDENCE_VERIFIED,
            )
        )
        summary["outcome"] = PASS
    result.evidence = [summary]
    result.outcome = aggregate_outcome(result.checks)
    return result


def _relative_inside(base: Path, target: Path, *, label: str) -> str:
    try:
        relative = os.path.relpath(target.resolve(), base.resolve())
    except OSError as exc:
        raise EvidenceVerificationError(f"{label} could not be resolved") from exc
    normalized = relative.replace("\\", "/")
    if normalized == ".":
        return "."
    try:
        return validate_relative_directory(normalized)
    except EvidencePathError as exc:
        raise EvidenceVerificationError(f"{label} must be inside the integrity-manifest directory") from exc


def seal_report_evidence(
    report_path: Path,
    *,
    integrity_path: Path | None = None,
    audit_path: Path | None = None,
    evidence_root: Path | None = None,
    checkpoint_path: Path | None = None,
    authorized_reuse: Sequence[str] = (),
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Create a new integrity sidecar and audit chain for a report.

    This is an explicit sealing operation. It never modifies the report or any
    evidence file. It refuses to overwrite an existing sidecar or audit chain.
    """
    report_path = Path(report_path)
    report, error = _read_json_file(report_path, label="report")
    if report is None:
        raise EvidenceVerificationError(error or "report is invalid")
    report_sha = sha256_file(report_path)
    report_id = f"report:{report_sha}"
    schema_version = report.get("schema_version")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int) or schema_version < 1:
        raise EvidenceVerificationError("report schema_version is missing or invalid")
    profile = report.get("profile")
    if not isinstance(profile, str) or not profile:
        raise EvidenceVerificationError("report profile is missing or invalid")
    entries, conflicts = extract_bound_evidence(report)
    if conflicts:
        raise EvidenceVerificationError("; ".join(conflicts))
    if not entries:
        raise EvidenceVerificationError("report has no supported evidence bindings")
    root = Path(evidence_root) if evidence_root is not None else _default_evidence_root(report_path, report)
    if not root.is_dir():
        raise EvidenceVerificationError("evidence root is missing or not a directory")

    created_at = normalize_timestamp(timestamp or utc_now_iso())
    records: list[EvidenceRecord] = []
    seen_ids: set[str] = set()
    content_paths: dict[str, set[str]] = {}
    for entry in entries:
        if entry.state is not None and entry.state != PASS:
            raise EvidenceVerificationError(f"evidence {entry.evidence_id!r} is not in a PASS binding state")
        if is_redacted_diagnostic_path(entry.path):
            raise EvidenceVerificationError(
                f"evidence {entry.evidence_id!r} points at a redacted diagnostic copy"
            )
        try:
            record = evidence_record_for_file(
                evidence_id=entry.evidence_id,
                kind=entry.kind,
                root=root,
                relative_path=entry.path,
                parent_id=report_id,
                created_at=created_at,
            )
        except (EvidencePathError, EvidenceChangedDuringVerification) as exc:
            raise EvidenceVerificationError(
                f"evidence {entry.evidence_id!r} could not be sealed: {exc}"
            ) from exc
        if record.evidence_id in seen_ids:
            raise EvidenceVerificationError(f"evidence identifier {record.evidence_id!r} is duplicated")
        seen_ids.add(record.evidence_id)
        if record.sha256 != entry.sha256:
            raise EvidenceVerificationError(
                f"evidence {entry.evidence_id!r} does not match its report digest"
            )
        if entry.size is not None and record.size != entry.size:
            raise EvidenceVerificationError(f"evidence {entry.evidence_id!r} does not match its report size")
        content_paths.setdefault(record.sha256, set()).add(record.path)
        records.append(record)

    allowed_reuse = {digest for digest in authorized_reuse if _valid_digest(digest)}
    for digest, paths in sorted(content_paths.items()):
        if len(paths) > 1 and digest not in allowed_reuse:
            raise EvidenceVerificationError(
                "evidence content is reused under more than one identifier; "
                "pass --authorized-reuse <sha256> to acknowledge it"
            )

    integrity_path = (
        Path(integrity_path) if integrity_path is not None else default_integrity_path(report_path)
    )
    audit_path = Path(audit_path) if audit_path is not None else default_audit_path(report_path)
    if integrity_path.exists():
        raise EvidenceVerificationError("refusing to overwrite an existing integrity manifest")
    if audit_path.exists():
        raise EvidenceVerificationError("refusing to overwrite an existing audit chain")

    events = [
        {
            "event_type": EVIDENCE_CREATED,
            "timestamp": created_at,
            "outcome": PASS,
            "evidence": record,
            "details": {
                "message": "evidence was retained and bound to the report",
                "source": entry.source,
                "aliases": list(entry.aliases),
            },
        }
        for record, entry in zip(records, entries, strict=True)
    ]
    audit_records = build_audit_chain(events)
    audit_bytes = render_audit_chain(audit_records)
    checkpoint: dict[str, Any] | None = None
    if checkpoint_path is not None:
        checkpoint = load_checkpoint(checkpoint_path)
        verification = verify_audit_chain(audit_records, checkpoint=checkpoint)
        if verification.outcome != PASS:
            raise EvidenceVerificationError("new audit chain does not match the supplied checkpoint")

    integrity_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_root_relative = _relative_inside(integrity_path.parent, root, label="evidence root")
    report_relative = _relative_inside(integrity_path.parent, report_path, label="report")
    audit_relative = _relative_inside(integrity_path.parent, audit_path, label="audit chain")
    manifest = {
        "schema_version": INTEGRITY_SCHEMA_VERSION,
        "profile": INTEGRITY_PROFILE,
        "generated_at": created_at,
        "report": {
            "path": report_relative,
            "sha256": report_sha,
            "schema_version": schema_version,
            "profile": profile,
        },
        "parent_id": report_id,
        "evidence_root": evidence_root_relative,
        "evidence": [record.to_dict() for record in records],
        "audit": {
            "path": audit_relative,
            "sha256": sha256_bytes(audit_bytes),
            "record_count": len(audit_records),
            "head": audit_records[-1]["record_hash"],
            "checkpoint": checkpoint,
        },
        "authorized_reuse": [
            {
                "sha256": digest,
                "reason": "explicitly authorized by the operator",
            }
            for digest in sorted(allowed_reuse)
        ],
        "limitations": list(DEFAULT_LIMITATIONS),
    }
    if redact_structure(manifest) != manifest:
        raise EvidenceVerificationError(
            "integrity manifest contains credential-like material that cannot be persisted"
        )
    try:
        write_audit_chain(audit_path, audit_records)
    except AuditChainError as exc:
        raise EvidenceVerificationError(str(exc)) from exc
    try:
        write_integrity_manifest(integrity_path, manifest)
    except OSError as exc:
        raise EvidenceVerificationError("integrity manifest could not be written") from exc
    return {
        "report": str(report_path),
        "report_sha256": report_sha,
        "integrity_path": str(integrity_path),
        "audit_path": str(audit_path),
        "audit": manifest["audit"],
        "evidence_count": len(records),
        "manifest": manifest,
    }


def write_integrity_manifest(
    path: Path,
    manifest: Mapping[str, Any],
    *,
    overwrite: bool = False,
) -> None:
    """Write a sanitized integrity manifest, refusing overwrite by default."""
    path = Path(path)
    if path.exists() and not overwrite:
        raise EvidenceVerificationError("refusing to overwrite an existing integrity manifest")
    cleaned = redact_structure(manifest)
    if cleaned != manifest:
        raise EvidenceVerificationError(
            "integrity manifest contains credential-like material that cannot be persisted"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(dump_sanitized_json(manifest), encoding="utf-8", newline="\n")
    except OSError as exc:
        raise EvidenceVerificationError("integrity manifest could not be written") from exc


def checkpoint_audit_chain(
    audit_path: Path,
    output_path: Path,
    *,
    source_label: str | None = None,
) -> dict[str, Any]:
    """Create a checkpoint file from a valid audit chain."""
    checkpoint = create_checkpoint(Path(audit_path), source_label=source_label)
    try:
        write_checkpoint(Path(output_path), checkpoint)
    except AuditChainError as exc:
        raise EvidenceVerificationError(str(exc)) from exc
    return checkpoint


def render_verification_summary(result: VerificationResult) -> str:
    """Render a human-readable, credential-safe verification summary."""
    payload = result.to_dict()
    lines = [f"Evidence verification: {payload['outcome']}"]
    if payload.get("report"):
        lines.append(f"Report: {payload['report'].get('path')} ({payload['report'].get('sha256')})")
    if payload.get("manifest"):
        lines.append(f"Release manifest: {payload['manifest'].get('sha256')}")
    if payload.get("audit"):
        audit = payload["audit"]
        lines.append(
            f"Audit chain: {audit.get('record_count')} records, head {audit.get('head')}, "
            f"anchored={audit.get('anchored')}"
        )
    lines.append("Checks:")
    for check in payload["checks"]:
        lines.append(f"- {check['name']}: {check['outcome']} - {check['detail']}")
    if payload["issues"]:
        lines.append("Issues:")
        for issue in payload["issues"]:
            lines.append(f"- {issue['event_type']}: {issue['detail']}")
    if payload["limitations"]:
        lines.append("Limitations:")
        for limitation in payload["limitations"]:
            lines.append(f"- {limitation}")
    lines.append(payload["mutation"]["statement"])
    lines.append(f"Trust boundary: {payload['trust_boundary']}")
    return "\n".join(lines) + "\n"


def render_verification_json(result: VerificationResult) -> str:
    """Render a sanitized machine-readable verification result."""
    return dump_sanitized_json(result.to_dict())


# Re-exported for callers that build audit records while verifying.
__all__ = [
    "AUDIT_EVENT_TYPES",
    "AUDIT_PROFILE",
    "AUDIT_SCHEMA_VERSION",
    "DEFAULT_LIMITATIONS",
    "EVIDENCE_CREATED",
    "EVIDENCE_MISSING",
    "EVIDENCE_MODIFIED",
    "EVIDENCE_PATH_INVALID",
    "EVIDENCE_REJECTED",
    "EVIDENCE_REPLACED",
    "EVIDENCE_VERIFIED",
    "GENESIS_PREVIOUS_HASH",
    "INTEGRITY_PROFILE",
    "INTEGRITY_SCHEMA_VERSION",
    "MANIFEST_BINDING_MISMATCH",
    "MUTATION_STATEMENT",
    "TRUST_BOUNDARY",
    "BoundEvidence",
    "EvidenceVerificationError",
    "IntegrityManifest",
    "VerificationCheck",
    "VerificationIssue",
    "VerificationResult",
    "aggregate_outcome",
    "append_audit_event",
    "build_audit_chain",
    "checkpoint_audit_chain",
    "default_audit_path",
    "default_integrity_path",
    "extract_bound_evidence",
    "load_integrity_manifest",
    "render_verification_json",
    "render_verification_summary",
    "seal_report_evidence",
    "verification_exit_code",
    "verify_audit_file",
    "verify_evidence_set",
    "verify_individual_evidence",
    "verify_manifest_binding",
    "verify_report",
    "write_integrity_manifest",
]
