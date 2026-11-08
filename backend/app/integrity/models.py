"""Immutable V33 audit records and API-safe serialization."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from backend.app.core.redaction import redact_structure, redact_text
from backend.app.integrity.constants import (
    AnchorStatus,
    AssuranceLevel,
    AuditStatus,
    AuditTrigger,
    IntegrityScope,
    ScopeStatus,
    Severity,
    recommended_action_for_reason,
    severity_for_reason,
    verification_source_for_reason,
)


def utc_now_iso() -> str:
    """UTC timestamp with millisecond precision and a trailing ``Z``."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def safe_artifact_id(path: Path | str | None, *, roots: tuple[Path, ...] = ()) -> str | None:
    """Return a safe relative artifact identifier, never an absolute path.

    Paths below a configured root become POSIX-style relative identifiers.
    Paths outside every root are reduced to a basename so diagnostics never
    disclose host directory structure.
    """
    if path is None:
        return None
    candidate = Path(path)
    for root in roots:
        try:
            relative = candidate.resolve().relative_to(root.resolve())
        except (OSError, ValueError):
            continue
        return relative.as_posix()
    name = candidate.name
    return name or None


def finding_id_for(
    audit_run_id: str,
    scope: IntegrityScope,
    reason_code: str,
    artifact_id: str | None,
    verification_source: str,
) -> str:
    payload = "|".join(
        [
            str(audit_run_id),
            scope.value,
            str(reason_code),
            str(artifact_id or ""),
            str(verification_source),
        ]
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
    return f"finding-{digest}"


@dataclass(frozen=True)
class Finding:
    """One sanitized, idempotent audit finding."""

    finding_id: str
    audit_run_id: str
    scope: IntegrityScope
    severity: Severity
    reason_code: str
    artifact_id: str | None
    detected_at: str
    explanation: str
    verification_source: str
    recommended_action: str

    @classmethod
    def create(
        cls,
        *,
        audit_run_id: str,
        scope: IntegrityScope,
        reason_code: str,
        artifact_id: str | None = None,
        explanation: str = "",
        verification_source: str | None = None,
        severity: Severity | None = None,
        detected_at: str | None = None,
    ) -> Finding:
        source = verification_source or verification_source_for_reason(reason_code)
        return cls(
            finding_id=finding_id_for(audit_run_id, scope, reason_code, artifact_id, source),
            audit_run_id=str(audit_run_id),
            scope=scope,
            severity=severity or severity_for_reason(reason_code),
            reason_code=str(reason_code),
            artifact_id=str(artifact_id) if artifact_id else None,
            detected_at=detected_at or utc_now_iso(),
            explanation=redact_text(str(explanation or ""))[:2000],
            verification_source=redact_text(str(source))[:256],
            recommended_action=redact_text(recommended_action_for_reason(reason_code))[:1000],
        )

    def to_dict(self) -> dict[str, Any]:
        return redact_structure(
            {
                "finding_id": self.finding_id,
                "audit_run_id": self.audit_run_id,
                "scope": self.scope.value,
                "severity": self.severity.value,
                "reason_code": self.reason_code,
                "artifact_id": self.artifact_id,
                "detected_at": self.detected_at,
                "explanation": self.explanation,
                "verification_source": self.verification_source,
                "recommended_action": self.recommended_action,
            }
        )


@dataclass
class ScopeResult:
    """Per-scope execution result (one row per run/scope)."""

    audit_run_id: str
    scope: IntegrityScope
    status: ScopeStatus
    started_at: str
    completed_at: str
    duration_ms: int
    artifacts_checked: int = 0
    checks_total: int = 0
    checks_failed: int = 0
    findings_count: int = 0
    reason_codes: list[str] = field(default_factory=list)
    error_summary: str | None = None
    truncated: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_structure(
            {
                "audit_run_id": self.audit_run_id,
                "scope": self.scope.value,
                "status": self.status.value,
                "started_at": self.started_at,
                "completed_at": self.completed_at,
                "duration_ms": self.duration_ms,
                "artifacts_checked": self.artifacts_checked,
                "checks_total": self.checks_total,
                "checks_failed": self.checks_failed,
                "findings_count": self.findings_count,
                "reason_codes": list(self.reason_codes),
                "error_summary": self.error_summary,
                "truncated": self.truncated,
                "details": dict(self.details),
            }
        )


@dataclass
class AuditRun:
    """Durable audit-run summary."""

    audit_run_id: str
    trigger: AuditTrigger
    requested_scopes: list[IntegrityScope]
    completed_scopes: list[IntegrityScope]
    status: AuditStatus
    started_at: str
    created_at: str
    completed_at: str | None = None
    duration_ms: int = 0
    cancelled: bool = False
    timed_out: bool = False
    retry_count: int = 0
    artifacts_checked: int = 0
    finding_counts: dict[str, int] = field(default_factory=dict)
    reason_code_counts: dict[str, int] = field(default_factory=dict)
    error_summary: str | None = None
    external_anchor_configured: bool = False
    assurance: AssuranceLevel = AssuranceLevel.NONE
    requested_by: str | None = None
    schedule_slot: str | None = None

    def to_dict(self, *, include_details: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "audit_run_id": self.audit_run_id,
            "trigger": self.trigger.value,
            "requested_scopes": [scope.value for scope in self.requested_scopes],
            "completed_scopes": [scope.value for scope in self.completed_scopes],
            "status": self.status.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "cancelled": self.cancelled,
            "timed_out": self.timed_out,
            "retry_count": self.retry_count,
            "artifacts_checked": self.artifacts_checked,
            "finding_counts": dict(self.finding_counts),
            "reason_code_counts": dict(self.reason_code_counts),
            "error_summary": self.error_summary,
            "external_anchor_configured": self.external_anchor_configured,
            "assurance": self.assurance.value,
            "requested_by": self.requested_by,
            "created_at": self.created_at,
        }
        if include_details:
            payload["schedule_slot"] = self.schedule_slot
        return redact_structure(payload)


@dataclass
class TrustOverview:
    """Trust-material summary that never claims external anchoring."""

    trusted_key_count: int = 0
    active_key_count: int = 0
    expired_key_count: int = 0
    revoked_key_count: int = 0
    unknown_key_count: int = 0
    evidence_trust_state: str = "NOT_CONFIGURED"
    transparency_trust_state: str = "NOT_CONFIGURED"
    latest_tree_head_size: int | None = None
    latest_tree_head_digest: str | None = None
    latest_tree_head_id: str | None = None
    external_anchor_status: AnchorStatus = AnchorStatus.NOT_CONFIGURED
    external_anchor_detail: str = "no external transparency provider is configured"
    assurance: AssuranceLevel = AssuranceLevel.NONE
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return redact_structure(
            {
                "trusted_key_count": self.trusted_key_count,
                "active_key_count": self.active_key_count,
                "expired_key_count": self.expired_key_count,
                "revoked_key_count": self.revoked_key_count,
                "unknown_key_count": self.unknown_key_count,
                "evidence_trust_state": self.evidence_trust_state,
                "transparency_trust_state": self.transparency_trust_state,
                "latest_tree_head_size": self.latest_tree_head_size,
                "latest_tree_head_digest": self.latest_tree_head_digest,
                "latest_tree_head_id": self.latest_tree_head_id,
                "external_anchor_status": self.external_anchor_status.value,
                "external_anchor_detail": self.external_anchor_detail,
                "assurance": self.assurance.value,
                "limitations": list(self.limitations),
            }
        )


@dataclass
class IntegrityStatus:
    """Dashboard overview payload."""

    enabled: bool
    store_status: str
    latest_audit: dict[str, Any] | None
    last_success: dict[str, Any] | None
    last_failure: dict[str, Any] | None
    running_audits: int
    total_audits: int
    total_audited_artifacts: int
    verified_evidence_count: int
    verified_checkpoint_count: int
    verified_tree_head_count: int
    open_findings: int
    findings_by_severity: dict[str, int]
    trust: TrustOverview
    scheduler: dict[str, Any]
    external_anchor_configured: bool
    assurance: AssuranceLevel
    generated_at: str = field(default_factory=utc_now_iso)
    store_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return redact_structure(
            {
                "enabled": self.enabled,
                "store_status": self.store_status,
                "store_error": self.store_error,
                "latest_audit": self.latest_audit,
                "last_success": self.last_success,
                "last_failure": self.last_failure,
                "running_audits": self.running_audits,
                "total_audits": self.total_audits,
                "total_audited_artifacts": self.total_audited_artifacts,
                "verified_evidence_count": self.verified_evidence_count,
                "verified_checkpoint_count": self.verified_checkpoint_count,
                "verified_tree_head_count": self.verified_tree_head_count,
                "open_findings": self.open_findings,
                "findings_by_severity": dict(self.findings_by_severity),
                "trust": self.trust.to_dict(),
                "scheduler": dict(self.scheduler),
                "external_anchor_configured": self.external_anchor_configured,
                "assurance": self.assurance.value,
                "generated_at": self.generated_at,
            }
        )


def empty_finding_counts() -> dict[str, int]:
    return {severity.value: 0 for severity in Severity}


def count_findings(findings: list[Finding]) -> tuple[dict[str, int], dict[str, int]]:
    counts = empty_finding_counts()
    reasons: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        reasons[finding.reason_code] = reasons.get(finding.reason_code, 0) + 1
    return counts, reasons
