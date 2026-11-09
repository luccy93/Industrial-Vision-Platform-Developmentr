"""Append-only governance audit event builder (V35).

Every event carries a self-digest over its own sanitized fields. The digest is
tamper-evident only relative to that single row: it is **not** a hash chain, not
an externally anchored log, and not immutable storage. Database triggers block
updates and deletes for the audit table, but an operator with database access
could still rewrite history outside the application.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from backend.app.core.redaction import redact_structure, redact_text
from backend.app.domain.common import utcnow
from backend.app.forensics.custody import canonical_json_bytes, sha256_hex
from backend.app.governance.constants import GovernanceAuditOutcome

AUDIT_ASSURANCE = "LOCAL_SELF_DIGEST_ONLY"
AUDIT_NON_CLAIMS: tuple[str, ...] = (
    "The governance audit is a local append-only database record.",
    "The per-event digest is not a hash chain and is not externally anchored.",
    "Database-level immutability is not claimed outside the configured database.",
)

_HASH_FIELDS: tuple[str, ...] = (
    "event_type",
    "actor_id",
    "actor_role",
    "target_type",
    "target_id",
    "case_id",
    "outcome",
    "reason",
    "request_id",
    "occurred_at",
    "event_key",
    "metadata",
)


def _as_utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)


def compute_event_hash(event: Mapping[str, Any]) -> str:
    """Recompute the self-digest for an audit event payload."""
    payload = {field: event.get(field) for field in _HASH_FIELDS}
    payload["metadata"] = dict(payload.get("metadata") or {})
    return sha256_hex(canonical_json_bytes(payload))


def build_audit_event(
    *,
    event_type: str,
    actor_id: str | None,
    actor_role: str,
    target_type: str,
    target_id: str,
    case_id: str | None = None,
    outcome: str = GovernanceAuditOutcome.SUCCESS.value,
    reason: str = "",
    request_id: str | None = None,
    occurred_at: datetime | None = None,
    event_key: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a sanitized event with a deterministic self-digest."""
    moment = _as_utc(occurred_at or utcnow())
    event: dict[str, Any] = {
        "event_type": str(event_type).upper(),
        "actor_id": redact_text(str(actor_id or "SYSTEM")).strip()[:256] or "SYSTEM",
        "actor_role": redact_text(str(actor_role or "SYSTEM")).strip().upper()[:16] or "SYSTEM",
        "target_type": redact_text(str(target_type or "UNKNOWN")).strip()[:32] or "UNKNOWN",
        "target_id": redact_text(str(target_id or "")).strip()[:128],
        "case_id": (redact_text(str(case_id)).strip()[:36] or None) if case_id else None,
        "outcome": str(outcome).upper(),
        "reason": redact_text(str(reason or "")).strip()[:2048],
        "request_id": (redact_text(str(request_id)).strip()[:128] or None) if request_id else None,
        "occurred_at": moment.isoformat(),
        "event_key": (str(event_key).strip()[:128] or None) if event_key else None,
        "metadata": dict(redact_structure(dict(metadata or {}))),
    }
    event["event_hash"] = compute_event_hash(event)
    event["hash_algorithm"] = "sha256"
    event["assurance"] = AUDIT_ASSURANCE
    event["external_anchor_claimed"] = False
    event["non_claims"] = list(AUDIT_NON_CLAIMS)
    return event


def verify_audit_event(event: Mapping[str, Any]) -> bool:
    """True when the stored digest matches the stored sanitized fields."""
    stored = str(event.get("event_hash") or "")
    if not stored:
        return False
    return stored == compute_event_hash(event)


__all__ = [
    "AUDIT_ASSURANCE",
    "AUDIT_NON_CLAIMS",
    "build_audit_event",
    "compute_event_hash",
    "verify_audit_event",
]
