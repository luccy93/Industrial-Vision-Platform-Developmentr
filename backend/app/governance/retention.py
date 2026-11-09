"""Deterministic, non-destructive retention evaluation (V35).

The evaluator is pure: it takes an injected ``as_of`` clock value and existing
V34/V35 records and returns a governance state. It never deletes, schedules a
deletion, releases a hold, or approves a disposition. Missing metadata is
reported explicitly instead of being guessed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from backend.app.forensics.custody import canonical_json_bytes, datetime_to_iso, sha256_hex
from backend.app.governance.constants import (
    BLOCKING_HOLD_STATUSES,
    CASE_STATUS_NOT_TERMINAL,
    DISPOSITION_APPROVED,
    DISPOSITION_BLOCKED,
    DISPOSITION_ELIGIBLE_CASE_STATUSES,
    DISPOSITION_OPEN,
    DISPOSITION_REVIEW_REQUIRED,
    INTEGRITY_NOT_PASS,
    INTEGRITY_UNAVAILABLE,
    LEGAL_HOLD_ACTIVE,
    LEGAL_HOLD_PENDING_APPROVAL,
    OPEN_DISPOSITION_STATUSES,
    RETENTION_DEADLINE_REACHED,
    RETENTION_DURATION_UNCONFIGURED,
    RETENTION_POLICY_UNAVAILABLE,
    RETENTION_REVIEW_DUE,
    RETENTION_START_UNAVAILABLE,
    REVIEW_INTERVAL_UNCONFIGURED,
    DataStatus,
    DispositionStatus,
    GovernanceState,
    LegalHoldStatus,
)
from backend.app.governance.policies import PolicyDefinition

DISPOSITION_APPROVAL_NOTE = (
    "Approval authorizes only a future, separately scoped disposition process; "
    "no physical deletion is performed or scheduled by V35."
)


def parse_utc(value: Any) -> datetime | None:
    """Parse a datetime value and normalize it to aware UTC."""
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed.astimezone(UTC) if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return None


def normalize_as_of(value: datetime | date) -> datetime:
    """Normalize an evaluation clock to the UTC midnight boundary."""
    if isinstance(value, datetime):
        moment = value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
    elif isinstance(value, date):
        moment = datetime.combine(value, time.min, tzinfo=UTC)
    else:
        raise ValueError("as_of must be a date or datetime")
    return datetime.combine(moment.date(), time.min, tzinfo=UTC)


@dataclass
class RetentionResult:
    governance_state: str
    data_status: str
    as_of: datetime
    policy_id: str | None = None
    policy_version: int | None = None
    retention_start: datetime | None = None
    retention_deadline: datetime | None = None
    next_review_at: datetime | None = None
    disposition_eligible: bool = False
    integrity_status: str = "NOT_RUN"
    verification_id: str | None = None
    legal_hold_ids: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    deletion_authorized: bool = False
    deletion_note: str = "Retention state is not a deletion instruction; V35 never deletes evidence."

    def to_dict(self) -> dict[str, Any]:
        return {
            "governance_state": self.governance_state,
            "data_status": self.data_status,
            "as_of": self.as_of.date().isoformat(),
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "retention_start": datetime_to_iso(self.retention_start) or None,
            "retention_deadline": datetime_to_iso(self.retention_deadline) or None,
            "next_review_at": datetime_to_iso(self.next_review_at) or None,
            "disposition_eligible": bool(self.disposition_eligible),
            "integrity_status": self.integrity_status,
            "verification_id": self.verification_id,
            "legal_hold_ids": sorted(self.legal_hold_ids),
            "reasons": sorted(set(self.reasons)),
            "deletion_authorized": False,
            "deletion_note": self.deletion_note,
            "disposition_approval_note": DISPOSITION_APPROVAL_NOTE,
        }


def _hold_id(hold: Mapping[str, Any]) -> str:
    return str(hold.get("hold_id") or hold.get("id") or "")


def blocking_holds(holds: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [hold for hold in holds if str(hold.get("status") or "").upper() in BLOCKING_HOLD_STATUSES]


def evaluate_retention(
    *,
    case: Mapping[str, Any],
    policy: PolicyDefinition | None,
    as_of: datetime | date,
    holds: Sequence[Mapping[str, Any]] = (),
    latest_disposition: Mapping[str, Any] | None = None,
    latest_verification: Mapping[str, Any] | None = None,
    review_completed_at: datetime | date | None = None,
) -> RetentionResult:
    """Evaluate one case deterministically without mutating any record."""
    moment = normalize_as_of(as_of)
    reasons: set[str] = set()
    data_status = DataStatus.OK.value

    retention_start = parse_utc(case.get("created_at"))
    if retention_start is None:
        data_status = DataStatus.UNAVAILABLE.value
        reasons.add(RETENTION_START_UNAVAILABLE)
    if policy is None:
        data_status = DataStatus.UNAVAILABLE.value
        reasons.add(RETENTION_POLICY_UNAVAILABLE)

    retention_deadline: datetime | None = None
    next_review_at: datetime | None = None
    if policy is not None:
        if policy.retention_days is None:
            if data_status == DataStatus.OK.value:
                data_status = DataStatus.INCOMPLETE.value
            reasons.add(RETENTION_DURATION_UNCONFIGURED)
        elif retention_start is not None:
            retention_deadline = retention_start + timedelta(days=int(policy.retention_days))
        if policy.review_interval_days is None:
            if data_status == DataStatus.OK.value:
                data_status = DataStatus.INCOMPLETE.value
            reasons.add(REVIEW_INTERVAL_UNCONFIGURED)
        else:
            anchor = normalize_as_of(review_completed_at) if review_completed_at else retention_start
            if anchor is not None:
                next_review_at = anchor + timedelta(days=int(policy.review_interval_days))

    blocking = blocking_holds(holds)
    hold_ids = sorted(hold_id for hold_id in (_hold_id(hold) for hold in blocking) if hold_id)
    if any(str(hold.get("status")).upper() == LegalHoldStatus.PENDING_APPROVAL.value for hold in blocking):
        reasons.add(LEGAL_HOLD_PENDING_APPROVAL)
    if any(str(hold.get("status")).upper() == LegalHoldStatus.ACTIVE.value for hold in blocking):
        reasons.add(LEGAL_HOLD_ACTIVE)

    disposition_status = str(latest_disposition.get("status") or "").upper() if latest_disposition else ""
    disposition_due = retention_deadline is not None and moment >= retention_deadline
    if disposition_due:
        reasons.add(RETENTION_DEADLINE_REACHED)
    if disposition_status == DispositionStatus.APPROVED.value:
        reasons.add(DISPOSITION_APPROVED)
    if disposition_status == DispositionStatus.BLOCKED.value:
        reasons.add(DISPOSITION_BLOCKED)
    if disposition_status in OPEN_DISPOSITION_STATUSES:
        reasons.add(DISPOSITION_OPEN)

    if blocking:
        governance_state = GovernanceState.LEGAL_HOLD.value
    elif disposition_status == DispositionStatus.APPROVED.value:
        governance_state = GovernanceState.DISPOSITION_APPROVED.value
    elif disposition_status == DispositionStatus.BLOCKED.value:
        governance_state = GovernanceState.DISPOSITION_BLOCKED.value
    elif disposition_status in OPEN_DISPOSITION_STATUSES or (
        disposition_due and policy is not None and policy.disposition_review_required
    ):
        governance_state = GovernanceState.DISPOSITION_REVIEW_REQUIRED.value
        reasons.add(DISPOSITION_REVIEW_REQUIRED)
    elif next_review_at is not None and moment >= next_review_at:
        governance_state = GovernanceState.REVIEW_DUE.value
        reasons.add(RETENTION_REVIEW_DUE)
    else:
        governance_state = GovernanceState.ACTIVE.value

    integrity_status = (
        str(latest_verification.get("outcome") or "NOT_RUN").upper() if latest_verification else "NOT_RUN"
    )
    if integrity_status in {"FAIL", "PARTIAL"}:
        reasons.add(INTEGRITY_NOT_PASS)
    elif integrity_status == "UNAVAILABLE":
        reasons.add(INTEGRITY_UNAVAILABLE)

    case_status = str(case.get("status") or "").upper()
    disposition_eligible = bool(
        policy is not None
        and policy.disposition_review_required
        and disposition_due
        and not blocking
        and case_status in DISPOSITION_ELIGIBLE_CASE_STATUSES
        and disposition_status not in {DispositionStatus.APPROVED.value}
        and disposition_status not in OPEN_DISPOSITION_STATUSES
    )
    if disposition_due and case_status not in DISPOSITION_ELIGIBLE_CASE_STATUSES:
        reasons.add(CASE_STATUS_NOT_TERMINAL)

    return RetentionResult(
        governance_state=governance_state,
        data_status=data_status,
        as_of=moment,
        policy_id=policy.policy_id if policy is not None else None,
        policy_version=policy.version if policy is not None else None,
        retention_start=retention_start,
        retention_deadline=retention_deadline,
        next_review_at=next_review_at,
        disposition_eligible=disposition_eligible,
        integrity_status=integrity_status,
        verification_id=(
            str(latest_verification.get("verification_id"))
            if latest_verification and latest_verification.get("verification_id")
            else None
        ),
        legal_hold_ids=hold_ids,
        reasons=sorted(reasons),
    )


def build_evaluation_key(payload: Mapping[str, Any]) -> str:
    """Stable idempotency key for one evaluation input state."""
    return sha256_hex(canonical_json_bytes(dict(payload)))


def evaluation_key_payload(
    *,
    case_id: str,
    policy_id: str | None,
    policy_version: int | None,
    evaluation_kind: str,
    as_of: datetime,
    hold_ids: Sequence[str],
    latest_disposition: Mapping[str, Any] | None,
    latest_verification: Mapping[str, Any] | None,
) -> dict[str, Any]:
    return {
        "case_id": str(case_id),
        "policy_id": policy_id,
        "policy_version": policy_version,
        "evaluation_kind": str(evaluation_kind),
        "as_of_date": normalize_as_of(as_of).date().isoformat(),
        "hold_ids": sorted(str(item) for item in hold_ids),
        "latest_disposition": (
            {
                "id": str(latest_disposition.get("disposition_id") or latest_disposition.get("id") or ""),
                "status": str(latest_disposition.get("status") or "").upper(),
                "version": int(latest_disposition.get("version") or 0),
            }
            if latest_disposition
            else None
        ),
        "latest_verification": (
            {
                "id": str(latest_verification.get("verification_id") or latest_verification.get("id") or ""),
                "outcome": str(latest_verification.get("outcome") or "NOT_RUN").upper(),
            }
            if latest_verification
            else None
        ),
    }


__all__ = [
    "DISPOSITION_APPROVAL_NOTE",
    "RetentionResult",
    "blocking_holds",
    "build_evaluation_key",
    "evaluate_retention",
    "evaluation_key_payload",
    "normalize_as_of",
    "parse_utc",
]
