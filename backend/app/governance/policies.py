"""Versioned governance policy rules (V35).

Policies are append-only: a stable ``policy_id`` has one row per version and
updates always insert a new version. Selection is deterministic and the
default policy is a safe fallback whose retention/review durations remain
organization-defined until explicitly configured.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from backend.app.forensics.constants import CaseType, EvidenceArtifactType
from backend.app.governance.constants import (
    DEFAULT_POLICY_ID,
    DEFAULT_POLICY_NAME,
    DEFAULT_POLICY_REASON,
    DEFAULT_POLICY_VERSION,
    POLICY_TRANSITIONS,
    ApprovalLevel,
    PolicyState,
)
from backend.app.governance.errors import PolicyValidationError

_DEFAULT_POLICY_NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")


def default_policy_row_id() -> str:
    """Stable row identity for the seeded default policy version."""
    return str(uuid.uuid5(_DEFAULT_POLICY_NAMESPACE, "governance/POL-DEFAULT/1"))


def new_policy_id() -> str:
    return f"POL-{uuid.uuid4().hex[:12].upper()}"


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return None


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


@dataclass(frozen=True)
class PolicyDefinition:
    policy_id: str
    version: int
    name: str
    state: str
    case_type: str | None = None
    evidence_category: str | None = None
    retention_days: int | None = None
    review_interval_days: int | None = None
    required_approval_level: str = ApprovalLevel.SINGLE_REVIEWER.value
    export_allowed: bool = True
    export_requires_approval: bool = True
    allow_evidence_bytes: bool = False
    export_expiry_days: int | None = None
    export_review_days: int | None = None
    legal_hold_eligible: bool = True
    disposition_review_required: bool = True
    actor_id: str = "SYSTEM"
    actor_role: str = "SYSTEM"
    reason: str = DEFAULT_POLICY_REASON
    idempotency_key: str | None = None
    created_at: datetime | None = None

    @classmethod
    def from_mapping(cls, row: Mapping[str, Any]) -> PolicyDefinition:
        return cls(
            policy_id=str(row.get("policy_id") or ""),
            version=int(row.get("version") or 0),
            name=str(row.get("name") or ""),
            state=str(row.get("state") or PolicyState.DRAFT.value).upper(),
            case_type=str(row["case_type"]).upper() if row.get("case_type") else None,
            evidence_category=(
                str(row["evidence_category"]).upper() if row.get("evidence_category") else None
            ),
            retention_days=_optional_int(row.get("retention_days")),
            review_interval_days=_optional_int(row.get("review_interval_days")),
            required_approval_level=str(
                row.get("required_approval_level") or ApprovalLevel.SINGLE_REVIEWER.value
            ).upper(),
            export_allowed=bool(row.get("export_allowed", True)),
            export_requires_approval=bool(row.get("export_requires_approval", True)),
            allow_evidence_bytes=bool(row.get("allow_evidence_bytes", False)),
            export_expiry_days=_optional_int(row.get("export_expiry_days")),
            export_review_days=_optional_int(row.get("export_review_days")),
            legal_hold_eligible=bool(row.get("legal_hold_eligible", True)),
            disposition_review_required=bool(row.get("disposition_review_required", True)),
            actor_id=str(row.get("actor_id") or "SYSTEM"),
            actor_role=str(row.get("actor_role") or "SYSTEM").upper(),
            reason=str(row.get("reason") or ""),
            idempotency_key=(str(row["idempotency_key"]) if row.get("idempotency_key") is not None else None),
            created_at=_parse_datetime(row.get("created_at")),
        )

    def snapshot(self) -> dict[str, Any]:
        """Sanitized immutable policy snapshot stored with every decision."""
        return {
            "policy_id": self.policy_id,
            "version": int(self.version),
            "name": self.name,
            "state": self.state,
            "case_type": self.case_type,
            "evidence_category": self.evidence_category,
            "retention_days": self.retention_days,
            "review_interval_days": self.review_interval_days,
            "required_approval_level": self.required_approval_level,
            "export_allowed": bool(self.export_allowed),
            "export_requires_approval": bool(self.export_requires_approval),
            "allow_evidence_bytes": bool(self.allow_evidence_bytes),
            "export_expiry_days": self.export_expiry_days,
            "export_review_days": self.export_review_days,
            "legal_hold_eligible": bool(self.legal_hold_eligible),
            "disposition_review_required": bool(self.disposition_review_required),
            "reason": self.reason,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.snapshot()
        payload.update(
            {
                "actor_id": self.actor_id,
                "actor_role": self.actor_role,
                "idempotency_key": self.idempotency_key,
                "created_at": self.created_at.astimezone(UTC).isoformat() if self.created_at else None,
                "is_default": self.policy_id == DEFAULT_POLICY_ID,
            }
        )
        return payload


def default_policy_definition(*, version: int = DEFAULT_POLICY_VERSION) -> PolicyDefinition:
    return PolicyDefinition(
        policy_id=DEFAULT_POLICY_ID,
        version=int(version),
        name=DEFAULT_POLICY_NAME,
        state=PolicyState.ENABLED.value,
        case_type=None,
        evidence_category=None,
        retention_days=None,
        review_interval_days=None,
        required_approval_level=ApprovalLevel.SINGLE_REVIEWER.value,
        export_allowed=True,
        export_requires_approval=True,
        allow_evidence_bytes=False,
        export_expiry_days=None,
        export_review_days=None,
        legal_hold_eligible=True,
        disposition_review_required=True,
        actor_id="SYSTEM",
        actor_role="SYSTEM",
        reason=DEFAULT_POLICY_REASON,
        created_at=None,
    )


def validate_policy(policy: PolicyDefinition) -> None:
    """Validate a candidate policy version. Raises ``PolicyValidationError``."""
    name = str(policy.name or "").strip()
    if not name:
        raise PolicyValidationError("policy name must not be empty")
    if len(name) > 128:
        raise PolicyValidationError("policy name must be at most 128 characters")
    if not str(policy.reason or "").strip():
        raise PolicyValidationError("a policy reason is required")
    if policy.state not in {state.value for state in PolicyState}:
        raise PolicyValidationError(f"unknown policy state: {policy.state}")
    if policy.required_approval_level not in {level.value for level in ApprovalLevel}:
        raise PolicyValidationError(f"unknown approval level: {policy.required_approval_level}")
    if policy.case_type is not None and policy.case_type not in {item.value for item in CaseType}:
        raise PolicyValidationError(f"unknown case type: {policy.case_type}")
    if policy.evidence_category is not None and policy.evidence_category not in {
        item.value for item in EvidenceArtifactType
    }:
        raise PolicyValidationError(f"unknown evidence category: {policy.evidence_category}")
    for field_name in ("retention_days", "review_interval_days", "export_expiry_days", "export_review_days"):
        value = getattr(policy, field_name)
        if value is not None and int(value) <= 0:
            raise PolicyValidationError(f"{field_name} must be positive when configured")
    if (
        policy.retention_days is not None
        and policy.review_interval_days is not None
        and int(policy.review_interval_days) > int(policy.retention_days)
    ):
        raise PolicyValidationError("review_interval_days must not exceed retention_days")
    if policy.allow_evidence_bytes and not policy.export_allowed:
        raise PolicyValidationError("allow_evidence_bytes requires export_allowed")
    if (
        policy.required_approval_level == ApprovalLevel.DUAL_REVIEWER.value
        and not policy.disposition_review_required
    ):
        raise PolicyValidationError("DUAL_REVIEWER requires disposition_review_required")
    if policy.policy_id == DEFAULT_POLICY_ID and policy.state != PolicyState.ENABLED.value:
        raise PolicyValidationError("the default policy cannot be disabled, archived, or drafted")


def validate_state_transition(current: str, target: str) -> None:
    current_state = PolicyState(str(current).upper())
    target_state = PolicyState(str(target).upper())
    if target_state not in POLICY_TRANSITIONS[current_state]:
        raise PolicyValidationError(
            f"invalid policy state transition: {current_state.value} -> {target_state.value}"
        )


def _normalize_policies(candidates: Iterable[PolicyDefinition | Mapping[str, Any]]) -> list[PolicyDefinition]:
    normalized: list[PolicyDefinition] = []
    for item in candidates:
        normalized.append(item if isinstance(item, PolicyDefinition) else PolicyDefinition.from_mapping(item))
    return normalized


def latest_versions(
    candidates: Iterable[PolicyDefinition | Mapping[str, Any]],
) -> list[PolicyDefinition]:
    """Return the highest version per policy id (history is never rewritten)."""
    newest: dict[str, PolicyDefinition] = {}
    for policy in _normalize_policies(candidates):
        current = newest.get(policy.policy_id)
        if current is None or policy.version > current.version:
            newest[policy.policy_id] = policy
    return [newest[key] for key in sorted(newest)]


def policy_specificity(
    policy: PolicyDefinition,
    *,
    case_type: str,
    evidence_categories: Sequence[str],
) -> int | None:
    """Score a policy for one case; ``None`` means it does not apply."""
    if policy.policy_id == DEFAULT_POLICY_ID:
        return None
    if policy.case_type is not None and policy.case_type != str(case_type).upper():
        return None
    if policy.evidence_category is not None:
        if policy.evidence_category not in {str(item).upper() for item in evidence_categories}:
            return None
    score = 0
    if policy.case_type is not None:
        score += 2
    if policy.evidence_category is not None:
        score += 1
    return score


def select_policy(
    candidates: Iterable[PolicyDefinition | Mapping[str, Any]],
    *,
    case_type: str,
    evidence_categories: Sequence[str] = (),
) -> PolicyDefinition | None:
    """Deterministically choose the most specific enabled policy.

    Exact case-type matches outrank evidence-category-only matches; ties are
    resolved by ascending ``policy_id``. The default policy is the fallback.
    """
    newest = latest_versions(candidates)
    enabled = [policy for policy in newest if policy.state == PolicyState.ENABLED.value]
    scored: list[tuple[int, str, PolicyDefinition]] = []
    for policy in enabled:
        score = policy_specificity(policy, case_type=case_type, evidence_categories=evidence_categories)
        if score is not None:
            scored.append((score, policy.policy_id, policy))
    if scored:
        scored.sort(key=lambda item: (-item[0], item[1]))
        return scored[0][2]
    defaults = [policy for policy in enabled if policy.policy_id == DEFAULT_POLICY_ID]
    if defaults:
        defaults.sort(key=lambda policy: policy.version, reverse=True)
        return defaults[0]
    return None


__all__ = [
    "PolicyDefinition",
    "default_policy_definition",
    "default_policy_row_id",
    "latest_versions",
    "new_policy_id",
    "policy_specificity",
    "select_policy",
    "validate_policy",
    "validate_state_transition",
]
