"""V35 forensic governance orchestration.

The service composes versioned policies, deterministic retention evaluation,
and (in later layers) legal holds, disposition review, export approvals,
append-only access audit, and compliance-readiness reporting. It never deletes
or mutates evidence, cases, custody records, checkpoints, or audit history.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import date, datetime
from typing import Any

from backend.app.core.logging import get_logger
from backend.app.domain.common import utcnow
from backend.app.forensics.errors import ForensicCaseNotFoundError
from backend.app.governance.constants import (
    GOVERNANCE_ASSURANCE,
    GOVERNANCE_LIMITATIONS,
    GOVERNANCE_NON_CLAIMS,
    MAX_BATCH_SIZE,
    EvaluationKind,
    PolicyState,
)
from backend.app.governance.errors import (
    EvaluationNotFoundError,
    PolicyNotFoundError,
    PolicyValidationError,
)
from backend.app.governance.policies import (
    PolicyDefinition,
    new_policy_id,
    select_policy,
)
from backend.app.governance.repository import GovernanceRepository
from backend.app.governance.retention import (
    build_evaluation_key,
    evaluate_retention,
    evaluation_key_payload,
    normalize_as_of,
)

logger = get_logger("industrial-vision.governance")

_POLICY_FIELDS: tuple[str, ...] = (
    "name",
    "state",
    "case_type",
    "evidence_category",
    "retention_days",
    "review_interval_days",
    "required_approval_level",
    "export_allowed",
    "export_requires_approval",
    "allow_evidence_bytes",
    "export_expiry_days",
    "export_review_days",
    "legal_hold_eligible",
    "disposition_review_required",
    "reason",
)


def _definition(payload: Mapping[str, Any], *, policy_id: str) -> PolicyDefinition:
    normalized = dict(payload)
    if normalized.get("state") is not None:
        normalized["state"] = str(normalized["state"]).upper()
    if normalized.get("case_type") is not None:
        normalized["case_type"] = str(normalized["case_type"]).upper()
    if normalized.get("evidence_category") is not None:
        normalized["evidence_category"] = str(normalized["evidence_category"]).upper()
    if normalized.get("required_approval_level") is not None:
        normalized["required_approval_level"] = str(normalized["required_approval_level"]).upper()
    return PolicyDefinition(
        policy_id=policy_id,
        version=1,
        name=str(normalized.get("name") or ""),
        state=str(normalized.get("state") or PolicyState.DRAFT.value).upper(),
        case_type=normalized.get("case_type"),
        evidence_category=normalized.get("evidence_category"),
        retention_days=normalized.get("retention_days"),
        review_interval_days=normalized.get("review_interval_days"),
        required_approval_level=str(normalized.get("required_approval_level") or "SINGLE_REVIEWER").upper(),
        export_allowed=bool(normalized.get("export_allowed", True)),
        export_requires_approval=bool(normalized.get("export_requires_approval", True)),
        allow_evidence_bytes=bool(normalized.get("allow_evidence_bytes", False)),
        export_expiry_days=normalized.get("export_expiry_days"),
        export_review_days=normalized.get("export_review_days"),
        legal_hold_eligible=bool(normalized.get("legal_hold_eligible", True)),
        disposition_review_required=bool(normalized.get("disposition_review_required", True)),
        actor_id=str(normalized.get("actor_id") or "SYSTEM"),
        actor_role=str(normalized.get("actor_role") or "SYSTEM").upper(),
        reason=str(normalized.get("reason") or ""),
        idempotency_key=normalized.get("idempotency_key"),
    )


class GovernanceService:
    def __init__(
        self,
        *,
        settings: Any,
        repository: GovernanceRepository,
        forensic_repository: Any,
        clock: Callable[[], datetime] | None = None,
        alert_repository: Any | None = None,
        notifier: Any | None = None,
        integrity_service: Any | None = None,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._forensics = forensic_repository
        self._clock = clock or utcnow
        self._alert_repository = alert_repository
        self._notifier = notifier
        self._integrity = integrity_service

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def ensure_default_policy(self) -> dict[str, Any]:
        policy, replayed = self._repository.ensure_default_policy()
        return {"policy": policy, "replayed": replayed}

    def status(self) -> dict[str, Any]:
        return {
            "enabled": bool(getattr(self._settings, "governance_enabled", True)),
            "assurance": GOVERNANCE_ASSURANCE,
            "policy_count": self._repository.count_policies(),
            "evaluation_states": self._repository.evaluation_state_counts(),
            "audit_event_count": self._repository.count_audit_events(),
            "retention_scheduler": "DISABLED",
            "automatic_deletion": False,
            "automatic_hold_release": False,
            "automatic_disposition_approval": False,
            "regulatory_certification_claimed": False,
            "external_immutable_storage_claimed": False,
            "external_anchor_claimed": False,
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
            "limitations": list(GOVERNANCE_LIMITATIONS),
        }

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------
    def create_policy(
        self,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
    ) -> dict[str, Any]:
        policy_id = str(payload.get("policy_id") or new_policy_id()).upper()
        if policy_id == "POL-DEFAULT":
            raise PolicyValidationError(
                "the default policy is seeded automatically; create a new version instead"
            )
        definition = _definition(
            {
                **payload,
                "actor_id": actor_id or "SYSTEM",
                "actor_role": actor_role,
            },
            policy_id=policy_id,
        )
        policy, replayed = self._repository.create_policy_version(definition)
        return {"policy": policy, "replayed": replayed}

    def update_policy(
        self,
        policy_id: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        expected_version: int | None,
    ) -> dict[str, Any]:
        latest = self._repository.get_policy(policy_id)
        if latest is None:
            raise PolicyNotFoundError(policy_id)
        merged: dict[str, Any] = {key: latest.get(key) for key in _POLICY_FIELDS}
        for key in _POLICY_FIELDS:
            if key in payload:
                merged[key] = payload[key]
        definition = _definition(
            {
                **merged,
                "actor_id": actor_id or "SYSTEM",
                "actor_role": actor_role,
                "idempotency_key": payload.get("idempotency_key"),
            },
            policy_id=str(policy_id).upper(),
        )
        policy, replayed = self._repository.create_policy_version(
            definition, expected_version=expected_version
        )
        return {"policy": policy, "replayed": replayed}

    def set_policy_state(
        self,
        policy_id: str,
        state: str,
        *,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        expected_version: int | None,
    ) -> dict[str, Any]:
        return self.update_policy(
            policy_id,
            {"state": state, "reason": reason},
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=expected_version,
        )

    def get_policy(self, policy_id: str) -> dict[str, Any]:
        policy = self._repository.get_policy(policy_id)
        if policy is None:
            raise PolicyNotFoundError(policy_id)
        return policy

    def list_policies(self, *, page: int = 1, page_size: int | None = None) -> dict[str, Any]:
        size = int(page_size or getattr(self._settings, "governance_page_size", 20))
        items, total = self._repository.list_policies(page=page, page_size=size)
        return {"items": items, "page": max(1, int(page)), "page_size": size, "total": total}

    def list_policy_versions(
        self, policy_id: str, *, page: int = 1, page_size: int | None = None
    ) -> dict[str, Any]:
        self.get_policy(policy_id)
        size = int(page_size or getattr(self._settings, "governance_page_size", 20))
        items, total = self._repository.list_policy_versions(policy_id, page=page, page_size=size)
        return {"items": items, "page": max(1, int(page)), "page_size": size, "total": total}

    # ------------------------------------------------------------------
    # Retention
    # ------------------------------------------------------------------
    def _case_detail(self, case_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        case = self._forensics.get_case(case_id)
        if case is None:
            raise ForensicCaseNotFoundError(case_id)
        detail = self._forensics.get_case_detail(case_id)
        if not isinstance(detail, dict):
            detail = {"case": case, "evidence_references": []}
        detail.setdefault("case", case)
        return case, detail

    def _policy_for_case(self, detail: Mapping[str, Any]) -> PolicyDefinition | None:
        case = dict(detail.get("case") or {})
        categories = sorted(
            {
                str(reference.get("artifact_type") or "").upper()
                for reference in detail.get("evidence_references") or []
                if reference.get("artifact_type")
            }
        )
        candidates = [
            PolicyDefinition.from_mapping(row) for row in self._repository.latest_enabled_policies()
        ]
        return select_policy(
            candidates,
            case_type=str(case.get("case_type") or ""),
            evidence_categories=categories,
        )

    def _evaluate(
        self,
        case_id: str,
        *,
        actor_id: str | None,
        actor_role: str,
        as_of: datetime | date | None,
        evaluation_kind: str,
        request_id: str | None = None,
        review_reason: str | None = None,
        policy_override: PolicyDefinition | None = None,
    ) -> dict[str, Any]:
        case, detail = self._case_detail(case_id)
        policy = policy_override or self._policy_for_case(detail)
        holds, _ = self._repository.list_holds(case_id=case_id, page=1, page_size=100)
        latest_disposition = self._repository.latest_disposition(case_id)
        latest_verification = self._forensics.latest_verification(case_id)
        moment = normalize_as_of(as_of or self._clock())
        result = evaluate_retention(
            case=case,
            policy=policy,
            as_of=moment,
            holds=holds,
            latest_disposition=latest_disposition,
            latest_verification=latest_verification,
            review_completed_at=moment if evaluation_kind == EvaluationKind.REVIEW.value else None,
        )
        key_payload = evaluation_key_payload(
            case_id=case_id,
            policy_id=result.policy_id,
            policy_version=result.policy_version,
            evaluation_kind=evaluation_kind,
            as_of=moment,
            hold_ids=result.legal_hold_ids,
            latest_disposition=latest_disposition,
            latest_verification=latest_verification,
        )
        key = build_evaluation_key(key_payload)
        evaluation, replayed = self._repository.create_evaluation(
            case_id=case_id,
            evaluation_kind=evaluation_kind,
            policy_id=result.policy_id,
            policy_version=result.policy_version,
            policy_snapshot=policy.snapshot() if policy is not None else {},
            as_of=moment.date(),
            evaluated_at=moment if evaluation_kind == EvaluationKind.REVIEW.value else self._clock(),
            retention_start=result.retention_start,
            retention_deadline=result.retention_deadline,
            next_review_at=result.next_review_at,
            governance_state=result.governance_state,
            data_status=result.data_status,
            disposition_eligible=result.disposition_eligible,
            integrity_status=result.integrity_status,
            verification_id=result.verification_id,
            legal_hold_ids=result.legal_hold_ids,
            reasons=result.reasons,
            created_by=actor_id,
            request_id=request_id,
            reviewed_by=actor_id if evaluation_kind == EvaluationKind.REVIEW.value else None,
            review_reason=review_reason if evaluation_kind == EvaluationKind.REVIEW.value else None,
            idempotency_key=key,
        )
        return {
            "case_id": case_id,
            "evaluation": evaluation,
            "replayed": replayed,
            "policy": policy.snapshot() if policy is not None else None,
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
        }

    def evaluate_case(
        self,
        case_id: str,
        *,
        actor_id: str | None,
        actor_role: str,
        as_of: datetime | date | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return self._evaluate(
            case_id,
            actor_id=actor_id,
            actor_role=actor_role,
            as_of=as_of,
            evaluation_kind=EvaluationKind.EVALUATION.value,
            request_id=request_id,
        )

    def evaluate_batch(
        self,
        case_ids: Sequence[str],
        *,
        actor_id: str | None,
        actor_role: str,
        as_of: datetime | date | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        limit = min(
            MAX_BATCH_SIZE,
            max(1, int(getattr(self._settings, "governance_retention_batch_limit", 100))),
        )
        unique = list(dict.fromkeys(str(item) for item in case_ids if str(item).strip()))
        if len(unique) > limit:
            raise PolicyValidationError(f"retention batch is limited to {limit} cases")
        items: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for case_id in unique:
            try:
                items.append(
                    self.evaluate_case(
                        case_id,
                        actor_id=actor_id,
                        actor_role=actor_role,
                        as_of=as_of,
                        request_id=request_id,
                    )
                )
            except Exception as exc:  # isolated per-case failure
                errors.append({"case_id": case_id, "error": str(exc)[:512]})
        return {"items": items, "errors": errors, "limit": limit}

    def review_retention(
        self,
        case_id: str,
        *,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        as_of: datetime | date | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        if not str(reason or "").strip():
            raise PolicyValidationError("a review reason is required")
        latest = self._repository.latest_evaluation(case_id)
        if latest is None:
            raise EvaluationNotFoundError(case_id)
        policy = None
        if latest.get("policy_id") and latest.get("policy_version"):
            row = self._repository.get_policy_version(str(latest["policy_id"]), int(latest["policy_version"]))
            if row is not None:
                policy = PolicyDefinition.from_mapping(row)
        return self._evaluate(
            case_id,
            actor_id=actor_id,
            actor_role=actor_role,
            as_of=as_of,
            evaluation_kind=EvaluationKind.REVIEW.value,
            request_id=request_id,
            review_reason=reason,
            policy_override=policy,
        )

    def retention_case(self, case_id: str) -> dict[str, Any]:
        case = self._forensics.get_case(case_id)
        if case is None:
            raise ForensicCaseNotFoundError(case_id)
        latest = self._repository.latest_evaluation(case_id)
        return {
            "case": case,
            "evaluation": latest,
            "state": latest.get("governance_state") if latest else "NOT_EVALUATED",
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
        }


__all__ = ["GovernanceService"]
