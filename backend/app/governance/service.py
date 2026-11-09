"""V35 forensic governance orchestration.

The service composes versioned policies, deterministic retention evaluation,
and (in later layers) legal holds, disposition review, export approvals,
append-only access audit, and compliance-readiness reporting. It never deletes
or mutates evidence, cases, custody records, checkpoints, or audit history.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any

from backend.app.core.logging import get_logger
from backend.app.domain.common import utcnow
from backend.app.forensics.errors import ForensicCaseNotFoundError
from backend.app.governance.audit import (
    AUDIT_ASSURANCE,
    AUDIT_NON_CLAIMS,
    build_audit_event,
    verify_audit_event,
)
from backend.app.governance.constants import (
    BLOCKING_HOLD_STATUSES,
    CASE_STATUS_NOT_TERMINAL,
    DISPOSITION_ELIGIBLE_CASE_STATUSES,
    EVALUATION_STALE,
    EXPORT_EVIDENCE_BYTES_DISALLOWED,
    EXPORT_EXPIRED,
    EXPORT_GENERATION_READY_STATUSES,
    EXPORT_POLICY_DISALLOWS,
    GOVERNANCE_ASSURANCE,
    GOVERNANCE_LIMITATIONS,
    GOVERNANCE_NON_CLAIMS,
    HOLD_STATE_CHANGED,
    INTEGRITY_NOT_PASS,
    INTEGRITY_UNAVAILABLE,
    LEGAL_HOLD_ACTIVE,
    LEGAL_HOLD_PENDING_APPROVAL,
    MAX_BATCH_SIZE,
    OPEN_DISPOSITION_STATUSES,
    POLICY_STALE,
    RETENTION_DURATION_UNCONFIGURED,
    RETENTION_EVALUATION_MISSING,
    REVIEW_INTERVAL_UNCONFIGURED,
    VERIFICATION_STATE_CHANGED,
    ApprovalLevel,
    DataStatus,
    DispositionDecision,
    DispositionStatus,
    EvaluationKind,
    ExportApprovalStatus,
    GovernanceAuditEventType,
    GovernanceAuditOutcome,
    LegalHoldStatus,
    PolicyState,
    ReportFormat,
    ReportScope,
    SectionStatus,
)
from backend.app.governance.errors import (
    DispositionBlockedError,
    DispositionNotFoundError,
    DispositionStateError,
    EvaluationNotFoundError,
    ExportApprovalNotFoundError,
    ExportApprovalStateError,
    GovernanceDisabledError,
    GovernanceError,
    GovernanceReportError,
    PolicyNotFoundError,
    PolicyValidationError,
    SeparationOfDutiesError,
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
        forensic_service: Any | None = None,
        clock: Callable[[], datetime] | None = None,
        alert_repository: Any | None = None,
        notifier: Any | None = None,
        integrity_service: Any | None = None,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._forensics = forensic_repository
        self._forensic_service = forensic_service or forensic_repository
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
        audit_events = self._repository.audit_events(limit=500)
        verified = sum(1 for event in audit_events if verify_audit_event(event))
        return {
            "enabled": bool(getattr(self._settings, "governance_enabled", True)),
            "assurance": GOVERNANCE_ASSURANCE,
            "policy_count": self._repository.count_policies(),
            "evaluation_states": self._repository.evaluation_state_counts(),
            "hold_states": self._repository.hold_status_counts(),
            "disposition_states": self._repository.disposition_status_counts(),
            "export_states": self._repository.export_status_counts(),
            "audit_event_count": self._repository.count_audit_events(),
            "audit_integrity": {
                "checked": len(audit_events),
                "verified": verified,
                "outcome": "OK" if verified == len(audit_events) else "FAILED",
                "assurance": AUDIT_ASSURANCE,
            },
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
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return self.update_policy(
            policy_id,
            {"state": state, "reason": reason, "idempotency_key": idempotency_key},
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
        detail = self._forensics.get_case_detail(case_id)
        if not isinstance(detail, dict):
            raise ForensicCaseNotFoundError(case_id)
        case = dict(detail.get("case") or {})
        if not case:
            raise ForensicCaseNotFoundError(case_id)
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

    # ------------------------------------------------------------------
    # Access audit
    # ------------------------------------------------------------------
    def _audit(
        self,
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
        event_key: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        event = build_audit_event(
            event_type=event_type,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type=target_type,
            target_id=target_id,
            case_id=case_id,
            outcome=outcome,
            reason=reason,
            request_id=request_id,
            event_key=event_key,
            metadata=metadata,
        )
        record, replayed = self._repository.record_access_audit(
            event_type=event["event_type"],
            actor_id=event["actor_id"],
            actor_role=event["actor_role"],
            target_type=event["target_type"],
            target_id=event["target_id"],
            case_id=event["case_id"],
            outcome=event["outcome"],
            reason=event["reason"],
            request_id=event["request_id"],
            occurred_at=event["occurred_at"],
            event_key=event["event_key"],
            event_hash=event["event_hash"],
            metadata=event["metadata"],
        )
        return {
            "event": record,
            "replayed": replayed,
            "assurance": AUDIT_ASSURANCE,
            "non_claims": list(AUDIT_NON_CLAIMS),
        }

    def _audit_safe(self, **kwargs: Any) -> None:
        try:
            self._audit(**kwargs)
        except Exception as exc:  # audit must never break a read path
            logger.warning("governance audit write failed: %s", type(exc).__name__)

    def record_access(
        self,
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
        event_key: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._audit(
            event_type=event_type,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type=target_type,
            target_id=target_id,
            case_id=case_id,
            outcome=outcome,
            reason=reason,
            request_id=request_id,
            event_key=event_key,
            metadata=metadata,
        )

    def list_audit(
        self,
        *,
        event_type: str | None = None,
        actor_id: str | None = None,
        case_id: str | None = None,
        outcome: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        size = int(page_size or getattr(self._settings, "governance_audit_page_size", 50))
        items, total = self._repository.list_access_audit(
            event_type=event_type,
            actor_id=actor_id,
            case_id=case_id,
            outcome=outcome,
            target_type=target_type,
            target_id=target_id,
            page=page,
            page_size=size,
        )
        return {
            "items": items,
            "total": total,
            "page": max(1, int(page)),
            "page_size": size,
            "assurance": AUDIT_ASSURANCE,
            "non_claims": list(AUDIT_NON_CLAIMS),
        }

    def audit_summary(self) -> dict[str, Any]:
        summary = self._repository.access_audit_summary()
        events = self._repository.audit_events(limit=500)
        verified = sum(1 for event in events if verify_audit_event(event))
        return {
            **summary,
            "integrity": {
                "checked": len(events),
                "verified": verified,
                "outcome": "OK" if verified == len(events) else "FAILED",
            },
            "assurance": AUDIT_ASSURANCE,
            "non_claims": list(AUDIT_NON_CLAIMS),
        }

    def get_audit(self, event_id: str) -> dict[str, Any]:
        event = self._repository.get_access_audit(event_id)
        return {
            "event": event,
            "digest_valid": verify_audit_event(event),
            "assurance": AUDIT_ASSURANCE,
            "non_claims": list(AUDIT_NON_CLAIMS),
        }

    # ------------------------------------------------------------------
    # Shared governance helpers
    # ------------------------------------------------------------------
    def _require_enabled(self) -> None:
        if not bool(getattr(self._settings, "governance_enabled", True)):
            raise GovernanceDisabledError("governance is disabled")

    def _blocking_holds(self, case_id: str) -> list[dict[str, Any]]:
        holds, _ = self._repository.list_holds(
            case_id=case_id,
            statuses=sorted(BLOCKING_HOLD_STATUSES),
            page=1,
            page_size=100,
        )
        return holds

    @staticmethod
    def _hold_reason_codes(holds: Sequence[Mapping[str, Any]]) -> list[str]:
        codes: set[str] = set()
        for hold in holds:
            status = str(hold.get("status") or "").upper()
            if status == LegalHoldStatus.PENDING_APPROVAL.value:
                codes.add(LEGAL_HOLD_PENDING_APPROVAL)
            if status == LegalHoldStatus.ACTIVE.value:
                codes.add(LEGAL_HOLD_ACTIVE)
        return sorted(codes)

    def _latest_verification(self, case_id: str) -> dict[str, Any] | None:
        try:
            return self._forensics.latest_verification(case_id)
        except Exception:
            return None

    def _notify(
        self,
        event_type: str,
        *,
        case: Mapping[str, Any] | None,
        target_type: str,
        target_id: str,
        severity: str = "MEDIUM",
        detail: str = "",
        reason_codes: Sequence[str] = (),
    ) -> None:
        if self._notifier is None:
            return
        try:
            self._notifier.notify_event(
                event_type=event_type,
                case=case,
                target_type=target_type,
                target_id=target_id,
                severity=severity,
                detail=detail,
                reason_codes=reason_codes,
            )
        except Exception as exc:
            logger.warning("governance notification failed: %s", type(exc).__name__)

    # ------------------------------------------------------------------
    # Legal holds
    # ------------------------------------------------------------------
    def create_legal_hold(
        self,
        case_id: str,
        *,
        evidence_reference_id: str | None,
        scope: str,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        idempotency_key: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        if not str(reason or "").strip():
            raise PolicyValidationError("a legal-hold reason is required")
        case, detail = self._case_detail(case_id)
        policy = self._policy_for_case(detail)
        if policy is None:
            raise PolicyValidationError("no enabled governance policy applies to this case")
        if not policy.legal_hold_eligible:
            raise PolicyValidationError("the applicable governance policy disallows legal holds")
        if evidence_reference_id:
            reference = self._forensics.get_evidence_reference(evidence_reference_id)
            if reference is None or str(reference.get("case_id")) != str(case_id):
                raise PolicyValidationError("the evidence reference does not belong to this forensic case")
        requires_approval = bool(getattr(self._settings, "governance_legal_hold_requires_approval", True))
        status = LegalHoldStatus.PENDING_APPROVAL.value if requires_approval else LegalHoldStatus.ACTIVE.value
        now = self._clock()
        hold, events, replayed = self._repository.create_hold(
            case_id=case_id,
            evidence_reference_id=evidence_reference_id,
            status=status,
            scope=scope,
            reason=reason,
            requested_by=actor_id or "SYSTEM",
            requested_role=actor_role,
            approved_by=None if requires_approval else "POLICY",
            approved_at=None if requires_approval else now,
            approval_reason=(None if requires_approval else "approval not required by configuration"),
            metadata={
                "approval_required": requires_approval,
                "policy_id": policy.policy_id,
                "policy_version": policy.version,
            },
            idempotency_key=idempotency_key,
        )
        if not replayed:
            self._audit(
                event_type=GovernanceAuditEventType.LEGAL_HOLD_CREATED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="LEGAL_HOLD",
                target_id=hold["hold_id"],
                case_id=case_id,
                reason=reason,
                request_id=request_id,
                event_key=f"audit:hold:{hold['hold_id']}:created",
                metadata={
                    "status": hold["status"],
                    "evidence_reference_id": evidence_reference_id,
                    "approval_required": requires_approval,
                },
            )
            self._notify(
                "GOVERNANCE_LEGAL_HOLD_CREATED",
                case=case,
                target_type="LEGAL_HOLD",
                target_id=hold["hold_id"],
                detail="A legal hold was requested.",
                reason_codes=self._hold_reason_codes([hold]),
            )
        return {
            "hold": hold,
            "events": events,
            "replayed": replayed,
            "policy": policy.snapshot(),
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
        }

    def _hold_action(
        self,
        hold_id: str,
        *,
        target_status: str,
        event_type: str,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        expected_version: int | None,
        idempotency_key: str | None,
        request_id: str | None,
        notification: str | None,
    ) -> dict[str, Any]:
        self._require_enabled()
        if not str(reason or "").strip():
            raise PolicyValidationError("a legal-hold action reason is required")
        hold = self._repository.get_hold(hold_id)
        if hold is None:
            raise GovernanceError(f"legal hold not found: {hold_id}")
        actor = actor_id or "SYSTEM"
        if target_status in {LegalHoldStatus.ACTIVE.value, LegalHoldStatus.REJECTED.value}:
            if actor == str(hold.get("requested_by")):
                raise SeparationOfDutiesError(
                    "the legal-hold requester cannot approve or reject their own hold"
                )
        if target_status == LegalHoldStatus.WITHDRAWN.value:
            if actor_role != "ADMIN" and actor != str(hold.get("requested_by")):
                raise SeparationOfDutiesError(
                    "only the requester or an administrator may withdraw a legal hold"
                )
        updated, events, replayed = self._repository.transition_hold(
            hold_id,
            target_status=target_status,
            expected_version=expected_version,
            actor_id=actor,
            actor_role=actor_role,
            reason=reason,
            event_type=event_type,
            idempotency_key=idempotency_key,
        )
        if not replayed:
            self._audit(
                event_type=event_type,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="LEGAL_HOLD",
                target_id=hold_id,
                case_id=str(updated.get("case_id") or ""),
                reason=reason,
                request_id=request_id,
                event_key=f"audit:hold:{hold_id}:{target_status.lower()}:{updated['version']}",
                metadata={"status": target_status, "hold_number": updated.get("hold_number")},
            )
            if notification:
                case = self._forensics.get_case(str(updated.get("case_id") or ""))
                self._notify(
                    notification,
                    case=case,
                    target_type="LEGAL_HOLD",
                    target_id=hold_id,
                    detail=f"Legal hold {target_status.lower()}.",
                    reason_codes=self._hold_reason_codes([updated]),
                )
        return {
            "hold": updated,
            "events": events,
            "replayed": replayed,
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
        }

    def approve_legal_hold(
        self,
        hold_id: str,
        *,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        expected_version: int | None = None,
        idempotency_key: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return self._hold_action(
            hold_id,
            target_status=LegalHoldStatus.ACTIVE.value,
            event_type=GovernanceAuditEventType.LEGAL_HOLD_APPROVED.value,
            reason=reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
            request_id=request_id,
            notification="GOVERNANCE_LEGAL_HOLD_APPROVED",
        )

    def reject_legal_hold(
        self,
        hold_id: str,
        *,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        expected_version: int | None = None,
        idempotency_key: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return self._hold_action(
            hold_id,
            target_status=LegalHoldStatus.REJECTED.value,
            event_type=GovernanceAuditEventType.LEGAL_HOLD_REJECTED.value,
            reason=reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
            request_id=request_id,
            notification=None,
        )

    def release_legal_hold(
        self,
        hold_id: str,
        *,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        expected_version: int | None = None,
        idempotency_key: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return self._hold_action(
            hold_id,
            target_status=LegalHoldStatus.RELEASED.value,
            event_type=GovernanceAuditEventType.LEGAL_HOLD_RELEASED.value,
            reason=reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
            request_id=request_id,
            notification="GOVERNANCE_LEGAL_HOLD_RELEASED",
        )

    def withdraw_legal_hold(
        self,
        hold_id: str,
        *,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        expected_version: int | None = None,
        idempotency_key: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return self._hold_action(
            hold_id,
            target_status=LegalHoldStatus.WITHDRAWN.value,
            event_type=GovernanceAuditEventType.LEGAL_HOLD_WITHDRAWN.value,
            reason=reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
            request_id=request_id,
            notification=None,
        )

    def get_legal_hold(self, hold_id: str) -> dict[str, Any]:
        hold = self._repository.get_hold(hold_id)
        if hold is None:
            raise GovernanceError(f"legal hold not found: {hold_id}")
        return {
            "hold": hold,
            "events": self._repository.list_hold_events(hold_id),
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
        }

    def list_legal_holds(
        self,
        *,
        case_id: str | None = None,
        statuses: Sequence[str] | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        size = int(page_size or getattr(self._settings, "governance_page_size", 20))
        items, total = self._repository.list_holds(
            case_id=case_id, statuses=statuses, page=page, page_size=size
        )
        return {"items": items, "total": total, "page": max(1, int(page)), "page_size": size}

    # ------------------------------------------------------------------
    # Disposition review
    # ------------------------------------------------------------------
    def _disposition_blockers(self, row: Mapping[str, Any]) -> list[str]:
        case_id = str(row.get("case_id") or "")
        case, detail = self._case_detail(case_id)
        policy = self._policy_for_case(detail)
        codes: set[str] = set()
        if policy is None:
            codes.add(POLICY_STALE)
        else:
            if str(row.get("policy_id") or "") != policy.policy_id or int(
                row.get("policy_version") or 0
            ) != int(policy.version):
                codes.add(POLICY_STALE)
            if not policy.disposition_review_required:
                codes.add(POLICY_STALE)
        latest_evaluation = self._repository.latest_evaluation(case_id)
        if latest_evaluation is None or str(latest_evaluation.get("evaluation_id")) != str(
            row.get("evaluation_id")
        ):
            codes.add(EVALUATION_STALE)
        holds = self._blocking_holds(case_id)
        if holds:
            codes.update(self._hold_reason_codes(holds))
            codes.add(HOLD_STATE_CHANGED)
        if str(case.get("status") or "").upper() not in DISPOSITION_ELIGIBLE_CASE_STATUSES:
            codes.add(CASE_STATUS_NOT_TERMINAL)
        verification = self._latest_verification(case_id)
        outcome = str((verification or {}).get("outcome") or "NOT_RUN").upper()
        if outcome in {"FAIL", "PARTIAL"}:
            codes.add(INTEGRITY_NOT_PASS)
        elif outcome in {"UNAVAILABLE", "NOT_RUN"}:
            codes.add(INTEGRITY_UNAVAILABLE)
        metadata = dict(row.get("metadata") or {})
        recorded_verification = str(metadata.get("verification_id") or "")
        current_verification = str((verification or {}).get("verification_id") or "")
        if recorded_verification and recorded_verification != current_verification:
            codes.add(VERIFICATION_STATE_CHANGED)
        if str(metadata.get("verification_outcome") or "").upper() != outcome:
            if metadata.get("verification_outcome"):
                codes.add(VERIFICATION_STATE_CHANGED)
        recorded_holds = sorted(str(item) for item in (metadata.get("hold_ids") or []))
        current_holds = sorted(str(item.get("hold_id")) for item in holds if item.get("hold_id"))
        if recorded_holds != current_holds:
            codes.add(HOLD_STATE_CHANGED)
        return sorted(codes)

    def request_disposition(
        self,
        case_id: str,
        *,
        justification: str,
        actor_id: str | None,
        actor_role: str,
        idempotency_key: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        if not str(justification or "").strip():
            raise PolicyValidationError("a disposition justification is required")
        case, detail = self._case_detail(case_id)
        policy = self._policy_for_case(detail)
        if policy is None:
            raise DispositionBlockedError(
                "no enabled governance policy applies to this case",
                reason_codes=[POLICY_STALE],
            )
        if not policy.disposition_review_required:
            raise PolicyValidationError("the applicable policy does not require disposition review")
        codes: set[str] = set()
        if str(case.get("status") or "").upper() not in DISPOSITION_ELIGIBLE_CASE_STATUSES:
            codes.add(CASE_STATUS_NOT_TERMINAL)
        holds = self._blocking_holds(case_id)
        if holds:
            codes.update(self._hold_reason_codes(holds))
        if codes:
            raise DispositionBlockedError(
                "disposition review is blocked by the current case state",
                reason_codes=sorted(codes),
            )
        evaluation_result = self.evaluate_case(
            case_id,
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=request_id,
        )
        evaluation = evaluation_result["evaluation"]
        if not bool(evaluation.get("disposition_eligible")):
            reason_codes = sorted(
                set(str(item) for item in (evaluation.get("reasons") or [])) | {POLICY_STALE}
            )
            raise DispositionBlockedError(
                "disposition review is not yet eligible for this case",
                reason_codes=reason_codes,
            )
        verification = self._latest_verification(case_id)
        outcome = str((verification or {}).get("outcome") or "NOT_RUN").upper()
        if outcome != "PASS":
            raise DispositionBlockedError(
                "disposition review requires a passing integrity verification",
                reason_codes=[
                    INTEGRITY_NOT_PASS if outcome in {"FAIL", "PARTIAL"} else INTEGRITY_UNAVAILABLE
                ],
            )
        open_key = f"case:{case_id}"
        row, replayed = self._repository.create_disposition(
            case_id=case_id,
            evaluation_id=str(evaluation.get("evaluation_id") or ""),
            status=DispositionStatus.REVIEW_REQUIRED.value,
            justification=justification,
            requested_by=actor_id or "SYSTEM",
            requested_role=actor_role,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            required_approval_level=policy.required_approval_level,
            blocked_reason_codes=[],
            open_key=open_key,
            metadata={
                "evaluation_id": evaluation.get("evaluation_id"),
                "evaluation_state": evaluation.get("governance_state"),
                "verification_id": (verification or {}).get("verification_id"),
                "verification_outcome": outcome,
                "hold_ids": [str(item.get("hold_id")) for item in holds],
                "case_status": case.get("status"),
                "policy_id": policy.policy_id,
                "policy_version": policy.version,
            },
            idempotency_key=idempotency_key,
        )
        if not replayed:
            self._audit(
                event_type=GovernanceAuditEventType.DISPOSITION_REQUESTED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="DISPOSITION",
                target_id=row["disposition_id"],
                case_id=case_id,
                reason=justification,
                request_id=request_id,
                event_key=f"audit:disposition:{row['disposition_id']}:requested",
                metadata={
                    "policy_id": policy.policy_id,
                    "policy_version": policy.version,
                    "evaluation_id": evaluation.get("evaluation_id"),
                },
            )
        return {
            "disposition": row,
            "evaluation": evaluation,
            "replayed": replayed,
            "policy": policy.snapshot(),
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
            "disposition_approval_note": (
                "Approval authorizes only a future, separately scoped disposition process; "
                "no physical deletion is performed or scheduled by V35."
            ),
        }

    def decide_disposition(
        self,
        disposition_id: str,
        *,
        decision: str,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        expected_version: int | None = None,
        idempotency_key: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        if not str(reason or "").strip():
            raise PolicyValidationError("a disposition decision reason is required")
        row = self._repository.get_disposition(disposition_id)
        if row is None:
            raise DispositionNotFoundError(disposition_id)
        current = str(row.get("status") or "").upper()
        if current not in OPEN_DISPOSITION_STATUSES:
            raise DispositionStateError(f"disposition request is already {current}")
        actor = actor_id or "SYSTEM"
        if actor == str(row.get("requested_by")):
            raise SeparationOfDutiesError("the disposition requester cannot decide their own request")
        choice = str(decision or "").upper()
        target: str
        approval_count = int(row.get("approval_count") or 0)
        reviewer_id = actor
        blocked_codes: list[str] = []
        event_type: str
        notification: str | None = None
        if choice == DispositionDecision.WITHDRAW.value:
            if actor_role != "ADMIN" and actor != str(row.get("requested_by")):
                raise SeparationOfDutiesError(
                    "only the requester or an administrator may withdraw a disposition request"
                )
            target = DispositionStatus.WITHDRAWN.value
            event_type = GovernanceAuditEventType.DISPOSITION_WITHDRAWN.value
        elif choice in {DispositionDecision.REJECT.value, DispositionDecision.BLOCK.value}:
            target = DispositionStatus.BLOCKED.value
            blocked_codes = [choice]
            event_type = (
                GovernanceAuditEventType.DISPOSITION_REJECTED.value
                if choice == DispositionDecision.REJECT.value
                else GovernanceAuditEventType.DISPOSITION_BLOCKED.value
            )
        elif choice == DispositionDecision.APPROVE.value:
            blocked_codes = self._disposition_blockers(row)
            if blocked_codes:
                raise DispositionBlockedError(
                    "disposition approval is blocked by the current governance state",
                    reason_codes=blocked_codes,
                )
            if str(row.get("required_approval_level") or "").upper() == ApprovalLevel.DUAL_REVIEWER.value:
                if str(row.get("reviewer_id") or "") == actor:
                    raise SeparationOfDutiesError("a second distinct reviewer is required for dual approval")
                approval_count += 1
                if approval_count < 2:
                    target = DispositionStatus.APPROVAL_PENDING.value
                    event_type = GovernanceAuditEventType.DISPOSITION_REQUESTED.value
                else:
                    target = DispositionStatus.APPROVED.value
                    event_type = GovernanceAuditEventType.DISPOSITION_APPROVED.value
                    notification = "GOVERNANCE_DISPOSITION_APPROVED"
            else:
                approval_count = 1
                target = DispositionStatus.APPROVED.value
                event_type = GovernanceAuditEventType.DISPOSITION_APPROVED.value
                notification = "GOVERNANCE_DISPOSITION_APPROVED"
        else:
            raise PolicyValidationError(f"unknown disposition decision: {decision}")
        open_key = None if target not in OPEN_DISPOSITION_STATUSES else f"case:{row['case_id']}"
        updated, decisions, replayed = self._repository.transition_disposition(
            disposition_id,
            decision=choice,
            target_status=target,
            expected_version=expected_version,
            actor_id=actor,
            actor_role=actor_role,
            reason=reason,
            approval_count=approval_count,
            reviewer_id=reviewer_id,
            decision_reason=reason,
            blocked_reason_codes=blocked_codes,
            open_key=open_key,
            idempotency_key=idempotency_key,
        )
        if not replayed:
            self._audit(
                event_type=event_type,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="DISPOSITION",
                target_id=disposition_id,
                case_id=str(updated.get("case_id") or ""),
                reason=reason,
                request_id=request_id,
                event_key=f"audit:disposition:{disposition_id}:{target.lower()}:{updated['version']}",
                metadata={
                    "decision": choice,
                    "status": target,
                    "approval_count": approval_count,
                    "blocked_reason_codes": blocked_codes,
                },
            )
            if notification:
                case = self._forensics.get_case(str(updated.get("case_id") or ""))
                self._notify(
                    notification,
                    case=case,
                    target_type="DISPOSITION",
                    target_id=disposition_id,
                    detail="Disposition review approved. No deletion is performed.",
                    reason_codes=[],
                )
        return {
            "disposition": updated,
            "decisions": decisions,
            "replayed": replayed,
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
            "physical_deletion_performed": False,
        }

    def get_disposition(self, disposition_id: str) -> dict[str, Any]:
        row = self._repository.get_disposition(disposition_id)
        if row is None:
            raise DispositionNotFoundError(disposition_id)
        return {
            "disposition": row,
            "decisions": self._repository.list_disposition_decisions(disposition_id),
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
        }

    def list_dispositions(
        self,
        *,
        case_id: str | None = None,
        statuses: Sequence[str] | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        size = int(page_size or getattr(self._settings, "governance_page_size", 20))
        items, total = self._repository.list_dispositions(
            case_id=case_id, statuses=statuses, page=page, page_size=size
        )
        return {"items": items, "total": total, "page": max(1, int(page)), "page_size": size}

    # ------------------------------------------------------------------
    # Export approvals
    # ------------------------------------------------------------------
    def _export_blockers(self, row: Mapping[str, Any]) -> list[str]:
        case_id = str(row.get("case_id") or "")
        case, detail = self._case_detail(case_id)
        policy = self._policy_for_case(detail)
        codes: set[str] = set()
        if policy is None:
            codes.add(POLICY_STALE)
        else:
            if str(row.get("policy_id") or "") != policy.policy_id or int(
                row.get("policy_version") or 0
            ) != int(policy.version):
                codes.add(POLICY_STALE)
            if not policy.export_allowed:
                codes.add(EXPORT_POLICY_DISALLOWS)
            if bool(row.get("include_evidence_bytes")) and not policy.allow_evidence_bytes:
                codes.add(EXPORT_EVIDENCE_BYTES_DISALLOWED)
        holds = self._blocking_holds(case_id)
        if holds:
            codes.update(self._hold_reason_codes(holds))
            codes.add(HOLD_STATE_CHANGED)
        expires_at = row.get("expires_at")
        if expires_at:
            parsed = _parse_iso(expires_at)
            if parsed is not None and parsed <= self._clock():
                codes.add(EXPORT_EXPIRED)
        return sorted(codes)

    def request_export(
        self,
        case_id: str,
        *,
        include_evidence_bytes: bool,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        idempotency_key: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        if not str(reason or "").strip():
            raise PolicyValidationError("an export request reason is required")
        case, detail = self._case_detail(case_id)
        policy = self._policy_for_case(detail)
        if policy is None:
            raise PolicyValidationError("no enabled governance policy applies to this case")
        if not policy.export_allowed:
            raise PolicyValidationError("export is disallowed by the applicable governance policy")
        if include_evidence_bytes:
            if not policy.allow_evidence_bytes:
                raise PolicyValidationError(
                    "evidence-byte export is disallowed by the applicable governance policy"
                )
            if not bool(getattr(self._settings, "forensic_export_include_evidence_bytes", False)):
                raise PolicyValidationError("evidence-byte export is disabled by configuration")
        holds = self._blocking_holds(case_id)
        if holds:
            raise DispositionBlockedError(
                "export is blocked while a legal hold is pending or active",
                reason_codes=self._hold_reason_codes(holds),
            )
        requires_approval = bool(policy.export_requires_approval)
        status = (
            ExportApprovalStatus.PENDING_APPROVAL.value
            if requires_approval
            else ExportApprovalStatus.POLICY_AUTO_APPROVED.value
        )
        now = self._clock()
        expires_at = (
            now + timedelta(days=int(policy.export_expiry_days))
            if policy.export_expiry_days is not None
            else None
        )
        review_at = (
            now + timedelta(days=int(policy.export_review_days))
            if policy.export_review_days is not None
            else None
        )
        row, replayed = self._repository.create_export_approval(
            case_id=case_id,
            status=status,
            reason=reason,
            requested_by=actor_id or "SYSTEM",
            requested_role=actor_role,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            include_evidence_bytes=include_evidence_bytes,
            required_approval_level=policy.required_approval_level,
            approved_by=None if requires_approval else "POLICY",
            approved_at=None if requires_approval else now,
            approval_reason=(None if requires_approval else "approval not required by the applicable policy"),
            expires_at=expires_at,
            review_at=review_at,
            metadata={
                "approval_required": requires_approval,
                "policy_id": policy.policy_id,
                "policy_version": policy.version,
                "include_evidence_bytes": include_evidence_bytes,
            },
            idempotency_key=idempotency_key,
        )
        if not replayed:
            self._audit(
                event_type=GovernanceAuditEventType.EXPORT_REQUESTED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="EXPORT_APPROVAL",
                target_id=row["approval_id"],
                case_id=case_id,
                reason=reason,
                request_id=request_id,
                event_key=f"audit:export:{row['approval_id']}:requested",
                metadata={
                    "status": status,
                    "include_evidence_bytes": include_evidence_bytes,
                    "policy_id": policy.policy_id,
                    "policy_version": policy.version,
                },
            )
        return {
            "approval": row,
            "replayed": replayed,
            "policy": policy.snapshot(),
            "delivery_claimed": False,
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
        }

    def _export_action(
        self,
        approval_id: str,
        *,
        target_status: str,
        fields: Mapping[str, Any] | None,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        expected_version: int | None,
        idempotency_key: str | None,
        request_id: str | None,
        event_type: str,
        notification: str | None,
        require_requester_difference: bool,
        check_blockers: bool,
    ) -> dict[str, Any]:
        self._require_enabled()
        row = self._repository.get_export_approval(approval_id)
        if row is None:
            raise ExportApprovalNotFoundError(approval_id)
        actor = actor_id or "SYSTEM"
        if require_requester_difference and actor == str(row.get("requested_by")):
            raise SeparationOfDutiesError("the export requester cannot approve or reject their own request")
        if check_blockers:
            codes = self._export_blockers(row)
            if codes:
                raise DispositionBlockedError(
                    "export approval is blocked by the current governance state",
                    reason_codes=codes,
                )
        updated, replayed = self._repository.transition_export_approval(
            approval_id,
            target_status=target_status,
            expected_version=expected_version,
            actor_id=actor,
            actor_role=actor_role,
            reason=reason,
            fields=fields,
            idempotency_key=idempotency_key,
        )
        if not replayed:
            self._audit(
                event_type=event_type,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="EXPORT_APPROVAL",
                target_id=approval_id,
                case_id=str(updated.get("case_id") or ""),
                reason=reason,
                request_id=request_id,
                event_key=f"audit:export:{approval_id}:{target_status.lower()}:{updated['version']}",
                metadata={"status": target_status},
            )
            if notification:
                case = self._forensics.get_case(str(updated.get("case_id") or ""))
                self._notify(
                    notification,
                    case=case,
                    target_type="EXPORT_APPROVAL",
                    target_id=approval_id,
                    detail=f"Export approval {target_status.lower()}.",
                    reason_codes=[],
                )
        return {
            "approval": updated,
            "replayed": replayed,
            "delivery_claimed": False,
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
        }

    def approve_export(
        self,
        approval_id: str,
        *,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        expected_version: int | None = None,
        idempotency_key: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        now = self._clock()
        return self._export_action(
            approval_id,
            target_status=ExportApprovalStatus.APPROVED.value,
            fields={
                "approved_by": actor_id or "SYSTEM",
                "approved_at": now,
                "approval_reason": reason,
            },
            reason=reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
            request_id=request_id,
            event_type=GovernanceAuditEventType.EXPORT_APPROVED.value,
            notification="GOVERNANCE_EXPORT_APPROVED",
            require_requester_difference=True,
            check_blockers=True,
        )

    def reject_export(
        self,
        approval_id: str,
        *,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        expected_version: int | None = None,
        idempotency_key: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        if not str(reason or "").strip():
            raise PolicyValidationError("a rejection reason is required")
        now = self._clock()
        return self._export_action(
            approval_id,
            target_status=ExportApprovalStatus.REJECTED.value,
            fields={
                "rejected_by": actor_id or "SYSTEM",
                "rejected_at": now,
                "rejection_reason": reason,
            },
            reason=reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
            request_id=request_id,
            event_type=GovernanceAuditEventType.EXPORT_REJECTED.value,
            notification=None,
            require_requester_difference=True,
            check_blockers=False,
        )

    def withdraw_export(
        self,
        approval_id: str,
        *,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        expected_version: int | None = None,
        idempotency_key: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        row = self._repository.get_export_approval(approval_id)
        if row is None:
            raise ExportApprovalNotFoundError(approval_id)
        if str(row.get("status") or "").upper() in {
            ExportApprovalStatus.GENERATED.value,
            ExportApprovalStatus.VERIFIED.value,
            ExportApprovalStatus.VERIFICATION_FAILED.value,
        }:
            raise ExportApprovalStateError(
                "generated export records cannot be withdrawn; evidence records are retained"
            )
        actor = actor_id or "SYSTEM"
        if actor_role != "ADMIN" and actor != str(row.get("requested_by")):
            raise SeparationOfDutiesError(
                "only the requester or an administrator may withdraw an export request"
            )
        now = self._clock()
        return self._export_action(
            approval_id,
            target_status=ExportApprovalStatus.WITHDRAWN.value,
            fields={
                "withdrawn_by": actor,
                "withdrawn_at": now,
                "withdrawal_reason": reason,
            },
            reason=reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=expected_version,
            idempotency_key=idempotency_key,
            request_id=request_id,
            event_type=GovernanceAuditEventType.EXPORT_REQUESTED.value,
            notification=None,
            require_requester_difference=False,
            check_blockers=False,
        )

    def generate_export(
        self,
        approval_id: str,
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        row = self._repository.get_export_approval(approval_id)
        if row is None:
            raise ExportApprovalNotFoundError(approval_id)
        status = str(row.get("status") or "").upper()
        if status not in EXPORT_GENERATION_READY_STATUSES:
            raise ExportApprovalStateError(f"export approval is not generation-ready: {status}")
        codes = self._export_blockers(row)
        if codes:
            if EXPORT_EXPIRED in codes:
                self._repository.transition_export_approval(
                    approval_id,
                    target_status=ExportApprovalStatus.EXPIRED.value,
                    expected_version=int(row.get("version") or 1),
                    actor_id=actor_id or "SYSTEM",
                    actor_role=actor_role,
                    reason="export approval expired",
                )
            raise DispositionBlockedError(
                "export generation is blocked by the current governance state",
                reason_codes=codes,
            )
        export_id = str(row["approval_id"])
        existing = None
        try:
            existing = self._forensic_service.get_export(export_id)
        except Exception:
            existing = None
        now = self._clock()
        if existing is None:
            try:
                export = self._forensic_service.create_export(
                    str(row["case_id"]),
                    include_evidence_bytes=bool(row.get("include_evidence_bytes")),
                    actor_id=actor_id,
                    actor_role=actor_role,
                    export_id=export_id,
                )
            except Exception as exc:
                updated, _ = self._repository.transition_export_approval(
                    approval_id,
                    target_status=ExportApprovalStatus.GENERATION_FAILED.value,
                    expected_version=int(row.get("version") or 1),
                    actor_id=actor_id or "SYSTEM",
                    actor_role=actor_role,
                    reason="export generation failed",
                    fields={
                        "generation_error": str(exc)[:1024],
                        "generated_by": actor_id or "SYSTEM",
                        "generated_at": now,
                    },
                    idempotency_key=f"export:{approval_id}:generation-failed:{row.get('version')}",
                )
                self._audit_safe(
                    event_type=GovernanceAuditEventType.EXPORT_GENERATION_FAILED.value,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    target_type="EXPORT_APPROVAL",
                    target_id=approval_id,
                    case_id=str(row.get("case_id") or ""),
                    outcome=GovernanceAuditOutcome.FAILURE.value,
                    reason=str(exc)[:512],
                    request_id=request_id,
                    event_key=f"audit:export:{approval_id}:generation-failed:{updated['version']}",
                )
                self._notify(
                    "GOVERNANCE_EXPORT_GENERATION_FAILED",
                    case=self._forensics.get_case(str(row.get("case_id") or "")),
                    target_type="EXPORT_APPROVAL",
                    target_id=approval_id,
                    severity="HIGH",
                    detail="Export generation failed.",
                )
                raise
        else:
            export = existing
        updated, replayed = self._repository.transition_export_approval(
            approval_id,
            target_status=ExportApprovalStatus.GENERATED.value,
            expected_version=int(row.get("version") or 1),
            actor_id=actor_id or "SYSTEM",
            actor_role=actor_role,
            reason="export generated",
            fields={
                "export_id": str(export.get("export_id") or export_id),
                "export_sha256": str(export.get("sha256") or ""),
                "manifest_digest": str(export.get("manifest_digest") or ""),
                "root_digest": str(export.get("root_digest") or ""),
                "filename": str(export.get("filename") or ""),
                "size_bytes": int(export.get("size_bytes") or 0),
                "file_count": int(export.get("file_count") or 0),
                "generated_by": actor_id or "SYSTEM",
                "generated_at": now,
                "generation_error": None,
            },
            idempotency_key=f"export:{approval_id}:generated:{row.get('version')}",
        )
        if not replayed:
            self._audit(
                event_type=GovernanceAuditEventType.EXPORT_GENERATED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="EXPORT_APPROVAL",
                target_id=approval_id,
                case_id=str(row.get("case_id") or ""),
                reason="export generated",
                request_id=request_id,
                event_key=f"audit:export:{approval_id}:generated:{updated['version']}",
                metadata={
                    "export_id": updated.get("export_id"),
                    "export_sha256": updated.get("export_sha256"),
                    "manifest_digest": updated.get("manifest_digest"),
                    "root_digest": updated.get("root_digest"),
                    "delivery_claimed": False,
                },
            )
        return {
            "approval": updated,
            "export": export,
            "replayed": replayed,
            "delivery_claimed": False,
            "external_recipient_validated": False,
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
        }

    def verify_governance_export(
        self,
        approval_id: str,
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        row = self._repository.get_export_approval(approval_id)
        if row is None:
            raise ExportApprovalNotFoundError(approval_id)
        status = str(row.get("status") or "").upper()
        if status not in {
            ExportApprovalStatus.GENERATED.value,
            ExportApprovalStatus.VERIFICATION_FAILED.value,
        }:
            raise ExportApprovalStateError(f"export is not verifiable in status: {status}")
        export_id = str(row.get("export_id") or "")
        result = self._forensic_service.verify_export(export_id, actor_id=actor_id, actor_role=actor_role)
        verification = dict(result.get("verification") or {})
        outcome = str(verification.get("outcome") or "FAIL").upper()
        target = (
            ExportApprovalStatus.VERIFIED.value
            if outcome == "PASS"
            else ExportApprovalStatus.VERIFICATION_FAILED.value
        )
        updated, replayed = self._repository.transition_export_approval(
            approval_id,
            target_status=target,
            expected_version=int(row.get("version") or 1),
            actor_id=actor_id or "SYSTEM",
            actor_role=actor_role,
            reason="export verification completed",
            fields={
                "verified_by": actor_id or "SYSTEM",
                "verified_at": self._clock(),
                "verification_outcome": outcome,
                "verification_detail": str(verification.get("detail") or "")[:2048],
            },
            idempotency_key=f"export:{approval_id}:verified:{row.get('version')}:{outcome}",
        )
        if not replayed:
            self._audit(
                event_type=(
                    GovernanceAuditEventType.EXPORT_VERIFIED.value
                    if outcome == "PASS"
                    else GovernanceAuditEventType.EXPORT_VERIFICATION_FAILED.value
                ),
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="EXPORT_APPROVAL",
                target_id=approval_id,
                case_id=str(row.get("case_id") or ""),
                outcome=(
                    GovernanceAuditOutcome.SUCCESS.value
                    if outcome == "PASS"
                    else GovernanceAuditOutcome.FAILURE.value
                ),
                reason="export verification completed",
                request_id=request_id,
                event_key=f"audit:export:{approval_id}:verified:{updated['version']}",
                metadata={"outcome": outcome, "export_id": export_id},
            )
            if outcome != "PASS":
                self._notify(
                    "GOVERNANCE_EXPORT_VERIFICATION_FAILED",
                    case=self._forensics.get_case(str(row.get("case_id") or "")),
                    target_type="EXPORT_APPROVAL",
                    target_id=approval_id,
                    severity="HIGH",
                    detail="Export verification failed.",
                    reason_codes=tuple(verification.get("reason_codes") or []),
                )
        return {
            "approval": updated,
            "verification": verification,
            "replayed": replayed,
            "delivery_claimed": False,
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
        }

    def export_download(
        self,
        approval_id: str,
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> tuple[Any, str, dict[str, Any]]:
        self._require_enabled()
        row = self._repository.get_export_approval(approval_id)
        if row is None:
            raise ExportApprovalNotFoundError(approval_id)
        status = str(row.get("status") or "").upper()
        if status not in {
            ExportApprovalStatus.GENERATED.value,
            ExportApprovalStatus.VERIFIED.value,
            ExportApprovalStatus.VERIFICATION_FAILED.value,
        }:
            raise ExportApprovalStateError(f"export is not downloadable in status: {status}")
        path, filename = self._forensic_service.export_path(str(row.get("export_id") or ""))
        self._audit_safe(
            event_type=GovernanceAuditEventType.EXPORT_DOWNLOAD_SERVED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="EXPORT_APPROVAL",
            target_id=approval_id,
            case_id=str(row.get("case_id") or ""),
            reason="export download served",
            request_id=request_id,
            event_key=f"audit:export:{approval_id}:download:{uuid_hex()}",
            metadata={
                "export_id": row.get("export_id"),
                "delivery_claimed": False,
            },
        )
        return path, filename, row

    def get_export_approval(self, approval_id: str) -> dict[str, Any]:
        row = self._repository.get_export_approval(approval_id)
        if row is None:
            raise ExportApprovalNotFoundError(approval_id)
        return {
            "approval": row,
            "delivery_claimed": False,
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
        }

    def list_export_approvals(
        self,
        *,
        case_id: str | None = None,
        statuses: Sequence[str] | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        size = int(page_size or getattr(self._settings, "governance_page_size", 20))
        items, total = self._repository.list_export_approvals(
            case_id=case_id, statuses=statuses, page=page, page_size=size
        )
        return {
            "items": items,
            "total": total,
            "page": max(1, int(page)),
            "page_size": size,
            "delivery_claimed": False,
        }

    def guard_direct_export(
        self,
        case_id: str,
        *,
        include_evidence_bytes: bool,
        actor_id: str | None,
        actor_role: str,
    ) -> dict[str, Any] | None:
        """Policy/hold guard for backward-compatible direct V34 exports."""
        if not bool(getattr(self._settings, "governance_enabled", True)):
            return None
        case, detail = self._case_detail(case_id)
        policy = self._policy_for_case(detail)
        if policy is None:
            raise GovernanceError("no enabled governance policy applies to this case")
        if not policy.export_allowed:
            raise GovernanceError("export is disallowed by the applicable governance policy")
        if include_evidence_bytes and not policy.allow_evidence_bytes:
            raise GovernanceError("evidence-byte export is disallowed by the applicable governance policy")
        holds = self._blocking_holds(case_id)
        if holds:
            raise GovernanceError("export is blocked while a legal hold is pending or active")
        return policy.snapshot()

    # ------------------------------------------------------------------
    # Retention queue and compliance readiness reports
    # ------------------------------------------------------------------
    def retention_queue(
        self,
        *,
        state: str | None = None,
        page: int = 1,
        page_size: int | None = None,
        as_of: datetime | date | None = None,
    ) -> dict[str, Any]:
        size = int(page_size or getattr(self._settings, "governance_page_size", 20))
        limit = int(getattr(self._settings, "governance_report_max_rows", 500))
        items = self._repository.latest_evaluations(limit=limit)
        if state:
            wanted = str(state).upper()
            items = [item for item in items if str(item.get("governance_state")) == wanted]
        total = len(items)
        start = (max(1, int(page)) - 1) * size
        return {
            "items": items[start : start + size],
            "total": total,
            "page": max(1, int(page)),
            "page_size": size,
            "as_of": normalize_as_of(as_of or self._clock()).date().isoformat(),
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
        }

    def _report_sections(
        self,
        *,
        as_of: datetime,
        detail: bool,
        case_id: str | None,
    ) -> dict[str, Any]:
        max_rows = int(getattr(self._settings, "governance_report_max_rows", 500))
        upcoming_days = int(getattr(self._settings, "governance_report_upcoming_days", 30))
        evaluations = self._repository.latest_evaluations(limit=max_rows)
        if case_id:
            evaluations = [item for item in evaluations if str(item.get("case_id")) == str(case_id)]
        holds = self._repository.list_blocking_holds(limit=max_rows)
        dispositions = self._repository.list_open_dispositions(limit=max_rows)
        audit_events = self._repository.audit_events(limit=max_rows)
        verified_audit = sum(1 for event in audit_events if verify_audit_event(event))
        policies, _ = self._repository.list_policies(page=1, page_size=100)
        default_policy = next((item for item in policies if item.get("policy_id") == "POL-DEFAULT"), None)
        state_counts: dict[str, int] = {}
        unconfigured = 0
        overdue_reviews = 0
        upcoming_reviews = 0
        retention_due = 0
        detail_rows: list[dict[str, Any]] = []
        for item in evaluations:
            state = str(item.get("governance_state") or "UNKNOWN")
            state_counts[state] = state_counts.get(state, 0) + 1
            reasons = {str(code) for code in (item.get("reasons") or [])}
            if RETENTION_DURATION_UNCONFIGURED in reasons or REVIEW_INTERVAL_UNCONFIGURED in reasons:
                unconfigured += 1
            next_review = _parse_iso(item.get("next_review_at"))
            if next_review is not None:
                if next_review < as_of:
                    overdue_reviews += 1
                elif next_review <= as_of + timedelta(days=upcoming_days):
                    upcoming_reviews += 1
            deadline = _parse_iso(item.get("retention_deadline"))
            if deadline is not None and deadline <= as_of:
                retention_due += 1
            if detail:
                case = self._forensics.get_case(str(item.get("case_id") or ""))
                detail_rows.append(
                    {
                        "case_id": item.get("case_id"),
                        "case_number": (case or {}).get("case_number"),
                        "case_status": (case or {}).get("status"),
                        "case_type": (case or {}).get("case_type"),
                        "governance_state": state,
                        "data_status": item.get("data_status"),
                        "policy_id": item.get("policy_id"),
                        "policy_version": item.get("policy_version"),
                        "retention_deadline": item.get("retention_deadline"),
                        "next_review_at": item.get("next_review_at"),
                        "integrity_status": item.get("integrity_status"),
                        "disposition_eligible": item.get("disposition_eligible"),
                        "reasons": list(item.get("reasons") or []),
                        "legal_hold_ids": list(item.get("legal_hold_ids") or []),
                        "deletion_authorized": False,
                    }
                )
        if detail and case_id and not detail_rows:
            # A DETAIL report for a case without a stored evaluation must say so
            # explicitly rather than silently returning an empty list.
            case = self._forensics.get_case(case_id) or {}
            state_counts["NOT_EVALUATED"] = state_counts.get("NOT_EVALUATED", 0) + 1
            detail_rows.append(
                {
                    "case_id": case_id,
                    "case_number": case.get("case_number"),
                    "case_status": case.get("status"),
                    "case_type": case.get("case_type"),
                    "governance_state": "NOT_EVALUATED",
                    "data_status": DataStatus.INCOMPLETE.value,
                    "policy_id": None,
                    "policy_version": None,
                    "retention_deadline": None,
                    "next_review_at": None,
                    "integrity_status": "NOT_RUN",
                    "disposition_eligible": False,
                    "reasons": [RETENTION_EVALUATION_MISSING],
                    "legal_hold_ids": [],
                    "deletion_authorized": False,
                }
            )
        truncated = len(evaluations) >= max_rows
        policy_status = (
            SectionStatus.OK.value
            if default_policy is not None and default_policy.get("state") == "ENABLED"
            else SectionStatus.INCOMPLETE.value
        )
        if default_policy is not None and (
            default_policy.get("retention_days") is None or default_policy.get("review_interval_days") is None
        ):
            policy_status = SectionStatus.PARTIAL.value
        retention_status = (
            SectionStatus.PARTIAL.value
            if (unconfigured or not evaluations or truncated)
            else SectionStatus.OK.value
        )
        audit_status = (
            SectionStatus.OK.value if verified_audit == len(audit_events) else SectionStatus.PARTIAL.value
        )
        overall = (
            "NO_KNOWN_GAPS"
            if policy_status == SectionStatus.OK.value
            and retention_status == SectionStatus.OK.value
            and audit_status == SectionStatus.OK.value
            else "REVIEW_REQUIRED"
        )
        return {
            "overall_status": overall,
            "sections": {
                "policy": {
                    "status": policy_status,
                    "count": len(policies),
                    "enabled_count": sum(1 for item in policies if item.get("state") == "ENABLED"),
                    "default_policy": default_policy,
                    "retention_duration_configured": bool(
                        default_policy and default_policy.get("retention_days") is not None
                    ),
                    "review_interval_configured": bool(
                        default_policy and default_policy.get("review_interval_days") is not None
                    ),
                },
                "retention": {
                    "status": retention_status,
                    "evaluated_cases": len(evaluations),
                    "state_counts": state_counts,
                    "unconfigured_durations": unconfigured,
                    "retention_due": retention_due,
                    "overdue_reviews": overdue_reviews,
                    "upcoming_reviews": upcoming_reviews,
                    "upcoming_window_days": upcoming_days,
                    "truncated": truncated,
                },
                "legal_holds": {
                    "status": SectionStatus.OK.value,
                    "counts": self._repository.hold_status_counts(),
                    "blocking": len(holds),
                    "oldest_blocking_requested_at": self._repository.oldest_blocking_hold_at(),
                },
                "dispositions": {
                    "status": SectionStatus.OK.value,
                    "counts": self._repository.disposition_status_counts(),
                    "open": len(dispositions),
                    "physical_deletion_performed": False,
                },
                "exports": {
                    "status": SectionStatus.OK.value,
                    "counts": self._repository.export_status_counts(),
                    "delivery_claimed": False,
                    "external_recipient_validated": False,
                },
                "audit": {
                    "status": audit_status,
                    "total": self._repository.count_audit_events(),
                    "checked": len(audit_events),
                    "verified": verified_audit,
                    "assurance": AUDIT_ASSURANCE,
                },
                "forensics": {
                    "status": SectionStatus.OK.value,
                    "summary": self._forensic_service.summary(),
                    "external_anchor_claimed": False,
                },
            },
            "detail": detail_rows if detail else None,
        }

    def compliance_report(
        self,
        *,
        scope: str = ReportScope.SUMMARY.value,
        case_id: str | None = None,
        format: str = ReportFormat.JSON.value,
        actor_id: str | None,
        actor_role: str,
        as_of: datetime | date | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        normalized_scope = str(scope).upper()
        if normalized_scope not in {item.value for item in ReportScope}:
            raise GovernanceReportError(f"unknown report scope: {scope}")
        if normalized_scope == ReportScope.DETAIL.value and case_id:
            self._case_detail(case_id)
        moment = normalize_as_of(as_of or self._clock())
        sections = self._report_sections(
            as_of=moment,
            detail=normalized_scope == ReportScope.DETAIL.value,
            case_id=case_id,
        )
        report = {
            "generated_at": self._clock().isoformat(),
            "generated_by": actor_id,
            "as_of": moment.date().isoformat(),
            "scope": normalized_scope,
            "case_id": case_id,
            "format": str(format).lower(),
            "assurance": GOVERNANCE_ASSURANCE,
            "audit_assurance": AUDIT_ASSURANCE,
            "regulatory_certification_claimed": False,
            "external_immutable_storage_claimed": False,
            "external_anchor_claimed": False,
            "automatic_deletion": False,
            "automatic_hold_release": False,
            "automatic_disposition_approval": False,
            **sections,
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
            "limitations": list(GOVERNANCE_LIMITATIONS),
        }
        self._audit(
            event_type=GovernanceAuditEventType.GOVERNANCE_REPORT_GENERATED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="REPORT",
            target_id=case_id or normalized_scope,
            case_id=case_id,
            request_id=request_id,
            event_key=f"audit:report:{normalized_scope}:{case_id or 'all'}:{uuid_hex()}",
            metadata={"scope": normalized_scope, "format": report["format"]},
        )
        return report

    @staticmethod
    def report_csv(report: Mapping[str, Any]) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["section", "metric", "value"])
        writer.writerow(["report", "generated_at", report.get("generated_at")])
        writer.writerow(["report", "scope", report.get("scope")])
        writer.writerow(["report", "as_of", report.get("as_of")])
        writer.writerow(["report", "overall_status", report.get("overall_status")])
        writer.writerow(["report", "regulatory_certification_claimed", "false"])
        writer.writerow(["report", "external_immutable_storage_claimed", "false"])
        writer.writerow(["report", "automatic_deletion", "false"])
        sections = dict(report.get("sections") or {})
        for section_name, payload in sections.items():
            if not isinstance(payload, Mapping):
                continue
            writer.writerow([section_name, "status", payload.get("status")])
            for key, value in payload.items():
                if key == "status":
                    continue
                if isinstance(value, (dict, list)):
                    writer.writerow([section_name, key, json_dumps(value)])
                elif value is not None:
                    writer.writerow([section_name, key, value])
        for row in report.get("detail") or []:
            writer.writerow(["detail", str(row.get("case_id")), json_dumps(row)])
        return buffer.getvalue()


def _parse_iso(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed.astimezone(UTC) if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return None


def uuid_hex() -> str:
    import uuid

    return uuid.uuid4().hex


def json_dumps(value: Any) -> str:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


__all__ = ["GovernanceService"]
