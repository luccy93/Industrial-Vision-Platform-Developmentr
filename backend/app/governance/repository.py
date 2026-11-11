"""Governance persistence (V35).

All writes are additive and transactional. Historical rows (policy versions,
retention evaluations, hold events, disposition decisions, access audit) are
never updated by the application. Mutable workflow rows change state through
explicit, version-checked transitions.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import date, datetime
from typing import Any

from sqlalchemy import and_, func
from sqlalchemy.orm import Session

from backend.app.core.redaction import redact_structure, redact_text
from backend.app.domain.common import utcnow
from backend.app.forensics.custody import datetime_to_iso
from backend.app.governance.constants import (
    DEFAULT_POLICY_ID,
    DISPOSITION_TRANSITIONS,
    EXPORT_TRANSITIONS,
    HOLD_TRANSITIONS,
    LegalHoldStatus,
    PolicyState,
)
from backend.app.governance.errors import (
    DispositionNotFoundError,
    DispositionStateError,
    DispositionVersionConflictError,
    ExportApprovalNotFoundError,
    ExportApprovalStateError,
    ExportApprovalVersionConflictError,
    GovernanceAuditNotFoundError,
    IdempotencyConflictError,
    LegalHoldNotFoundError,
    LegalHoldStateError,
    LegalHoldVersionConflictError,
    PolicyValidationError,
    PolicyVersionConflictError,
)
from backend.app.governance.policies import (
    PolicyDefinition,
    default_policy_definition,
    default_policy_row_id,
    validate_policy,
    validate_state_transition,
)
from backend.app.models.governance_orm import (
    GovernanceAccessAuditORM,
    GovernanceDispositionDecisionORM,
    GovernanceDispositionRequestORM,
    GovernanceExportApprovalORM,
    GovernanceLegalHoldEventORM,
    GovernanceLegalHoldORM,
    GovernancePolicyVersionORM,
    GovernanceRetentionEvaluationORM,
)


def _new_id() -> str:
    return str(uuid.uuid4())


def _safe_text(value: Any, limit: int) -> str:
    return redact_text(str(value or "")).strip()[:limit]


def _iso(value: datetime | None) -> str | None:
    return datetime_to_iso(value) if value is not None else None


def _policy_to_dict(row: GovernancePolicyVersionORM) -> dict[str, Any]:
    return redact_structure(
        {
            "policy_id": row.policy_id,
            "version": int(row.version),
            "name": row.name,
            "state": row.state,
            "case_type": row.case_type,
            "evidence_category": row.evidence_category,
            "retention_days": row.retention_days,
            "review_interval_days": row.review_interval_days,
            "required_approval_level": row.required_approval_level,
            "export_allowed": bool(row.export_allowed),
            "export_requires_approval": bool(row.export_requires_approval),
            "allow_evidence_bytes": bool(row.allow_evidence_bytes),
            "export_expiry_days": row.export_expiry_days,
            "export_review_days": row.export_review_days,
            "legal_hold_eligible": bool(row.legal_hold_eligible),
            "disposition_review_required": bool(row.disposition_review_required),
            "actor_id": row.actor_id,
            "actor_role": row.actor_role,
            "reason": row.reason,
            "idempotency_key": row.idempotency_key,
            "created_at": _iso(row.created_at),
            "is_default": row.policy_id == DEFAULT_POLICY_ID,
        }
    )


def _evaluation_to_dict(row: GovernanceRetentionEvaluationORM) -> dict[str, Any]:
    return redact_structure(
        {
            "evaluation_id": row.id,
            "case_id": row.case_id,
            "evaluation_kind": row.evaluation_kind,
            "evaluation_version": int(row.evaluation_version),
            "policy_id": row.policy_id,
            "policy_version": row.policy_version,
            "policy_snapshot": dict(row.policy_snapshot or {}),
            "as_of": row.as_of.isoformat() if row.as_of else None,
            "evaluated_at": _iso(row.evaluated_at),
            "retention_start": _iso(row.retention_start),
            "retention_deadline": _iso(row.retention_deadline),
            "next_review_at": _iso(row.next_review_at),
            "governance_state": row.governance_state,
            "data_status": row.data_status,
            "disposition_eligible": bool(row.disposition_eligible),
            "integrity_status": row.integrity_status,
            "verification_id": row.verification_id,
            "legal_hold_ids": sorted(str(item) for item in (row.legal_hold_ids or [])),
            "reasons": sorted(str(item) for item in (row.reasons or [])),
            "reviewed_by": row.reviewed_by,
            "review_reason": row.review_reason,
            "created_by": row.created_by,
            "request_id": row.request_id,
            "idempotency_key": row.idempotency_key,
            "created_at": _iso(row.created_at),
            "deletion_authorized": False,
            "deletion_note": "Retention state is not a deletion instruction; V35 never deletes evidence.",
        }
    )


def _hold_to_dict(row: GovernanceLegalHoldORM) -> dict[str, Any]:
    return redact_structure(
        {
            "hold_id": row.id,
            "hold_number": row.hold_number,
            "case_id": row.case_id,
            "evidence_reference_id": row.evidence_reference_id,
            "status": row.status,
            "scope": row.scope,
            "reason": row.reason,
            "requested_by": row.requested_by,
            "requested_role": row.requested_role,
            "requested_at": _iso(row.requested_at),
            "approved_by": row.approved_by,
            "approved_at": _iso(row.approved_at),
            "approval_reason": row.approval_reason,
            "rejected_by": row.rejected_by,
            "rejected_at": _iso(row.rejected_at),
            "rejection_reason": row.rejection_reason,
            "released_by": row.released_by,
            "released_at": _iso(row.released_at),
            "release_reason": row.release_reason,
            "withdrawn_by": row.withdrawn_by,
            "withdrawn_at": _iso(row.withdrawn_at),
            "withdrawal_reason": row.withdrawal_reason,
            "version": int(row.version or 1),
            "idempotency_key": row.idempotency_key,
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
            "metadata": dict(row.meta or {}),
        }
    )


def _hold_event_to_dict(row: GovernanceLegalHoldEventORM) -> dict[str, Any]:
    return redact_structure(
        {
            "event_id": row.id,
            "hold_id": row.hold_id,
            "event_type": row.event_type,
            "actor_id": row.actor_id,
            "actor_role": row.actor_role,
            "reason": row.reason,
            "from_status": row.from_status,
            "to_status": row.to_status,
            "occurred_at": _iso(row.occurred_at),
            "metadata": dict(row.meta or {}),
            "created_at": _iso(row.created_at),
        }
    )


def _disposition_to_dict(row: GovernanceDispositionRequestORM) -> dict[str, Any]:
    return redact_structure(
        {
            "disposition_id": row.id,
            "request_number": row.request_number,
            "case_id": row.case_id,
            "evaluation_id": row.evaluation_id,
            "status": row.status,
            "justification": row.justification,
            "requested_by": row.requested_by,
            "requested_role": row.requested_role,
            "requested_at": _iso(row.requested_at),
            "policy_id": row.policy_id,
            "policy_version": row.policy_version,
            "required_approval_level": row.required_approval_level,
            "approval_count": int(row.approval_count or 0),
            "reviewer_id": row.reviewer_id,
            "reviewed_at": _iso(row.reviewed_at),
            "decision_reason": row.decision_reason,
            "blocked_reason_codes": sorted(str(item) for item in (row.blocked_reason_codes or [])),
            "version": int(row.version or 1),
            "idempotency_key": row.idempotency_key,
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
            "metadata": dict(row.meta or {}),
            "physical_deletion_performed": False,
            "authorizes_future_process": row.status == "APPROVED",
            "disposition_approval_note": (
                "Approval authorizes only a future, separately scoped disposition process; "
                "no physical deletion is performed or scheduled by V35."
            ),
        }
    )


def _disposition_decision_to_dict(row: GovernanceDispositionDecisionORM) -> dict[str, Any]:
    return redact_structure(
        {
            "decision_id": row.id,
            "disposition_id": row.disposition_id,
            "decision": row.decision,
            "actor_id": row.actor_id,
            "actor_role": row.actor_role,
            "reason": row.reason,
            "from_status": row.from_status,
            "to_status": row.to_status,
            "occurred_at": _iso(row.occurred_at),
            "metadata": dict(row.meta or {}),
            "created_at": _iso(row.created_at),
        }
    )


def _export_approval_to_dict(row: GovernanceExportApprovalORM) -> dict[str, Any]:
    return redact_structure(
        {
            "approval_id": row.id,
            "request_number": row.request_number,
            "case_id": row.case_id,
            "status": row.status,
            "reason": row.reason,
            "requested_by": row.requested_by,
            "requested_role": row.requested_role,
            "requested_at": _iso(row.requested_at),
            "policy_id": row.policy_id,
            "policy_version": row.policy_version,
            "include_evidence_bytes": bool(row.include_evidence_bytes),
            "required_approval_level": row.required_approval_level,
            "approved_by": row.approved_by,
            "approved_at": _iso(row.approved_at),
            "approval_reason": row.approval_reason,
            "rejected_by": row.rejected_by,
            "rejected_at": _iso(row.rejected_at),
            "rejection_reason": row.rejection_reason,
            "withdrawn_by": row.withdrawn_by,
            "withdrawn_at": _iso(row.withdrawn_at),
            "withdrawal_reason": row.withdrawal_reason,
            "export_id": row.export_id,
            "export_sha256": row.export_sha256,
            "manifest_digest": row.manifest_digest,
            "root_digest": row.root_digest,
            "filename": row.filename,
            "size_bytes": row.size_bytes,
            "file_count": row.file_count,
            "generated_by": row.generated_by,
            "generated_at": _iso(row.generated_at),
            "generation_error": row.generation_error,
            "verified_by": row.verified_by,
            "verified_at": _iso(row.verified_at),
            "verification_outcome": row.verification_outcome,
            "verification_detail": row.verification_detail,
            "expires_at": _iso(row.expires_at),
            "review_at": _iso(row.review_at),
            "version": int(row.version or 1),
            "idempotency_key": row.idempotency_key,
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
            "metadata": dict(row.meta or {}),
            "delivery_claimed": False,
            "external_recipient_validated": False,
        }
    )


def _audit_to_dict(row: GovernanceAccessAuditORM) -> dict[str, Any]:
    return redact_structure(
        {
            "event_id": row.id,
            "event_type": row.event_type,
            "actor_id": row.actor_id,
            "actor_role": row.actor_role,
            "target_type": row.target_type,
            "target_id": row.target_id,
            "case_id": row.case_id,
            "outcome": row.outcome,
            "reason": row.reason,
            "request_id": row.request_id,
            "occurred_at": row.occurred_at,
            "event_key": row.event_key,
            "event_hash": row.event_hash,
            "metadata": dict(row.meta or {}),
            "created_at": _iso(row.created_at),
        }
    )


class GovernanceRepository:
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------
    def ensure_default_policy(self) -> tuple[dict[str, Any], bool]:
        with self._session_factory() as session:
            existing = (
                session.query(GovernancePolicyVersionORM)
                .filter_by(policy_id=DEFAULT_POLICY_ID)
                .order_by(GovernancePolicyVersionORM.version.desc())
                .first()
            )
            if existing is not None:
                return _policy_to_dict(existing), True
            policy = default_policy_definition()
            now = utcnow()
            row = GovernancePolicyVersionORM(
                id=default_policy_row_id(),
                policy_id=policy.policy_id,
                version=policy.version,
                name=policy.name,
                state=policy.state,
                case_type=policy.case_type,
                evidence_category=policy.evidence_category,
                retention_days=policy.retention_days,
                review_interval_days=policy.review_interval_days,
                required_approval_level=policy.required_approval_level,
                export_allowed=policy.export_allowed,
                export_requires_approval=policy.export_requires_approval,
                allow_evidence_bytes=policy.allow_evidence_bytes,
                export_expiry_days=policy.export_expiry_days,
                export_review_days=policy.export_review_days,
                legal_hold_eligible=policy.legal_hold_eligible,
                disposition_review_required=policy.disposition_review_required,
                actor_id=policy.actor_id,
                actor_role=policy.actor_role,
                reason=policy.reason,
                idempotency_key=None,
                created_at=now,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _policy_to_dict(row), False

    def create_policy_version(
        self,
        policy: PolicyDefinition,
        *,
        expected_version: int | None = None,
    ) -> tuple[dict[str, Any], bool]:
        with self._session_factory() as session:
            if policy.idempotency_key:
                existing = (
                    session.query(GovernancePolicyVersionORM)
                    .filter_by(idempotency_key=policy.idempotency_key)
                    .one_or_none()
                )
                if existing is not None:
                    if existing.policy_id != policy.policy_id:
                        raise IdempotencyConflictError(
                            "idempotency key was already used for a different policy"
                        )
                    return _policy_to_dict(existing), True
            latest = (
                session.query(GovernancePolicyVersionORM)
                .filter_by(policy_id=policy.policy_id)
                .order_by(GovernancePolicyVersionORM.version.desc())
                .first()
            )
            if latest is not None:
                if expected_version is not None and int(latest.version) != int(expected_version):
                    raise PolicyVersionConflictError(
                        policy.policy_id, int(expected_version), int(latest.version)
                    )
                if latest.state == PolicyState.ARCHIVED.value:
                    raise PolicyValidationError("archived policies cannot receive new versions")
                if policy.state != latest.state:
                    validate_state_transition(latest.state, policy.state)
                next_version = int(latest.version) + 1
            else:
                next_version = 1
            candidate = PolicyDefinition(
                policy_id=policy.policy_id,
                version=next_version,
                name=policy.name,
                state=policy.state,
                case_type=policy.case_type,
                evidence_category=policy.evidence_category,
                retention_days=policy.retention_days,
                review_interval_days=policy.review_interval_days,
                required_approval_level=policy.required_approval_level,
                export_allowed=policy.export_allowed,
                export_requires_approval=policy.export_requires_approval,
                allow_evidence_bytes=policy.allow_evidence_bytes,
                export_expiry_days=policy.export_expiry_days,
                export_review_days=policy.export_review_days,
                legal_hold_eligible=policy.legal_hold_eligible,
                disposition_review_required=policy.disposition_review_required,
                actor_id=policy.actor_id,
                actor_role=policy.actor_role,
                reason=policy.reason,
                idempotency_key=policy.idempotency_key,
                created_at=utcnow(),
            )
            validate_policy(candidate)
            row = GovernancePolicyVersionORM(
                id=_new_id(),
                policy_id=candidate.policy_id,
                version=candidate.version,
                name=candidate.name,
                state=candidate.state,
                case_type=candidate.case_type,
                evidence_category=candidate.evidence_category,
                retention_days=candidate.retention_days,
                review_interval_days=candidate.review_interval_days,
                required_approval_level=candidate.required_approval_level,
                export_allowed=candidate.export_allowed,
                export_requires_approval=candidate.export_requires_approval,
                allow_evidence_bytes=candidate.allow_evidence_bytes,
                export_expiry_days=candidate.export_expiry_days,
                export_review_days=candidate.export_review_days,
                legal_hold_eligible=candidate.legal_hold_eligible,
                disposition_review_required=candidate.disposition_review_required,
                actor_id=candidate.actor_id,
                actor_role=candidate.actor_role,
                reason=candidate.reason,
                idempotency_key=candidate.idempotency_key,
                created_at=candidate.created_at,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _policy_to_dict(row), False

    def get_policy(self, policy_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernancePolicyVersionORM)
                .filter_by(policy_id=str(policy_id))
                .order_by(GovernancePolicyVersionORM.version.desc())
                .first()
            )
            return _policy_to_dict(row) if row is not None else None

    def get_policy_version(self, policy_id: str, version: int) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernancePolicyVersionORM)
                .filter_by(policy_id=str(policy_id), version=int(version))
                .one_or_none()
            )
            return _policy_to_dict(row) if row is not None else None

    def list_policies(self, *, page: int = 1, page_size: int = 20) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            rows = (
                session.query(GovernancePolicyVersionORM)
                .order_by(
                    GovernancePolicyVersionORM.policy_id.asc(),
                    GovernancePolicyVersionORM.version.desc(),
                )
                .all()
            )
            newest: dict[str, GovernancePolicyVersionORM] = {}
            for row in rows:
                newest.setdefault(row.policy_id, row)
            items = [_policy_to_dict(newest[key]) for key in sorted(newest)]
            total = len(items)
            start = (page - 1) * page_size
            return items[start : start + page_size], total

    def list_policy_versions(
        self, policy_id: str, *, page: int = 1, page_size: int = 20
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernancePolicyVersionORM).filter_by(policy_id=str(policy_id))
            total = int(query.count())
            rows = (
                query.order_by(GovernancePolicyVersionORM.version.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_policy_to_dict(row) for row in rows], total

    def latest_enabled_policies(self) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(GovernancePolicyVersionORM)
                .filter(GovernancePolicyVersionORM.state == PolicyState.ENABLED.value)
                .order_by(
                    GovernancePolicyVersionORM.policy_id.asc(),
                    GovernancePolicyVersionORM.version.desc(),
                )
                .all()
            )
            newest: dict[str, GovernancePolicyVersionORM] = {}
            for row in rows:
                newest.setdefault(row.policy_id, row)
            return [_policy_to_dict(newest[key]) for key in sorted(newest)]

    def count_policies(self) -> int:
        with self._session_factory() as session:
            return int(
                session.query(func.count(func.distinct(GovernancePolicyVersionORM.policy_id))).scalar() or 0
            )

    # ------------------------------------------------------------------
    # Retention evaluations
    # ------------------------------------------------------------------
    def create_evaluation(
        self,
        *,
        case_id: str,
        evaluation_kind: str,
        policy_id: str | None,
        policy_version: int | None,
        policy_snapshot: Mapping[str, Any],
        as_of: date,
        evaluated_at: datetime,
        retention_start: datetime | None,
        retention_deadline: datetime | None,
        next_review_at: datetime | None,
        governance_state: str,
        data_status: str,
        disposition_eligible: bool,
        integrity_status: str,
        verification_id: str | None,
        legal_hold_ids: Sequence[str],
        reasons: Sequence[str],
        created_by: str | None,
        request_id: str | None,
        reviewed_by: str | None = None,
        review_reason: str | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[dict[str, Any], bool]:
        with self._session_factory() as session:
            if idempotency_key:
                existing = (
                    session.query(GovernanceRetentionEvaluationORM)
                    .filter_by(idempotency_key=str(idempotency_key))
                    .one_or_none()
                )
                if existing is not None:
                    if existing.case_id != str(case_id):
                        raise IdempotencyConflictError(
                            "idempotency key was already used for a different case"
                        )
                    return _evaluation_to_dict(existing), True
            evaluation_version = (
                int(
                    session.query(func.count(GovernanceRetentionEvaluationORM.id))
                    .filter_by(case_id=str(case_id))
                    .scalar()
                    or 0
                )
                + 1
            )
            row = GovernanceRetentionEvaluationORM(
                id=_new_id(),
                case_id=str(case_id),
                evaluation_kind=str(evaluation_kind),
                evaluation_version=evaluation_version,
                policy_id=policy_id,
                policy_version=policy_version,
                policy_snapshot=dict(redact_structure(dict(policy_snapshot))),
                as_of=as_of,
                evaluated_at=evaluated_at,
                retention_start=retention_start,
                retention_deadline=retention_deadline,
                next_review_at=next_review_at,
                governance_state=str(governance_state),
                data_status=str(data_status),
                disposition_eligible=bool(disposition_eligible),
                integrity_status=str(integrity_status),
                verification_id=verification_id,
                legal_hold_ids=sorted(str(item) for item in legal_hold_ids),
                reasons=sorted(str(item) for item in reasons),
                reviewed_by=_safe_text(reviewed_by, 256) or None,
                review_reason=_safe_text(review_reason, 2048) or None,
                created_by=_safe_text(created_by, 256) or None,
                request_id=_safe_text(request_id, 128) or None,
                idempotency_key=idempotency_key,
                created_at=evaluated_at,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _evaluation_to_dict(row), False

    def get_evaluation(self, evaluation_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceRetentionEvaluationORM).filter_by(id=str(evaluation_id)).one_or_none()
            )
            return _evaluation_to_dict(row) if row is not None else None

    def latest_evaluation(self, case_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceRetentionEvaluationORM)
                .filter_by(case_id=str(case_id))
                .order_by(
                    GovernanceRetentionEvaluationORM.created_at.desc(),
                    GovernanceRetentionEvaluationORM.evaluation_version.desc(),
                )
                .first()
            )
            return _evaluation_to_dict(row) if row is not None else None

    def list_evaluations(
        self, case_id: str, *, page: int = 1, page_size: int = 20
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernanceRetentionEvaluationORM).filter_by(case_id=str(case_id))
            total = int(query.count())
            rows = (
                query.order_by(
                    GovernanceRetentionEvaluationORM.created_at.desc(),
                    GovernanceRetentionEvaluationORM.evaluation_version.desc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_evaluation_to_dict(row) for row in rows], total

    def evaluation_state_counts(self) -> dict[str, int]:
        with self._session_factory() as session:
            rows = (
                session.query(
                    GovernanceRetentionEvaluationORM.governance_state,
                    func.count(GovernanceRetentionEvaluationORM.id),
                )
                .group_by(GovernanceRetentionEvaluationORM.governance_state)
                .all()
            )
            return {str(state): int(count) for state, count in rows}

    # ------------------------------------------------------------------
    # Read helpers used by retention evaluation
    # ------------------------------------------------------------------
    def get_hold(self, hold_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.query(GovernanceLegalHoldORM).filter_by(id=str(hold_id)).one_or_none()
            return _hold_to_dict(row) if row is not None else None

    def list_holds(
        self,
        *,
        case_id: str | None = None,
        statuses: Sequence[str] | None = None,
        evidence_reference_id: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernanceLegalHoldORM)
            if case_id:
                query = query.filter_by(case_id=str(case_id))
            if statuses:
                query = query.filter(
                    GovernanceLegalHoldORM.status.in_([str(item).upper() for item in statuses])
                )
            if evidence_reference_id:
                query = query.filter_by(evidence_reference_id=str(evidence_reference_id))
            total = int(query.count())
            rows = (
                query.order_by(
                    GovernanceLegalHoldORM.requested_at.desc(),
                    GovernanceLegalHoldORM.hold_number.desc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_hold_to_dict(row) for row in rows], total

    def list_hold_events(self, hold_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceLegalHoldEventORM)
                .filter_by(hold_id=str(hold_id))
                .order_by(
                    GovernanceLegalHoldEventORM.occurred_at.asc(),
                    GovernanceLegalHoldEventORM.created_at.asc(),
                )
                .all()
            )
            return [_hold_event_to_dict(row) for row in rows]

    def latest_disposition(self, case_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceDispositionRequestORM)
                .filter_by(case_id=str(case_id))
                .order_by(
                    GovernanceDispositionRequestORM.requested_at.desc(),
                    GovernanceDispositionRequestORM.created_at.desc(),
                )
                .first()
            )
            return _disposition_to_dict(row) if row is not None else None

    def get_disposition(self, disposition_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceDispositionRequestORM).filter_by(id=str(disposition_id)).one_or_none()
            )
            return _disposition_to_dict(row) if row is not None else None

    def list_dispositions(
        self,
        *,
        case_id: str | None = None,
        statuses: Sequence[str] | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernanceDispositionRequestORM)
            if case_id:
                query = query.filter_by(case_id=str(case_id))
            if statuses:
                query = query.filter(
                    GovernanceDispositionRequestORM.status.in_([str(item).upper() for item in statuses])
                )
            total = int(query.count())
            rows = (
                query.order_by(
                    GovernanceDispositionRequestORM.requested_at.desc(),
                    GovernanceDispositionRequestORM.request_number.desc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_disposition_to_dict(row) for row in rows], total

    def list_disposition_decisions(self, disposition_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceDispositionDecisionORM)
                .filter_by(disposition_id=str(disposition_id))
                .order_by(
                    GovernanceDispositionDecisionORM.occurred_at.asc(),
                    GovernanceDispositionDecisionORM.created_at.asc(),
                )
                .all()
            )
            return [_disposition_decision_to_dict(row) for row in rows]

    def find_disposition_decision_by_key(self, idempotency_key: str) -> dict[str, Any] | None:
        """Return the stored decision for an idempotency key, if any.

        This lookup lets the service replay a completed decision even after the
        disposition has reached a terminal status.
        """
        with self._session_factory() as session:
            row = (
                session.query(GovernanceDispositionDecisionORM)
                .filter_by(idempotency_key=str(idempotency_key))
                .one_or_none()
            )
            return _disposition_decision_to_dict(row) if row is not None else None

    def get_export_approval(self, approval_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.query(GovernanceExportApprovalORM).filter_by(id=str(approval_id)).one_or_none()
            return _export_approval_to_dict(row) if row is not None else None

    def list_export_approvals(
        self,
        *,
        case_id: str | None = None,
        statuses: Sequence[str] | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernanceExportApprovalORM)
            if case_id:
                query = query.filter_by(case_id=str(case_id))
            if statuses:
                query = query.filter(
                    GovernanceExportApprovalORM.status.in_([str(item).upper() for item in statuses])
                )
            total = int(query.count())
            rows = (
                query.order_by(
                    GovernanceExportApprovalORM.requested_at.desc(),
                    GovernanceExportApprovalORM.request_number.desc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_export_approval_to_dict(row) for row in rows], total

    # ------------------------------------------------------------------
    # Legal holds
    # ------------------------------------------------------------------
    def create_hold(
        self,
        *,
        case_id: str,
        evidence_reference_id: str | None,
        status: str,
        scope: str,
        reason: str,
        requested_by: str,
        requested_role: str,
        approved_by: str | None = None,
        approved_at: datetime | None = None,
        approval_reason: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
        with self._session_factory() as session:
            if idempotency_key:
                existing = (
                    session.query(GovernanceLegalHoldORM)
                    .filter_by(idempotency_key=str(idempotency_key))
                    .one_or_none()
                )
                if existing is not None:
                    if existing.case_id != str(case_id):
                        raise IdempotencyConflictError(
                            "idempotency key was already used for a different legal hold"
                        )
                    events = (
                        session.query(GovernanceLegalHoldEventORM)
                        .filter_by(hold_id=existing.id)
                        .order_by(GovernanceLegalHoldEventORM.occurred_at.asc())
                        .all()
                    )
                    return (
                        _hold_to_dict(existing),
                        [_hold_event_to_dict(event) for event in events],
                        True,
                    )
            now = utcnow()
            hold_id = _new_id()
            row = GovernanceLegalHoldORM(
                id=hold_id,
                hold_number=f"HOLD-{now:%Y%m%d}-{uuid.uuid4().hex[:8].upper()}",
                case_id=str(case_id),
                evidence_reference_id=evidence_reference_id,
                status=str(status).upper(),
                scope=_safe_text(scope, 2048),
                reason=_safe_text(reason, 2048),
                requested_by=_safe_text(requested_by, 256),
                requested_role=_safe_text(requested_role, 16).upper(),
                requested_at=now,
                approved_by=_safe_text(approved_by, 256) or None,
                approved_at=approved_at,
                approval_reason=_safe_text(approval_reason, 2048) or None,
                version=1,
                idempotency_key=idempotency_key,
                created_at=now,
                updated_at=now,
                meta=dict(redact_structure(dict(metadata or {}))),
            )
            session.add(row)
            event = GovernanceLegalHoldEventORM(
                id=_new_id(),
                hold_id=hold_id,
                event_type="CREATED",
                actor_id=_safe_text(requested_by, 256),
                actor_role=_safe_text(requested_role, 16).upper(),
                reason=_safe_text(reason, 2048),
                from_status=None,
                to_status=str(status).upper(),
                occurred_at=now,
                idempotency_key=f"hold:{hold_id}:created",
                meta=dict(redact_structure(dict(metadata or {}))),
                created_at=now,
            )
            session.add(event)
            session.commit()
            session.refresh(row)
            session.refresh(event)
            return _hold_to_dict(row), [_hold_event_to_dict(event)], False

    def transition_hold(
        self,
        hold_id: str,
        *,
        target_status: str,
        expected_version: int | None,
        actor_id: str,
        actor_role: str,
        reason: str,
        event_type: str,
        idempotency_key: str | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
        with self._session_factory() as session:
            row = session.query(GovernanceLegalHoldORM).filter_by(id=str(hold_id)).one_or_none()
            if row is None:
                raise LegalHoldNotFoundError(hold_id)
            if idempotency_key:
                existing_event = (
                    session.query(GovernanceLegalHoldEventORM)
                    .filter_by(idempotency_key=str(idempotency_key))
                    .one_or_none()
                )
                if existing_event is not None:
                    if existing_event.hold_id != row.id:
                        raise IdempotencyConflictError(
                            "idempotency key was already used for a different legal hold action"
                        )
                    events = (
                        session.query(GovernanceLegalHoldEventORM)
                        .filter_by(hold_id=row.id)
                        .order_by(GovernanceLegalHoldEventORM.occurred_at.asc())
                        .all()
                    )
                    return (
                        _hold_to_dict(row),
                        [_hold_event_to_dict(event) for event in events],
                        True,
                    )
            if expected_version is not None and int(row.version) != int(expected_version):
                raise LegalHoldVersionConflictError(hold_id, int(expected_version), int(row.version))
            target = str(target_status).upper()
            current = str(row.status).upper()
            if target not in HOLD_TRANSITIONS.get(current, frozenset()):
                raise LegalHoldStateError(f"invalid legal hold transition: {current} -> {target}")
            now = utcnow()
            if target == LegalHoldStatus.ACTIVE.value:
                row.approved_by = _safe_text(actor_id, 256)
                row.approved_at = now
                row.approval_reason = _safe_text(reason, 2048)
            elif target == LegalHoldStatus.REJECTED.value:
                row.rejected_by = _safe_text(actor_id, 256)
                row.rejected_at = now
                row.rejection_reason = _safe_text(reason, 2048)
            elif target == LegalHoldStatus.RELEASED.value:
                row.released_by = _safe_text(actor_id, 256)
                row.released_at = now
                row.release_reason = _safe_text(reason, 2048)
            elif target == LegalHoldStatus.WITHDRAWN.value:
                row.withdrawn_by = _safe_text(actor_id, 256)
                row.withdrawn_at = now
                row.withdrawal_reason = _safe_text(reason, 2048)
            row.status = target
            row.version = int(row.version) + 1
            row.updated_at = now
            event = GovernanceLegalHoldEventORM(
                id=_new_id(),
                hold_id=row.id,
                event_type=str(event_type).upper(),
                actor_id=_safe_text(actor_id, 256),
                actor_role=_safe_text(actor_role, 16).upper(),
                reason=_safe_text(reason, 2048),
                from_status=current,
                to_status=target,
                occurred_at=now,
                idempotency_key=idempotency_key,
                meta={},
                created_at=now,
            )
            session.add(event)
            session.commit()
            session.refresh(row)
            events = (
                session.query(GovernanceLegalHoldEventORM)
                .filter_by(hold_id=row.id)
                .order_by(
                    GovernanceLegalHoldEventORM.occurred_at.asc(),
                    GovernanceLegalHoldEventORM.created_at.asc(),
                )
                .all()
            )
            return _hold_to_dict(row), [_hold_event_to_dict(item) for item in events], False

    # ------------------------------------------------------------------
    # Disposition review
    # ------------------------------------------------------------------
    def create_disposition(
        self,
        *,
        case_id: str,
        evaluation_id: str | None,
        status: str,
        justification: str,
        requested_by: str,
        requested_role: str,
        policy_id: str | None,
        policy_version: int | None,
        required_approval_level: str,
        blocked_reason_codes: Sequence[str],
        open_key: str | None,
        metadata: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[dict[str, Any], bool]:
        with self._session_factory() as session:
            if idempotency_key:
                existing = (
                    session.query(GovernanceDispositionRequestORM)
                    .filter_by(idempotency_key=str(idempotency_key))
                    .one_or_none()
                )
                if existing is not None:
                    if existing.case_id != str(case_id):
                        raise IdempotencyConflictError(
                            "idempotency key was already used for a different disposition request"
                        )
                    return _disposition_to_dict(existing), True
            if open_key:
                open_row = (
                    session.query(GovernanceDispositionRequestORM)
                    .filter_by(open_key=str(open_key))
                    .one_or_none()
                )
                if open_row is not None:
                    raise DispositionStateError("an open disposition review already exists for this case")
            now = utcnow()
            row = GovernanceDispositionRequestORM(
                id=_new_id(),
                request_number=f"DISP-{now:%Y%m%d}-{uuid.uuid4().hex[:8].upper()}",
                case_id=str(case_id),
                evaluation_id=evaluation_id,
                status=str(status).upper(),
                justification=_safe_text(justification, 4096),
                requested_by=_safe_text(requested_by, 256),
                requested_role=_safe_text(requested_role, 16).upper(),
                requested_at=now,
                policy_id=policy_id,
                policy_version=policy_version,
                required_approval_level=str(required_approval_level).upper(),
                approval_count=0,
                blocked_reason_codes=sorted(str(item) for item in blocked_reason_codes),
                open_key=open_key,
                version=1,
                idempotency_key=idempotency_key,
                created_at=now,
                updated_at=now,
                meta=dict(redact_structure(dict(metadata or {}))),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _disposition_to_dict(row), False

    def transition_disposition(
        self,
        disposition_id: str,
        *,
        decision: str,
        target_status: str,
        expected_version: int | None,
        actor_id: str,
        actor_role: str,
        reason: str,
        approval_count: int,
        reviewer_id: str | None,
        decision_reason: str,
        blocked_reason_codes: Sequence[str],
        open_key: str | None,
        idempotency_key: str | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceDispositionRequestORM).filter_by(id=str(disposition_id)).one_or_none()
            )
            if row is None:
                raise DispositionNotFoundError(disposition_id)
            if idempotency_key:
                existing_decision = (
                    session.query(GovernanceDispositionDecisionORM)
                    .filter_by(idempotency_key=str(idempotency_key))
                    .one_or_none()
                )
                if existing_decision is not None:
                    if existing_decision.disposition_id != row.id:
                        raise IdempotencyConflictError(
                            "idempotency key was already used for a different disposition decision"
                        )
                    decisions = (
                        session.query(GovernanceDispositionDecisionORM)
                        .filter_by(disposition_id=row.id)
                        .order_by(GovernanceDispositionDecisionORM.occurred_at.asc())
                        .all()
                    )
                    return (
                        _disposition_to_dict(row),
                        [_disposition_decision_to_dict(item) for item in decisions],
                        True,
                    )
            if expected_version is not None and int(row.version) != int(expected_version):
                raise DispositionVersionConflictError(disposition_id, int(expected_version), int(row.version))
            target = str(target_status).upper()
            current = str(row.status).upper()
            if target not in DISPOSITION_TRANSITIONS.get(current, frozenset()):
                raise DispositionStateError(f"invalid disposition transition: {current} -> {target}")
            now = utcnow()
            row.status = target
            row.approval_count = max(0, int(approval_count))
            row.reviewer_id = _safe_text(reviewer_id, 256) or None
            row.reviewed_at = now
            row.decision_reason = _safe_text(decision_reason, 2048)
            row.blocked_reason_codes = sorted(str(item) for item in blocked_reason_codes)
            row.open_key = open_key
            row.version = int(row.version) + 1
            row.updated_at = now
            decision_row = GovernanceDispositionDecisionORM(
                id=_new_id(),
                disposition_id=row.id,
                decision=str(decision).upper(),
                actor_id=_safe_text(actor_id, 256),
                actor_role=_safe_text(actor_role, 16).upper(),
                reason=_safe_text(reason, 2048),
                from_status=current,
                to_status=target,
                occurred_at=now,
                idempotency_key=idempotency_key,
                meta={},
                created_at=now,
            )
            session.add(decision_row)
            session.commit()
            session.refresh(row)
            decisions = (
                session.query(GovernanceDispositionDecisionORM)
                .filter_by(disposition_id=row.id)
                .order_by(
                    GovernanceDispositionDecisionORM.occurred_at.asc(),
                    GovernanceDispositionDecisionORM.created_at.asc(),
                )
                .all()
            )
            return (
                _disposition_to_dict(row),
                [_disposition_decision_to_dict(item) for item in decisions],
                False,
            )

    # ------------------------------------------------------------------
    # Export approvals
    # ------------------------------------------------------------------
    def create_export_approval(
        self,
        *,
        case_id: str,
        status: str,
        reason: str,
        requested_by: str,
        requested_role: str,
        policy_id: str | None,
        policy_version: int | None,
        include_evidence_bytes: bool,
        required_approval_level: str,
        approved_by: str | None = None,
        approved_at: datetime | None = None,
        approval_reason: str | None = None,
        expires_at: datetime | None = None,
        review_at: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[dict[str, Any], bool]:
        with self._session_factory() as session:
            if idempotency_key:
                existing = (
                    session.query(GovernanceExportApprovalORM)
                    .filter_by(idempotency_key=str(idempotency_key))
                    .one_or_none()
                )
                if existing is not None:
                    if existing.case_id != str(case_id):
                        raise IdempotencyConflictError(
                            "idempotency key was already used for a different export approval"
                        )
                    return _export_approval_to_dict(existing), True
            now = utcnow()
            row = GovernanceExportApprovalORM(
                id=_new_id(),
                request_number=f"EXP-{now:%Y%m%d}-{uuid.uuid4().hex[:8].upper()}",
                case_id=str(case_id),
                status=str(status).upper(),
                reason=_safe_text(reason, 2048),
                requested_by=_safe_text(requested_by, 256),
                requested_role=_safe_text(requested_role, 16).upper(),
                requested_at=now,
                policy_id=policy_id,
                policy_version=policy_version,
                include_evidence_bytes=bool(include_evidence_bytes),
                required_approval_level=str(required_approval_level).upper(),
                approved_by=_safe_text(approved_by, 256) or None,
                approved_at=approved_at,
                approval_reason=_safe_text(approval_reason, 2048) or None,
                verification_outcome="NOT_RUN",
                verification_detail="",
                expires_at=expires_at,
                review_at=review_at,
                version=1,
                idempotency_key=idempotency_key,
                created_at=now,
                updated_at=now,
                meta=dict(redact_structure(dict(metadata or {}))),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _export_approval_to_dict(row), False

    def transition_export_approval(
        self,
        approval_id: str,
        *,
        target_status: str,
        expected_version: int | None,
        actor_id: str,
        actor_role: str,
        reason: str,
        fields: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[dict[str, Any], bool]:
        with self._session_factory() as session:
            row = session.query(GovernanceExportApprovalORM).filter_by(id=str(approval_id)).one_or_none()
            if row is None:
                raise ExportApprovalNotFoundError(approval_id)
            meta = dict(row.meta or {})
            if idempotency_key and meta.get("last_transition_key") == str(idempotency_key):
                return _export_approval_to_dict(row), True
            if expected_version is not None and int(row.version) != int(expected_version):
                raise ExportApprovalVersionConflictError(approval_id, int(expected_version), int(row.version))
            target = str(target_status).upper()
            current = str(row.status).upper()
            if target not in EXPORT_TRANSITIONS.get(current, frozenset()):
                raise ExportApprovalStateError(f"invalid export approval transition: {current} -> {target}")
            now = utcnow()
            allowed_fields = {
                "approved_by",
                "approved_at",
                "approval_reason",
                "rejected_by",
                "rejected_at",
                "rejection_reason",
                "withdrawn_by",
                "withdrawn_at",
                "withdrawal_reason",
                "export_id",
                "export_sha256",
                "manifest_digest",
                "root_digest",
                "filename",
                "size_bytes",
                "file_count",
                "generated_by",
                "generated_at",
                "generation_error",
                "verified_by",
                "verified_at",
                "verification_outcome",
                "verification_detail",
                "expires_at",
                "review_at",
            }
            for key, value in dict(fields or {}).items():
                if key not in allowed_fields:
                    continue
                setattr(row, key, value)
            row.status = target
            row.version = int(row.version) + 1
            row.updated_at = now
            if idempotency_key:
                meta["last_transition_key"] = str(idempotency_key)
                meta["last_transition_actor"] = _safe_text(actor_id, 256)
                meta["last_transition_role"] = _safe_text(actor_role, 16).upper()
                meta["last_transition_reason"] = _safe_text(reason, 2048)
                meta["last_transition_at"] = now.isoformat()
            row.meta = dict(redact_structure(meta))
            session.commit()
            session.refresh(row)
            return _export_approval_to_dict(row), False

    # ------------------------------------------------------------------
    # Governance aggregates used by reports
    # ------------------------------------------------------------------
    def hold_status_counts(self) -> dict[str, int]:
        with self._session_factory() as session:
            rows = (
                session.query(
                    GovernanceLegalHoldORM.status,
                    func.count(GovernanceLegalHoldORM.id),
                )
                .group_by(GovernanceLegalHoldORM.status)
                .all()
            )
            return {str(status): int(count) for status, count in rows}

    def disposition_status_counts(self) -> dict[str, int]:
        with self._session_factory() as session:
            rows = (
                session.query(
                    GovernanceDispositionRequestORM.status,
                    func.count(GovernanceDispositionRequestORM.id),
                )
                .group_by(GovernanceDispositionRequestORM.status)
                .all()
            )
            return {str(status): int(count) for status, count in rows}

    def export_status_counts(self) -> dict[str, int]:
        with self._session_factory() as session:
            rows = (
                session.query(
                    GovernanceExportApprovalORM.status,
                    func.count(GovernanceExportApprovalORM.id),
                )
                .group_by(GovernanceExportApprovalORM.status)
                .all()
            )
            return {str(status): int(count) for status, count in rows}

    def latest_evaluations(self, *, limit: int = 500) -> list[dict[str, Any]]:
        limit = max(1, min(5000, int(limit)))
        with self._session_factory() as session:
            newest = (
                session.query(
                    GovernanceRetentionEvaluationORM.case_id.label("case_id"),
                    func.max(GovernanceRetentionEvaluationORM.evaluation_version).label("max_version"),
                )
                .group_by(GovernanceRetentionEvaluationORM.case_id)
                .subquery()
            )
            rows = (
                session.query(GovernanceRetentionEvaluationORM)
                .join(
                    newest,
                    and_(
                        GovernanceRetentionEvaluationORM.case_id == newest.c.case_id,
                        GovernanceRetentionEvaluationORM.evaluation_version == newest.c.max_version,
                    ),
                )
                .order_by(
                    GovernanceRetentionEvaluationORM.evaluated_at.desc(),
                    GovernanceRetentionEvaluationORM.case_id.asc(),
                )
                .limit(limit)
                .all()
            )
            return [_evaluation_to_dict(row) for row in rows]

    def list_blocking_holds(self, *, limit: int = 500) -> list[dict[str, Any]]:
        limit = max(1, min(5000, int(limit)))
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceLegalHoldORM)
                .filter(
                    GovernanceLegalHoldORM.status.in_(
                        [LegalHoldStatus.PENDING_APPROVAL.value, LegalHoldStatus.ACTIVE.value]
                    )
                )
                .order_by(GovernanceLegalHoldORM.requested_at.asc())
                .limit(limit)
                .all()
            )
            return [_hold_to_dict(row) for row in rows]

    def list_open_dispositions(self, *, limit: int = 500) -> list[dict[str, Any]]:
        limit = max(1, min(5000, int(limit)))
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceDispositionRequestORM)
                .filter(GovernanceDispositionRequestORM.status.in_(["REVIEW_REQUIRED", "APPROVAL_PENDING"]))
                .order_by(GovernanceDispositionRequestORM.requested_at.asc())
                .limit(limit)
                .all()
            )
            return [_disposition_to_dict(row) for row in rows]

    def list_export_approvals_all(self, *, limit: int = 500) -> list[dict[str, Any]]:
        limit = max(1, min(5000, int(limit)))
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceExportApprovalORM)
                .order_by(GovernanceExportApprovalORM.requested_at.desc())
                .limit(limit)
                .all()
            )
            return [_export_approval_to_dict(row) for row in rows]

    def oldest_blocking_hold_at(self) -> str | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceLegalHoldORM)
                .filter(
                    GovernanceLegalHoldORM.status.in_(
                        [LegalHoldStatus.PENDING_APPROVAL.value, LegalHoldStatus.ACTIVE.value]
                    )
                )
                .order_by(GovernanceLegalHoldORM.requested_at.asc())
                .first()
            )
            return _iso(row.requested_at) if row is not None else None

    def audit_events(self, *, limit: int = 500) -> list[dict[str, Any]]:
        limit = max(1, min(5000, int(limit)))
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceAccessAuditORM)
                .order_by(GovernanceAccessAuditORM.created_at.asc())
                .limit(limit)
                .all()
            )
            return [_audit_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Access audit (append-only)
    # ------------------------------------------------------------------
    def record_access_audit(
        self,
        *,
        event_type: str,
        actor_id: str,
        actor_role: str,
        target_type: str,
        target_id: str,
        case_id: str | None,
        outcome: str,
        reason: str = "",
        request_id: str | None = None,
        occurred_at: str | None = None,
        event_key: str | None = None,
        event_hash: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> tuple[dict[str, Any], bool]:
        with self._session_factory() as session:
            if event_key:
                existing = (
                    session.query(GovernanceAccessAuditORM).filter_by(event_key=str(event_key)).one_or_none()
                )
                if existing is not None:
                    return _audit_to_dict(existing), True
            row = GovernanceAccessAuditORM(
                id=_new_id(),
                event_type=str(event_type),
                actor_id=_safe_text(actor_id, 256) or "SYSTEM",
                actor_role=_safe_text(actor_role, 16) or "SYSTEM",
                target_type=_safe_text(target_type, 32),
                target_id=_safe_text(target_id, 128),
                case_id=_safe_text(case_id, 36) or None,
                outcome=str(outcome),
                reason=_safe_text(reason, 2048),
                request_id=_safe_text(request_id, 128) or None,
                occurred_at=str(occurred_at or ""),
                event_key=event_key,
                event_hash=str(event_hash),
                meta=dict(redact_structure(dict(metadata or {}))),
                created_at=utcnow(),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _audit_to_dict(row), False

    def get_access_audit(self, event_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.query(GovernanceAccessAuditORM).filter_by(id=str(event_id)).one_or_none()
            if row is None:
                raise GovernanceAuditNotFoundError(event_id)
            return _audit_to_dict(row)

    def list_access_audit(
        self,
        *,
        event_type: str | None = None,
        actor_id: str | None = None,
        case_id: str | None = None,
        outcome: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(200, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernanceAccessAuditORM)
            if event_type:
                query = query.filter_by(event_type=str(event_type).upper())
            if actor_id:
                query = query.filter_by(actor_id=str(actor_id))
            if case_id:
                query = query.filter_by(case_id=str(case_id))
            if outcome:
                query = query.filter_by(outcome=str(outcome).upper())
            if target_type:
                query = query.filter_by(target_type=str(target_type))
            if target_id:
                query = query.filter_by(target_id=str(target_id))
            total = int(query.count())
            rows = (
                query.order_by(
                    GovernanceAccessAuditORM.occurred_at.desc(),
                    GovernanceAccessAuditORM.created_at.desc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_audit_to_dict(row) for row in rows], total

    def access_audit_summary(self) -> dict[str, Any]:
        with self._session_factory() as session:
            total = int(session.query(func.count(GovernanceAccessAuditORM.id)).scalar() or 0)
            by_type = (
                session.query(
                    GovernanceAccessAuditORM.event_type,
                    func.count(GovernanceAccessAuditORM.id),
                )
                .group_by(GovernanceAccessAuditORM.event_type)
                .all()
            )
            by_outcome = (
                session.query(
                    GovernanceAccessAuditORM.outcome,
                    func.count(GovernanceAccessAuditORM.id),
                )
                .group_by(GovernanceAccessAuditORM.outcome)
                .all()
            )
            return {
                "total": total,
                "by_event_type": {str(key): int(count) for key, count in by_type},
                "by_outcome": {str(key): int(count) for key, count in by_outcome},
            }

    def count_audit_events(self) -> int:
        with self._session_factory() as session:
            return int(session.query(func.count(GovernanceAccessAuditORM.id)).scalar() or 0)


__all__ = ["GovernanceRepository"]
