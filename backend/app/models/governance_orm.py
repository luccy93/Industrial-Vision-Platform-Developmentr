"""Forensic governance ORM (V35).

All tables are additive and reference V34 records by identifier. No table uses
``ON DELETE CASCADE``: V35 must never remove evidence, cases, custody records,
or audit history. Mutable workflow rows (holds, dispositions, export approvals)
are protected against deletion by migration triggers; historical rows are
protected against both update and delete.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.domain.common import utcnow
from backend.app.models.camera_orm import Base


class GovernancePolicyVersionORM(Base):
    __tablename__ = "governance_policy_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="DRAFT", index=True)
    case_type: Mapped[str | None] = mapped_column(String(32), nullable=True, default=None, index=True)
    evidence_category: Mapped[str | None] = mapped_column(String(32), nullable=True, default=None, index=True)
    retention_days: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    review_interval_days: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    required_approval_level: Mapped[str] = mapped_column(
        String(24), nullable=False, default="SINGLE_REVIEWER"
    )
    export_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    export_requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    allow_evidence_bytes: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    export_expiry_days: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    export_review_days: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    legal_hold_eligible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    disposition_review_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False, default="SYSTEM")
    actor_role: Mapped[str] = mapped_column(String(16), nullable=False, default="SYSTEM")
    reason: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    idempotency_key: Mapped[str | None] = mapped_column(
        String(128), nullable=True, default=None, unique=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )

    __table_args__ = (
        UniqueConstraint("policy_id", "version", name="uq_governance_policy_version"),
        Index("ix_governance_policy_id_version", "policy_id", "version"),
    )


class GovernanceRetentionEvaluationORM(Base):
    __tablename__ = "governance_retention_evaluations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    evaluation_kind: Mapped[str] = mapped_column(String(16), nullable=False, default="EVALUATION")
    evaluation_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    policy_id: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    policy_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    as_of: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    retention_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    retention_deadline: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    next_review_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    governance_state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    data_status: Mapped[str] = mapped_column(String(16), nullable=False, default="OK")
    disposition_eligible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    integrity_status: Mapped[str] = mapped_column(String(16), nullable=False, default="NOT_RUN")
    verification_id: Mapped[str | None] = mapped_column(String(36), nullable=True, default=None)
    legal_hold_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    reasons: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    reviewed_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    review_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    created_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None)
    idempotency_key: Mapped[str | None] = mapped_column(
        String(128), nullable=True, default=None, unique=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_governance_eval_case_time", "case_id", "evaluated_at"),
        Index("ix_governance_eval_state_review", "governance_state", "next_review_at"),
        Index("ix_governance_eval_policy", "policy_id", "policy_version"),
    )


class GovernanceLegalHoldORM(Base):
    __tablename__ = "governance_legal_holds"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    hold_number: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    evidence_reference_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("forensic_evidence_references.id"), nullable=True, default=None, index=True
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING_APPROVAL", index=True)
    scope: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    reason: Mapped[str] = mapped_column(String(2048), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(256), nullable=False)
    requested_role: Mapped[str] = mapped_column(String(16), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    approved_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    approval_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    rejected_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    rejection_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    released_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    release_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    withdrawn_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    withdrawn_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    withdrawal_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    idempotency_key: Mapped[str | None] = mapped_column(
        String(128), nullable=True, default=None, unique=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_governance_holds_case_status", "case_id", "status"),
        Index("ix_governance_holds_status_requested", "status", "requested_at"),
    )


class GovernanceLegalHoldEventORM(Base):
    __tablename__ = "governance_legal_hold_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    hold_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("governance_legal_holds.id"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    from_status: Mapped[str | None] = mapped_column(String(24), nullable=True, default=None)
    to_status: Mapped[str] = mapped_column(String(24), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    idempotency_key: Mapped[str | None] = mapped_column(
        String(128), nullable=True, default=None, unique=True, index=True
    )
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (Index("ix_governance_hold_events_hold_time", "hold_id", "created_at"),)


class GovernanceDispositionRequestORM(Base):
    __tablename__ = "governance_disposition_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_number: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    evaluation_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("governance_retention_evaluations.id"), nullable=True, default=None
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    justification: Mapped[str] = mapped_column(String(4096), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(256), nullable=False)
    requested_role: Mapped[str] = mapped_column(String(16), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    policy_id: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    required_approval_level: Mapped[str] = mapped_column(
        String(24), nullable=False, default="SINGLE_REVIEWER"
    )
    approval_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reviewer_id: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    decision_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    blocked_reason_codes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    open_key: Mapped[str | None] = mapped_column(
        String(64), nullable=True, default=None, unique=True, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    idempotency_key: Mapped[str | None] = mapped_column(
        String(128), nullable=True, default=None, unique=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_governance_disposition_case_status", "case_id", "status"),
        Index("ix_governance_disposition_status_requested", "status", "requested_at"),
    )


class GovernanceDispositionDecisionORM(Base):
    __tablename__ = "governance_disposition_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    disposition_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("governance_disposition_requests.id"), nullable=False, index=True
    )
    decision: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    from_status: Mapped[str] = mapped_column(String(24), nullable=False)
    to_status: Mapped[str] = mapped_column(String(24), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    idempotency_key: Mapped[str | None] = mapped_column(
        String(128), nullable=True, default=None, unique=True, index=True
    )
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (
        UniqueConstraint(
            "disposition_id", "actor_id", "decision", name="uq_governance_disposition_actor_decision"
        ),
        Index("ix_governance_disposition_decisions_time", "disposition_id", "created_at"),
    )


class GovernanceExportApprovalORM(Base):
    __tablename__ = "governance_export_approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    request_number: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(2048), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(256), nullable=False)
    requested_role: Mapped[str] = mapped_column(String(16), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    policy_id: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    include_evidence_bytes: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    required_approval_level: Mapped[str] = mapped_column(
        String(24), nullable=False, default="SINGLE_REVIEWER"
    )
    approved_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    approval_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    rejected_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    rejection_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    withdrawn_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    withdrawn_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    withdrawal_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    export_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("forensic_exports.id"), nullable=True, default=None, unique=True, index=True
    )
    export_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)
    manifest_digest: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)
    root_digest: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)
    filename: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    file_count: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    generated_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    generation_error: Mapped[str | None] = mapped_column(String(1024), nullable=True, default=None)
    verified_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    verification_outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="NOT_RUN")
    verification_detail: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None, index=True
    )
    review_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    idempotency_key: Mapped[str | None] = mapped_column(
        String(128), nullable=True, default=None, unique=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_governance_export_case_status", "case_id", "status"),
        Index("ix_governance_export_status_requested", "status", "requested_at"),
    )


class GovernanceAccessAuditORM(Base):
    __tablename__ = "governance_access_audit"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    actor_role: Mapped[str] = mapped_column(String(16), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, default=None, index=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None, index=True)
    occurred_at: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    event_key: Mapped[str | None] = mapped_column(
        String(128), nullable=True, default=None, unique=True, index=True
    )
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )

    __table_args__ = (
        Index("ix_governance_audit_target", "target_type", "target_id"),
        Index("ix_governance_audit_occurred", "occurred_at"),
    )


__all__ = [
    "GovernanceAccessAuditORM",
    "GovernanceDispositionDecisionORM",
    "GovernanceDispositionRequestORM",
    "GovernanceExportApprovalORM",
    "GovernanceLegalHoldEventORM",
    "GovernanceLegalHoldORM",
    "GovernancePolicyVersionORM",
    "GovernanceRetentionEvaluationORM",
]
