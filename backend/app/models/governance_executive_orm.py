"""Executive governance ORM (V38).

Three additive tables hold strategic actions, append-only action events, and
report metadata. Report payloads reuse the V36 ``governance_snapshots`` table
with the ``EXECUTIVE_*`` snapshot types. No table uses ``ON DELETE CASCADE``:
executive records must never remove evidence, cases, custody records,
governance records, automation records, intelligence records, snapshots, or
audit history.

Actions are mutable only for lifecycle and assignment updates. Action events
and report metadata are append-only and are protected by migration triggers.
Actions cannot be deleted.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
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


class GovernanceExecutiveActionORM(Base):
    __tablename__ = "governance_executive_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    recommendation_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("governance_recommendations.id"),
        nullable=False,
        index=True,
    )
    recommendation_rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    recommendation_severity: Mapped[str] = mapped_column(String(16), nullable=False)
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(String(4000), nullable=False, default="")
    owner_id: Mapped[str] = mapped_column(String(256), nullable=False)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="MEDIUM")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN", index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_by: Mapped[str] = mapped_column(String(256), nullable=False, default="SYSTEM")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    blocked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    outcome_summary: Mapped[str | None] = mapped_column(String(4000), nullable=True, default=None)
    block_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    cancel_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)

    __table_args__ = (
        Index("ix_governance_executive_action_status_due", "status", "due_at"),
        Index("ix_governance_executive_action_owner_status", "owner_id", "status"),
        Index("ix_governance_executive_action_recommendation", "recommendation_id", "status"),
    )


class GovernanceExecutiveActionEventORM(Base):
    __tablename__ = "governance_executive_action_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    action_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("governance_executive_actions.id"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    from_status: Mapped[str | None] = mapped_column(String(16), nullable=True, default=None)
    to_status: Mapped[str | None] = mapped_column(String(16), nullable=True, default=None)
    actor_id: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    actor_role: Mapped[str | None] = mapped_column(String(16), nullable=True, default=None)
    reason: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )

    __table_args__ = (Index("ix_governance_executive_action_event_time", "action_id", "created_at"),)


class GovernanceExecutiveReportORM(Base):
    __tablename__ = "governance_executive_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    report_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    report_format: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="GENERATED", index=True)
    window_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    generated_by: Mapped[str] = mapped_column(String(256), nullable=False, default="SYSTEM")
    snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("governance_snapshots.id"),
        nullable=False,
        index=True,
    )
    snapshot_type: Mapped[str] = mapped_column(String(32), nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    source_coverage: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    sections_available: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    sections_unavailable: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    report_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    row_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    redaction_applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_governance_executive_report_idempotency"),
        Index("ix_governance_executive_report_type_generated", "report_type", "generated_at"),
        Index("ix_governance_executive_report_window", "window_start", "window_end"),
    )


__all__ = [
    "GovernanceExecutiveActionEventORM",
    "GovernanceExecutiveActionORM",
    "GovernanceExecutiveReportORM",
]
