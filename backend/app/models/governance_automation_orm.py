"""Governance automation ORM (V36).

Four additive tables hold schedule configuration, job lifecycle, append-only
job events, and append-only compliance snapshots. No table uses
``ON DELETE CASCADE``: automation must never remove evidence, cases, custody
records, governance records, or audit history. Job events and snapshots are
protected against update and delete by migration triggers; schedules and jobs
are protected against deletion while remaining mutable for lifecycle updates.
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


class GovernanceJobScheduleORM(Base):
    __tablename__ = "governance_job_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    job_type: Mapped[str] = mapped_column(String(48), nullable=False, unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=1440)
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    config_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_slot: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None)
    last_idempotency_key: Mapped[str | None] = mapped_column(String(200), nullable=True, default=None)
    updated_by: Mapped[str] = mapped_column(String(256), nullable=False, default="SYSTEM")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (Index("ix_governance_schedule_enabled_type", "enabled", "job_type"),)


class GovernanceJobORM(Base):
    __tablename__ = "governance_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    job_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING", index=True)
    trigger: Mapped[str] = mapped_column(String(16), nullable=False, default="MANUAL")
    schedule_slot: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None)
    dedup_key: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    retry_of_job_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("governance_jobs.id"), nullable=True, default=None, index=True
    )
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    config_version: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    config_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    requested_by: Mapped[str] = mapped_column(String(256), nullable=False, default="SYSTEM")
    requested_role: Mapped[str] = mapped_column(String(16), nullable=False, default="SYSTEM")
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    cancel_requested_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)
    error_message: Mapped[str | None] = mapped_column(String(512), nullable=True, default=None)

    __table_args__ = (
        UniqueConstraint("job_type", "schedule_slot", name="uq_governance_job_slot"),
        UniqueConstraint("retry_of_job_id", "attempt", name="uq_governance_job_retry_attempt"),
        Index("ix_governance_job_status_available", "status", "available_at"),
        Index("ix_governance_job_type_created", "job_type", "created_at"),
        Index("ix_governance_job_lease_expires", "lease_expires_at"),
        Index("ix_governance_job_cancel_requested", "cancel_requested_at"),
    )


class GovernanceJobEventORM(Base):
    __tablename__ = "governance_job_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("governance_jobs.id"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    from_status: Mapped[str | None] = mapped_column(String(16), nullable=True, default=None)
    to_status: Mapped[str | None] = mapped_column(String(16), nullable=True, default=None)
    actor_id: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    actor_role: Mapped[str | None] = mapped_column(String(16), nullable=True, default=None)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )

    __table_args__ = (Index("ix_governance_job_event_job_time", "job_id", "created_at"),)


class GovernanceSnapshotORM(Base):
    __tablename__ = "governance_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    snapshot_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    as_of: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    generated_by: Mapped[str] = mapped_column(String(256), nullable=False, default="SYSTEM")
    job_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("governance_jobs.id"), nullable=True, default=None, index=True
    )
    trigger: Mapped[str] = mapped_column(String(16), nullable=False, default="MANUAL")
    dedup_key: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    row_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (Index("ix_governance_snapshot_type_generated", "snapshot_type", "generated_at"),)
