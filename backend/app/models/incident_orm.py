"""Incident ORM — operational incident records (PostgreSQL).

Unlike hot-path perception state, incidents are operational records and
persist here: the incident itself, linked intelligence events, the
append-only timeline, evidence metadata, assignment audit rows, and the
yearly numbering counters.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Index, Integer, String, text
from sqlalchemy.orm import Mapped, mapped_column

# Incident states that block automatic creation of a duplicate incident for
# the same source cluster. Shared with the Alembic migration so both schema
# paths enforce the identical predicate.
_OPEN_CLUSTER_WHERE = "status IN ('OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'MITIGATED')"

from backend.app.domain.common import utcnow
from backend.app.models.camera_orm import Base


class IncidentORM(Base):
    __tablename__ = "incidents"

    # Exception to the no-__table_args__ convention elsewhere: duplicate
    # active incidents for one source cluster must be impossible at the
    # database level on every backend (the application dedupe check alone
    # has a check-then-insert race). Rendered on SQLite via init_db and on
    # PostgreSQL via the Alembic migration alike.
    __table_args__ = (
        Index(
            "uq_incidents_open_cluster",
            "camera_id",
            "source_cluster_id",
            unique=True,
            sqlite_where=text(_OPEN_CLUSTER_WHERE),
            postgresql_where=text(_OPEN_CLUSTER_WHERE),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_number: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    camera_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(String(4096), nullable=False, default="")

    source_cluster_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    primary_event_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    priority: Mapped[str] = mapped_column(String(8), nullable=False, index=True, default="P4")

    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True, default="OPEN")
    category: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")

    source: Mapped[str] = mapped_column(String(16), nullable=False, default="AUTOMATIC")

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)

    assigned_to: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True, default=None)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)


class IncidentEventORM(Base):
    __tablename__ = "incident_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, default="UNKNOWN")
    source_domain: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)


class IncidentTimelineORM(Base):
    __tablename__ = "incident_timeline"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False, default="SYSTEM")
    message: Mapped[str] = mapped_column(String(4096), nullable=False, default="")
    previous_state: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)
    new_state: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)


class IncidentEvidenceORM(Base):
    __tablename__ = "incident_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    camera_id: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(16), nullable=False, default="OTHER")
    uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    frame_id: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None)
    description: Mapped[str] = mapped_column(String(4096), nullable=False, default="")
    checksum: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class IncidentAssignmentORM(Base):
    __tablename__ = "incident_assignments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    assignee: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    previous_assignee: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    actor_id: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False, default="SYSTEM")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)


class IncidentCounterORM(Base):
    """Yearly numbering counters. Incremented with a single atomic UPDATE so
    concurrent creators can never observe the same value (no count()+1)."""

    __tablename__ = "incident_counters"

    year: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
