"""Operational event history + delivery outbox ORM (V12).

``operational_events`` is the durable counterpart of V09's in-memory
unified events: one row per canonical event identity (idempotent upsert),
recording the latest known state. It does NOT store frames, detections,
tracks, or telemetry — meaningful normalized events only.

``event_outbox`` is the durable delivery intent behind cross-process
publication: event row + outbox row commit in one transaction, and a
managed publisher drains pending rows with bounded retries. Redis
remains notification transport, never storage.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.domain.common import utcnow
from backend.app.models.camera_orm import Base


class OperationalEventORM(Base):
    __tablename__ = "operational_events"

    # Canonical V09 unified event identity (same value linked from
    # incident_events.event_id), so incident links resolve to real rows.
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    camera_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source_domain: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    risk_score: Mapped[float] = mapped_column(Float(), nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint("camera_id", "source_domain", "source_event_id", name="uq_operational_event_source"),
        Index("ix_operational_events_domain_type", "source_domain", "event_type"),
    )


class EventOutboxORM(Base):
    __tablename__ = "event_outbox"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # Stable envelope event identity: UNIQUE prevents duplicate intents.
    event_id: Mapped[str] = mapped_column(String(256), nullable=False, unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
