"""Alerting ORM — rules, notifications, deliveries, transitions (V15).

PostgreSQL is the durable source of truth; Redis stays transport-only.
No credentials are stored here: SMTP/webhook secrets live exclusively
in environment configuration, never in rule rows, payloads, or logs.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.domain.common import utcnow
from backend.app.models.camera_orm import Base


class AlertRuleORM(Base):
    __tablename__ = "alert_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    domains: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    event_types: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    min_severity: Mapped[str | None] = mapped_column(String(16), nullable=True, default=None)
    min_priority: Mapped[str | None] = mapped_column(String(8), nullable=True, default=None)
    camera_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    incident_statuses: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    channels: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suppression_scope: Mapped[str] = mapped_column(String(16), nullable=False, default="RULE")
    trigger_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suppressed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_triggered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class NotificationORM(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(36), ForeignKey("alert_rules.id"), nullable=False, index=True)
    source_event_id: Mapped[str] = mapped_column(String(256), nullable=False)
    source_domain: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    camera_id: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None, index=True)
    incident_id: Mapped[str | None] = mapped_column(String(36), nullable=True, default=None, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    message: Mapped[str] = mapped_column(String(4096), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    priority: Mapped[str] = mapped_column(String(8), nullable=False, default="P4")
    context: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    muted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )

    __table_args__ = (UniqueConstraint("rule_id", "source_event_id", name="uq_notification_rule_source"),)


class DeliveryAttemptORM(Base):
    __tablename__ = "delivery_attempts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    notification_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("notifications.id"), nullable=False, index=True
    )
    channel: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    destination: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None, index=True
    )
    last_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (
        UniqueConstraint(
            "notification_id", "channel", "destination", name="uq_delivery_notification_channel"
        ),
        Index("ix_delivery_pending_retry", "status", "next_retry_at"),
    )


class IncidentTransitionORM(Base):
    __tablename__ = "incident_transitions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    transition_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    previous_state: Mapped[str | None] = mapped_column(String(16), nullable=True, default=None)
    new_state: Mapped[str | None] = mapped_column(String(16), nullable=True, default=None)
    actor_id: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)


class AlertEvaluationORM(Base):
    __tablename__ = "alert_evaluations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(36), ForeignKey("alert_rules.id"), nullable=False, index=True)
    source_event_id: Mapped[str] = mapped_column(String(256), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    suppression_reason: Mapped[str | None] = mapped_column(String(32), nullable=True, default=None)
    suppression_scope: Mapped[str | None] = mapped_column(String(16), nullable=True, default=None)
    next_eligible_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (UniqueConstraint("rule_id", "source_event_id", name="uq_evaluation_rule_source"),)


class AlertingCursorORM(Base):
    __tablename__ = "alerting_cursor"

    consumer: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    last_id: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
