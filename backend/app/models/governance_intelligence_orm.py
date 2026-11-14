"""Governance intelligence ORM (V37).

Four additive tables hold versioned risk models, versioned operational SLA
targets, deduplicated advisory recommendations, and append-only recommendation
events. No table uses ``ON DELETE CASCADE``: intelligence must never remove
evidence, cases, custody records, governance records, automation records, or
audit history. Risk models, SLA targets, and recommendation events are
append-only; recommendations are mutable for lifecycle updates but cannot be
deleted.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
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


class GovernanceRiskModelORM(Base):
    __tablename__ = "governance_risk_models"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    model_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="ENABLED")
    thresholds: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    factor_points: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    effective_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False, default="SYSTEM")
    actor_role: Mapped[str] = mapped_column(String(16), nullable=False, default="SYSTEM")
    reason: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (
        UniqueConstraint("model_id", "version", name="uq_governance_risk_model_version"),
        Index("ix_governance_risk_model_effective", "model_id", "effective_from"),
    )


class GovernanceSlaTargetORM(Base):
    __tablename__ = "governance_sla_targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_key: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    target_hours: Mapped[int] = mapped_column(Integer, nullable=False)
    warning_hours: Mapped[int] = mapped_column(Integer, nullable=False)
    effective_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False, default="SYSTEM")
    actor_role: Mapped[str] = mapped_column(String(16), nullable=False, default="SYSTEM")
    reason: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (
        UniqueConstraint("target_key", "version", name="uq_governance_sla_target_version"),
        Index("ix_governance_sla_target_effective", "target_key", "effective_from"),
    )


class GovernanceRecommendationORM(Base):
    __tablename__ = "governance_recommendations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    recommendation_key: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scope_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    scope_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    rationale: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    source_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN", index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    acknowledged_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    acknowledgement_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    dismissed_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    dismissed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    dismissal_reason: Mapped[str | None] = mapped_column(String(500), nullable=True, default=None)
    resolved_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    resolution_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (
        Index("ix_governance_recommendation_status_severity", "status", "severity", "last_evaluated_at"),
        Index("ix_governance_recommendation_scope", "rule_id", "scope_type", "scope_id"),
    )


class GovernanceRecommendationEventORM(Base):
    __tablename__ = "governance_recommendation_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    recommendation_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("governance_recommendations.id"),
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

    __table_args__ = (Index("ix_governance_recommendation_event_time", "recommendation_id", "created_at"),)
