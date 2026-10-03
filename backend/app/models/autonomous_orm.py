"""Autonomous perception ORM — persistent perception configuration (PostgreSQL).

Only slow-changing configuration lives here: per-camera perception profiles.
Every frame-level scene, object, trajectory, risk estimate, and event stays
in memory (see ``AutonomousPerceptionEngine``) — the hot path never writes
to PostgreSQL.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.domain.common import utcnow
from backend.app.models.camera_orm import Base


class AutonomousProfileORM(Base):
    __tablename__ = "autonomous_perception_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    profile_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    camera_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    scene_type: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    lane_detection_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    depth_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    trajectory_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    collision_risk_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    bev_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    trajectory_horizon_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=2.0)
    collision_risk_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    collision_grace_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    configuration: Mapped[dict] = mapped_column("configuration", JSON, nullable=False, default=dict)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
