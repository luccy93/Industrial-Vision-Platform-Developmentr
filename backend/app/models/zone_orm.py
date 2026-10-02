"""Zone ORM — persistent zone configuration (PostgreSQL).

Only slow-changing configuration lives here. Runtime membership, dwell
timers, and proximity pair state stay in memory (see ``SpatialEngine``).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.domain.common import utcnow
from backend.app.models.camera_orm import Base


class ZoneORM(Base):
    __tablename__ = "zones"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    zone_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    camera_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    zone_type: Mapped[str] = mapped_column(String(16), nullable=False, default="RESTRICTED")
    # JSON list of {"x": float, "y": float} in normalized coordinates.
    polygon: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="HIGH")
    dwell_threshold_seconds: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
