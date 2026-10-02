"""Quality ORM — persistent inspection configuration (PostgreSQL).

Only slow-changing configuration lives here: profiles, regions, defect
categories, and profile<->category associations. Every frame-level
inspection result, observation, and event stays in memory (see
``QualityInspectionEngine``) — the hot path never writes to PostgreSQL.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.domain.common import utcnow
from backend.app.models.camera_orm import Base


class InspectionProfileORM(Base):
    __tablename__ = "inspection_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    profile_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    camera_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    inspection_type: Mapped[str] = mapped_column(String(16), nullable=False, default="GENERAL")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    confidence_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.6)
    review_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.35)
    decision_policy: Mapped[dict] = mapped_column("decision_policy", JSON, nullable=False, default=dict)
    product_correlation: Mapped[dict | None] = mapped_column(
        "product_correlation", JSON, nullable=True, default=None
    )
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class InspectionRegionORM(Base):
    __tablename__ = "inspection_regions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    region_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    camera_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    profile_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    region_type: Mapped[str] = mapped_column(String(16), nullable=False, default="RECTANGLE")
    geometry: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class DefectCategoryORM(Base):
    __tablename__ = "defect_categories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    code: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="MEDIUM")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    confidence_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.6)
    review_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.35)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class ProfileDefectCategoryORM(Base):
    __tablename__ = "inspection_profile_defect_categories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    camera_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    profile_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    defect_category_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    defect_code: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    override_confidence_threshold: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    override_review_threshold: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
