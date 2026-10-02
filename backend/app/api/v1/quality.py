"""Quality API — inspection profile/category CRUD + runtime quality status.

Configuration is durable (PostgreSQL); inspection results, observations, and
events are in memory only. Every camera-scoped route validates the camera
exists so profiles can never attach to a missing camera.

Commit 01 ships the request/response contracts and dependencies; the routes
land with the runtime engine in Commit 02.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from backend.app.infrastructure.db import get_db, get_session_factory
from backend.app.quality.schemas import (
    DecisionPolicy,
    DefectCategory,
    DefectSeverity,
    InspectionProfile,
    InspectionRegion,
    InspectionType,
    ProductCorrelation,
    RegionType,
)

logger = logging.getLogger("industrial-vision.api")

router = APIRouter(tags=["quality"])


def get_profile_repository(request: Request, session: Session = Depends(get_db)) -> Any:
    from backend.app.quality.repository import InspectionProfileRepository

    factory = getattr(request.app.state, "session_factory", None)
    if factory is None:
        factory = get_session_factory(str(session.get_bind().url))  # type: ignore[union-attr]
    return InspectionProfileRepository(factory)


def get_category_repository(request: Request, session: Session = Depends(get_db)) -> Any:
    from backend.app.quality.repository import DefectCategoryRepository

    factory = getattr(request.app.state, "session_factory", None)
    if factory is None:
        factory = get_session_factory(str(session.get_bind().url))  # type: ignore[union-attr]
    return DefectCategoryRepository(factory)


def get_quality_engine(request: Request) -> Any:
    from backend.app.quality.engine import QualityInspectionEngine

    engine = getattr(request.app.state, "quality_engine", None)
    return engine if isinstance(engine, QualityInspectionEngine) else None


class RegionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    region_id: str | None = Field(default=None, min_length=1, max_length=128)
    region_type: RegionType = RegionType.RECTANGLE
    geometry: dict[str, Any]
    enabled: bool = True
    required: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class RegionUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    region_type: RegionType | None = None
    geometry: dict[str, Any] | None = None
    enabled: bool | None = None
    required: bool | None = None
    metadata: dict[str, Any] | None = None


class ProfileCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    profile_id: str | None = Field(default=None, min_length=1, max_length=128)
    inspection_type: InspectionType = InspectionType.GENERAL
    enabled: bool = True
    confidence_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    review_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    decision_policy: DecisionPolicy = Field(default_factory=DecisionPolicy)
    product_correlation: ProductCorrelation | None = None
    regions: list[RegionCreate] = Field(default_factory=list)
    defect_codes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    _normalize_enums = field_validator("inspection_type", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )


class ProfileUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    inspection_type: InspectionType | None = None
    enabled: bool | None = None
    confidence_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    review_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    decision_policy: DecisionPolicy | None = None
    product_correlation: ProductCorrelation | None = None
    regions: list[RegionCreate] | None = None
    defect_codes: list[str] | None = None
    metadata: dict[str, Any] | None = None

    _normalize_enums = field_validator("inspection_type", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )


class DefectCategoryCreate(BaseModel):
    code: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    severity: DefectSeverity = DefectSeverity.MEDIUM
    enabled: bool = True
    confidence_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    review_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)

    _normalize_enums = field_validator("severity", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )


class DefectCategoryUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1024)
    severity: DefectSeverity | None = None
    enabled: bool | None = None
    confidence_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    review_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    metadata: dict[str, Any] | None = None

    _normalize_enums = field_validator("severity", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )


def _profile_payload(profile: InspectionProfile) -> dict[str, Any]:
    data = profile.model_dump()
    for key in ("inspection_type",):
        data[key] = data[key].value
    for key in ("created_at", "updated_at"):
        data[key] = str(data[key])
    return data


def _region_payload(region: InspectionRegion) -> dict[str, Any]:
    data = region.model_dump()
    data["region_type"] = data["region_type"].value
    for key in ("created_at", "updated_at"):
        data[key] = str(data[key])
    return data


def _category_payload(category: DefectCategory) -> dict[str, Any]:
    data = category.model_dump()
    data["severity"] = data["severity"].value
    for key in ("created_at", "updated_at"):
        data[key] = str(data[key])
    return data


__all__ = [
    "DefectCategoryCreate",
    "DefectCategoryUpdate",
    "ProfileCreateRequest",
    "ProfileUpdateRequest",
    "RegionCreate",
    "RegionUpdate",
    "get_category_repository",
    "get_profile_repository",
    "get_quality_engine",
    "router",
]
