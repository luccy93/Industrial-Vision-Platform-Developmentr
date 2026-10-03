"""Quality API — inspection profile/category CRUD + runtime quality status.

Configuration is durable (PostgreSQL); inspection results, observations, and
events are in memory only. Every camera-scoped route validates the camera
exists so profiles can never attach to a missing camera.

Commit 01 ships the request/response contracts and dependencies; the routes
land with the runtime engine in Commit 02.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.orm import Session

from backend.app.api.v1.cameras import get_repository
from backend.app.core.config import get_settings
from backend.app.infrastructure.db import get_db, get_session_factory
from backend.app.ingestion.repository import CameraRepository
from backend.app.quality.repository import ProfileConflictError
from backend.app.quality.schemas import (
    DecisionPolicy,
    DefectCategory,
    DefectSeverity,
    InspectionProfile,
    InspectionRegion,
    InspectionType,
    ProductCorrelation,
    ProfileDefectCategory,
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

    @model_validator(mode="after")
    def _ordered_thresholds(self) -> ProfileCreateRequest:
        if self.review_threshold > self.confidence_threshold:
            raise ValueError("review_threshold must not exceed confidence_threshold")
        return self


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

    @model_validator(mode="after")
    def _ordered_thresholds(self) -> DefectCategoryCreate:
        if self.review_threshold > self.confidence_threshold:
            raise ValueError("review_threshold must not exceed confidence_threshold")
        return self


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


def _associations_by_profile(
    associations: list[ProfileDefectCategory],
) -> dict[str, dict[str, ProfileDefectCategory]]:
    result: dict[str, dict[str, ProfileDefectCategory]] = {}
    for association in associations:
        result.setdefault(association.profile_id, {})[association.defect_code.upper()] = association
    return result


def sync_camera_quality(
    engine: Any,
    profiles: Any,
    categories: Any,
    camera_id: str,
    catalog: list[DefectCategory] | None = None,
) -> list[InspectionProfile]:
    """Reload one camera's quality configuration into the runtime snapshot."""
    try:
        profile_list = profiles.list_all(camera_id)
        regions = profiles.list_regions(camera_id)
        associations = profiles.list_associations(camera_id)
        if catalog is None:
            catalog = categories.list_all()
        engine.set_profiles(camera_id, profile_list, regions, catalog, _associations_by_profile(associations))
    except Exception:
        logger.warning("quality load failed for %s", camera_id, exc_info=True)
        profile_list = []
    return profile_list


def _build_regions(camera_id: str, profile_id: str, items: list[RegionCreate]) -> list[InspectionRegion]:
    regions: list[InspectionRegion] = []
    seen: set[str] = set()
    for item in items:
        region_id = item.region_id or f"region-{uuid.uuid4().hex[:8]}"
        if region_id in seen:
            raise HTTPException(status_code=422, detail=f"duplicate region_id: {region_id}")
        seen.add(region_id)
        geometry = item.geometry
        if item.region_type is RegionType.POLYGON and "points" not in geometry:
            geometry = {"points": []}
        regions.append(
            InspectionRegion(
                region_id=region_id,
                camera_id=camera_id,
                profile_id=profile_id,
                name=item.name,
                region_type=item.region_type,
                geometry=geometry,
                enabled=item.enabled,
                required=item.required,
                metadata=item.metadata,
            )
        )
    return regions


def _build_associations(
    camera_id: str,
    profile_id: str,
    defect_codes: list[str],
    catalog: dict[str, DefectCategory],
) -> list[ProfileDefectCategory]:
    associations: list[ProfileDefectCategory] = []
    seen: set[str] = set()
    for code in defect_codes:
        normalized = code.strip().upper()
        if normalized in seen:
            continue
        seen.add(normalized)
        category = catalog.get(normalized)
        if category is None:
            raise HTTPException(status_code=422, detail=f"unknown defect category code: {code}")
        associations.append(
            ProfileDefectCategory(
                profile_id=profile_id,
                defect_category_id=category.defect_id,
                defect_code=category.code,
                enabled=True,
            )
        )
    return associations


def _profile_detail_payload(profile: InspectionProfile) -> dict[str, Any]:
    data = _profile_payload(profile)
    return data


@router.get("/api/v1/quality/status")
def quality_status(engine: Any = Depends(get_quality_engine)) -> dict[str, Any]:
    if engine is None:
        return {
            "enabled": False,
            "engine_status": "DISABLED",
            "model_status": "NOT_CONFIGURED",
            "model_name": None,
            "model_version": None,
            "active_profiles": 0,
            "active_sessions": 0,
            "inspection_count": 0,
            "pass_count": 0,
            "fail_count": 0,
            "review_count": 0,
            "error_count": 0,
            "defect_count": 0,
            "average_inspection_ms": 0.0,
            "last_inspection_timestamp": None,
            "frames_skipped": 0,
            "inspection_fps": 0.0,
            "cameras": {},
        }
    return engine.status()


@router.get("/api/v1/quality/defect-categories")
def list_defect_categories(categories: Any = Depends(get_category_repository)) -> dict[str, Any]:
    items = categories.list_all()
    return {"count": len(items), "categories": [_category_payload(c) for c in items]}


@router.post("/api/v1/quality/defect-categories", status_code=201)
def create_defect_category(
    payload: DefectCategoryCreate,
    categories: Any = Depends(get_category_repository),
) -> dict[str, Any]:
    category = DefectCategory(
        defect_id=f"cat-{uuid.uuid4().hex[:8]}",
        code=payload.code.strip().upper(),
        name=payload.name,
        description=payload.description,
        severity=payload.severity,
        enabled=payload.enabled,
        confidence_threshold=payload.confidence_threshold,
        review_threshold=payload.review_threshold,
        metadata=payload.metadata,
    )
    try:
        created = categories.create(category)
    except Exception as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return _category_payload(created)


@router.put("/api/v1/quality/defect-categories/{code}")
def update_defect_category(
    code: str,
    payload: DefectCategoryUpdate,
    categories: Any = Depends(get_category_repository),
) -> dict[str, Any]:
    try:
        updated = categories.update(code.strip().upper(), **payload.model_dump(exclude_none=True))
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if updated is None:
        raise HTTPException(status_code=404, detail="defect category not found")
    return _category_payload(updated)


@router.delete("/api/v1/quality/defect-categories/{code}")
def delete_defect_category(
    code: str,
    categories: Any = Depends(get_category_repository),
) -> dict[str, Any]:
    if not categories.delete(code.strip().upper()):
        raise HTTPException(status_code=404, detail="defect category not found")
    return {"code": code, "deleted": True}


@router.get("/api/v1/cameras/{camera_id}/inspection-profiles")
def list_inspection_profiles(
    camera_id: str,
    repository: CameraRepository = Depends(get_repository),
    profiles: Any = Depends(get_profile_repository),
    categories: Any = Depends(get_category_repository),
    engine: Any = Depends(get_quality_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    items = sync_camera_quality(engine, profiles, categories, camera_id)
    return {"camera_id": camera_id, "count": len(items), "profiles": [_profile_payload(p) for p in items]}


@router.post("/api/v1/cameras/{camera_id}/inspection-profiles", status_code=201)
def create_inspection_profile(
    camera_id: str,
    payload: ProfileCreateRequest,
    request: Request,
    repository: CameraRepository = Depends(get_repository),
    profiles: Any = Depends(get_profile_repository),
    categories: Any = Depends(get_category_repository),
    engine: Any = Depends(get_quality_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    settings = get_settings()
    profile_id = payload.profile_id or f"profile-{uuid.uuid4().hex[:8]}"
    try:
        if profiles.count(camera_id) >= settings.quality_max_profiles_per_camera:
            raise HTTPException(
                status_code=409,
                detail=f"camera already has {settings.quality_max_profiles_per_camera} inspection profiles",
            )
        profile = InspectionProfile(
            profile_id=profile_id,
            camera_id=camera_id,
            name=payload.name,
            enabled=payload.enabled,
            inspection_type=payload.inspection_type,
            confidence_threshold=payload.confidence_threshold,
            review_threshold=payload.review_threshold,
            decision_policy=payload.decision_policy,
            product_correlation=payload.product_correlation,
            metadata=payload.metadata,
        )
        regions = _build_regions(camera_id, profile_id, payload.regions)
        if len(regions) > settings.quality_max_regions_per_profile:
            raise HTTPException(
                status_code=422,
                detail=f"profile exceeds {settings.quality_max_regions_per_profile} regions",
            )
        catalog = categories.get_by_codes(payload.defect_codes)
        associations = _build_associations(camera_id, profile_id, payload.defect_codes, catalog)
        created = profiles.create(
            camera_id=camera_id, profile=profile, regions=regions, associations=associations
        )
    except HTTPException:
        raise
    except ProfileConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    sync_camera_quality(engine, profiles, categories, camera_id)
    return _profile_payload(created)


@router.get("/api/v1/cameras/{camera_id}/inspection-profiles/{profile_id}")
def get_inspection_profile(
    camera_id: str,
    profile_id: str,
    repository: CameraRepository = Depends(get_repository),
    profiles: Any = Depends(get_profile_repository),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    profile = profiles.get(camera_id, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="inspection profile not found")
    return _profile_payload(profile)


@router.put("/api/v1/cameras/{camera_id}/inspection-profiles/{profile_id}")
def update_inspection_profile(
    camera_id: str,
    profile_id: str,
    payload: ProfileUpdateRequest,
    repository: CameraRepository = Depends(get_repository),
    profiles: Any = Depends(get_profile_repository),
    categories: Any = Depends(get_category_repository),
    engine: Any = Depends(get_quality_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    try:
        updated = profiles.update(camera_id, profile_id, **payload.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if updated is None:
        raise HTTPException(status_code=404, detail="inspection profile not found")
    if payload.regions is not None:
        regions = _build_regions(camera_id, profile_id, payload.regions)
        profiles.replace_regions(camera_id, profile_id, regions)
    if payload.defect_codes is not None:
        catalog = categories.get_by_codes(payload.defect_codes)
        associations = _build_associations(camera_id, profile_id, payload.defect_codes, catalog)
        profiles.replace_associations(camera_id, profile_id, associations)
    sync_camera_quality(engine, profiles, categories, camera_id)
    return _profile_payload(profiles.get(camera_id, profile_id))


@router.delete("/api/v1/cameras/{camera_id}/inspection-profiles/{profile_id}")
def delete_inspection_profile(
    camera_id: str,
    profile_id: str,
    repository: CameraRepository = Depends(get_repository),
    profiles: Any = Depends(get_profile_repository),
    categories: Any = Depends(get_category_repository),
    engine: Any = Depends(get_quality_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    if not profiles.delete(camera_id, profile_id):
        raise HTTPException(status_code=404, detail="inspection profile not found")
    sync_camera_quality(engine, profiles, categories, camera_id)
    return {"camera_id": camera_id, "profile_id": profile_id, "deleted": True}


@router.get("/api/v1/cameras/{camera_id}/quality/latest")
def latest_quality_result(
    camera_id: str,
    repository: CameraRepository = Depends(get_repository),
    engine: Any = Depends(get_quality_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    result = engine.latest_result(camera_id) if engine else None
    return {"camera_id": camera_id, "result": result.to_websocket() if result else None}


@router.get("/api/v1/cameras/{camera_id}/quality/results")
def recent_quality_results(
    camera_id: str,
    limit: int = Query(default=10, ge=1, le=100),
    repository: CameraRepository = Depends(get_repository),
    engine: Any = Depends(get_quality_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    results = engine.recent_results(camera_id, limit) if engine else []
    return {
        "camera_id": camera_id,
        "count": len(results),
        "results": [r.to_websocket() for r in results],
    }


@router.get("/api/v1/cameras/{camera_id}/quality/events")
def quality_events(
    camera_id: str,
    status: str = Query(default="all"),
    limit: int = Query(default=50, ge=1, le=500),
    repository: CameraRepository = Depends(get_repository),
    engine: Any = Depends(get_quality_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    if engine is None:
        return {"camera_id": camera_id, "count": 0, "events": []}
    wanted = status.strip().upper()
    events = list(engine.active_events(camera_id, limit)) + list(engine.recent_events(camera_id, limit))
    if wanted != "ALL":
        events = [e for e in events if e.status.value == wanted]
    events = events[:limit]
    return {
        "camera_id": camera_id,
        "count": len(events),
        "events": [e.to_websocket() for e in events],
    }


@router.post("/api/v1/cameras/{camera_id}/quality/suppress/{event_id}")
def suppress_quality_event(
    camera_id: str,
    event_id: str,
    repository: CameraRepository = Depends(get_repository),
    engine: Any = Depends(get_quality_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    if engine is None:
        raise HTTPException(status_code=404, detail="quality event not found")
    try:
        status = engine.suppress(camera_id, event_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"camera_id": camera_id, "event_id": event_id, "status": status.value}


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
    "sync_camera_quality",
]
