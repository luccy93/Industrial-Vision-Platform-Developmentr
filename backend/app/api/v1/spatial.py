"""Spatial API — zone CRUD (PostgreSQL) + spatial runtime status.

Zone configuration is durable; membership/dwell/proximity state is in memory
and reported separately. Every route is camera-scoped and validates the
camera exists so zone IDs can never be attached to a missing camera.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from backend.app.api.v1.cameras import get_repository
from backend.app.core.config import get_settings
from backend.app.infrastructure.db import get_db, get_session_factory
from backend.app.ingestion.repository import CameraRepository
from backend.app.safety.schemas import SafetySeverity
from backend.app.spatial.engine import SpatialEngine
from backend.app.spatial.repository import ZoneConflictError, ZoneRepository
from backend.app.spatial.schemas import SafetyZone, ZonePoint, ZoneType

logger = logging.getLogger("industrial-vision.api")

router = APIRouter(tags=["spatial"])


def get_zone_repository(request: Request, session: Session = Depends(get_db)) -> ZoneRepository:
    factory = getattr(request.app.state, "session_factory", None)
    if factory is None:
        factory = get_session_factory(str(session.get_bind().url))  # type: ignore[union-attr]
    return ZoneRepository(factory)


def get_spatial_engine(request: Request) -> SpatialEngine:
    engine = getattr(request.app.state, "spatial_engine", None)
    if isinstance(engine, SpatialEngine):
        return engine
    return SpatialEngine(get_settings())


class ZoneCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    zone_id: str | None = Field(default=None, min_length=1, max_length=128)
    zone_type: ZoneType = ZoneType.RESTRICTED
    polygon: list[ZonePoint] = Field(min_length=3)
    enabled: bool = True
    severity: SafetySeverity = SafetySeverity.HIGH
    dwell_threshold_seconds: float | None = Field(default=None, ge=0.0)
    metadata: dict[str, Any] = Field(default_factory=dict)

    _normalize_enums = field_validator("zone_type", "severity", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )


class ZoneUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    zone_type: ZoneType | None = None
    polygon: list[ZonePoint] | None = Field(default=None, min_length=3)
    enabled: bool | None = None
    severity: SafetySeverity | None = None
    dwell_threshold_seconds: float | None = Field(default=None, ge=0.0)
    metadata: dict[str, Any] | None = None

    _normalize_enums = field_validator("zone_type", "severity", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )


def _zone_payload(zone: SafetyZone) -> dict[str, Any]:
    data = zone.model_dump()
    data["polygon"] = [p.model_dump() for p in zone.polygon]
    for key in ("zone_type", "severity"):
        data[key] = data[key].value
    for key in ("created_at", "updated_at"):
        data[key] = str(data[key])
    return data


def _sync_engine(engine: SpatialEngine, zones: list[SafetyZone], camera_id: str) -> None:
    engine.set_zones(camera_id, zones)


def sync_camera_zones(spatial: SpatialEngine, zones: ZoneRepository, camera_id: str) -> list[SafetyZone]:
    """Reload one camera's zone configuration into the runtime registry."""
    try:
        zones_list = zones.list(camera_id)
    except Exception:
        logger.warning("zone load failed for %s", camera_id, exc_info=True)
        zones_list = []
    _sync_engine(spatial, zones_list, camera_id)
    return zones_list


@router.get("/api/v1/spatial/status", summary="Spatial engine status")
def spatial_status(engine: SpatialEngine = Depends(get_spatial_engine)) -> dict[str, Any]:
    return engine.status()


@router.get("/api/v1/cameras/{camera_id}/zones")
def list_zones(
    camera_id: str,
    repository: CameraRepository = Depends(get_repository),
    zones: ZoneRepository = Depends(get_zone_repository),
    spatial: SpatialEngine = Depends(get_spatial_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    items = sync_camera_zones(spatial, zones, camera_id)
    return {"camera_id": camera_id, "count": len(items), "zones": [_zone_payload(z) for z in items]}


@router.post("/api/v1/cameras/{camera_id}/zones", status_code=201)
def create_zone(
    camera_id: str,
    payload: ZoneCreateRequest,
    repository: CameraRepository = Depends(get_repository),
    zones: ZoneRepository = Depends(get_zone_repository),
    spatial: SpatialEngine = Depends(get_spatial_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    settings = get_settings()
    try:
        if payload.enabled and zones.count(camera_id) >= settings.spatial_max_zones_per_camera:
            raise HTTPException(
                status_code=409,
                detail=f"camera already has {settings.spatial_max_zones_per_camera} zones",
            )
        zone = zones.create(
            camera_id=camera_id,
            zone_id=payload.zone_id,
            name=payload.name,
            zone_type=payload.zone_type,
            polygon=payload.polygon,
            enabled=payload.enabled,
            severity=payload.severity,
            dwell_threshold_seconds=payload.dwell_threshold_seconds,
            metadata=payload.metadata,
        )
    except ZoneConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    sync_camera_zones(spatial, zones, camera_id)
    return _zone_payload(zone)


@router.get("/api/v1/cameras/{camera_id}/zones/state")
def zone_state(
    camera_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    repository: CameraRepository = Depends(get_repository),
    spatial: SpatialEngine = Depends(get_spatial_engine),
) -> dict[str, Any]:
    """Current in-memory membership/dwell snapshot (never persisted).

    Declared before ``/zones/{zone_id}`` so the literal path wins the match.
    """
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    members = spatial.membership_snapshot(camera_id, limit)
    return {
        "camera_id": camera_id,
        "count": len(members),
        "zones_loaded": len(spatial.zones_for(camera_id, enabled_only=False)),
        "members": [m.model_dump(mode="json") for m in members],
    }


@router.get("/api/v1/cameras/{camera_id}/zones/{zone_id}")
def get_zone(
    camera_id: str,
    zone_id: str,
    repository: CameraRepository = Depends(get_repository),
    zones: ZoneRepository = Depends(get_zone_repository),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    zone = zones.get(camera_id, zone_id)
    if zone is None:
        raise HTTPException(status_code=404, detail="zone not found")
    return _zone_payload(zone)


@router.put("/api/v1/cameras/{camera_id}/zones/{zone_id}")
def update_zone(
    camera_id: str,
    zone_id: str,
    payload: ZoneUpdateRequest,
    repository: CameraRepository = Depends(get_repository),
    zones: ZoneRepository = Depends(get_zone_repository),
    spatial: SpatialEngine = Depends(get_spatial_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    try:
        zone = zones.update(
            camera_id,
            zone_id,
            **payload.model_dump(exclude_none=True),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if zone is None:
        raise HTTPException(status_code=404, detail="zone not found")
    sync_camera_zones(spatial, zones, camera_id)
    return _zone_payload(zone)


@router.delete("/api/v1/cameras/{camera_id}/zones/{zone_id}")
def delete_zone(
    camera_id: str,
    zone_id: str,
    repository: CameraRepository = Depends(get_repository),
    zones: ZoneRepository = Depends(get_zone_repository),
    spatial: SpatialEngine = Depends(get_spatial_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    if not zones.delete(camera_id, zone_id):
        raise HTTPException(status_code=404, detail="zone not found")
    spatial.remove_zone(camera_id, zone_id)
    return {"camera_id": camera_id, "zone_id": zone_id, "deleted": True}
