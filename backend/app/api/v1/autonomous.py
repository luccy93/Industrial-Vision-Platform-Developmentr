"""Autonomous perception API — profile CRUD (PostgreSQL) + runtime status.

Configuration is durable; scenes, objects, trajectories, risks, and events
are in memory and reported separately. Every camera-scoped route validates
the camera exists so profiles can never attach to a missing camera.

Commit 01 ships the request/response contracts and dependencies; the routes
land with the runtime engine in Commit 02.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from backend.app.api.v1.cameras import get_repository
from backend.app.autonomous.repository import AutonomousProfileConflictError
from backend.app.autonomous.schemas import AutonomousProfile, SceneType
from backend.app.core.config import get_settings
from backend.app.infrastructure.db import get_db, get_session_factory
from backend.app.ingestion.repository import CameraRepository

logger = logging.getLogger("industrial-vision.api")

router = APIRouter(tags=["autonomous"])


def get_autonomous_repository(request: Request, session: Session = Depends(get_db)) -> Any:
    from backend.app.autonomous.repository import AutonomousProfileRepository

    factory = getattr(request.app.state, "session_factory", None)
    if factory is None:
        factory = get_session_factory(str(session.get_bind().url))  # type: ignore[union-attr]
    return AutonomousProfileRepository(factory)


def get_autonomous_engine(request: Request) -> Any:
    from backend.app.autonomous.engine import AutonomousPerceptionEngine

    engine = getattr(request.app.state, "autonomous_engine", None)
    return engine if isinstance(engine, AutonomousPerceptionEngine) else None


class AutonomousProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    profile_id: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: bool = True
    scene_type: SceneType = SceneType.UNKNOWN
    lane_detection_enabled: bool = True
    depth_enabled: bool = False
    trajectory_enabled: bool = True
    collision_risk_enabled: bool = True
    bev_enabled: bool = True
    trajectory_horizon_seconds: float = Field(default=2.0, ge=0.1, le=10.0)
    collision_risk_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    collision_grace_seconds: float = Field(default=0.5, ge=0.0, le=300.0)
    configuration: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    _normalize_enums = field_validator("scene_type", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )


class AutonomousProfileUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: bool | None = None
    scene_type: SceneType | None = None
    lane_detection_enabled: bool | None = None
    depth_enabled: bool | None = None
    trajectory_enabled: bool | None = None
    collision_risk_enabled: bool | None = None
    bev_enabled: bool | None = None
    trajectory_horizon_seconds: float | None = Field(default=None, ge=0.1, le=10.0)
    collision_risk_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    collision_grace_seconds: float | None = Field(default=None, ge=0.0, le=300.0)
    configuration: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None

    _normalize_enums = field_validator("scene_type", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )


def _profile_payload(profile: AutonomousProfile) -> dict[str, Any]:
    data = profile.model_dump()
    data["scene_type"] = data["scene_type"].value
    for key in ("created_at", "updated_at"):
        data[key] = str(data[key])
    return data


def sync_camera_perception(engine: Any, profiles: Any, camera_id: str) -> list[AutonomousProfile]:
    """Reload one camera's perception profiles into the runtime snapshot."""
    try:
        profile_list = profiles.list_all(camera_id)
    except Exception:
        logger.warning("autonomous load failed for %s", camera_id, exc_info=True)
        profile_list = []
    try:
        engine.set_profiles(camera_id, profile_list)
    except Exception:
        logger.warning("autonomous sync failed for %s", camera_id, exc_info=True)
        return []
    return profile_list


@router.get("/api/v1/autonomous/status", summary="Autonomous engine status")
def autonomous_status(engine: Any = Depends(get_autonomous_engine)) -> dict[str, Any]:
    if engine is None:
        return {
            "enabled": False,
            "engine_status": "DISABLED",
            "scene_classifier_status": "NOT_CONFIGURED",
            "lane_detector_status": "NOT_CONFIGURED",
            "depth_status": "NOT_CONFIGURED",
            "trajectory_status": "DISABLED",
            "collision_status": "DISABLED",
            "bev_status": "DISABLED",
            "active_profiles": 0,
            "active_cameras": 0,
            "tracked_objects": 0,
            "perception_count": 0,
            "average_perception_ms": 0.0,
            "last_perception_timestamp": None,
            "frames_skipped": 0,
            "perception_fps": 0.0,
            "cameras": {},
        }
    return engine.status()


@router.get("/api/v1/cameras/{camera_id}/autonomous-profiles")
def list_autonomous_profiles(
    camera_id: str,
    repository: CameraRepository = Depends(get_repository),
    profiles: Any = Depends(get_autonomous_repository),
    engine: Any = Depends(get_autonomous_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    items = sync_camera_perception(engine, profiles, camera_id) if engine else profiles.list_all(camera_id)
    return {"camera_id": camera_id, "count": len(items), "profiles": [_profile_payload(p) for p in items]}


@router.post("/api/v1/cameras/{camera_id}/autonomous-profiles", status_code=201)
def create_autonomous_profile(
    camera_id: str,
    payload: AutonomousProfileCreate,
    repository: CameraRepository = Depends(get_repository),
    profiles: Any = Depends(get_autonomous_repository),
    engine: Any = Depends(get_autonomous_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    settings = get_settings()
    try:
        if profiles.count(camera_id) >= settings.autonomous_max_profiles_per_camera:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"camera already has {settings.autonomous_max_profiles_per_camera} perception profiles"
                ),
            )
        profile = AutonomousProfile(
            profile_id=payload.profile_id or f"profile-{uuid.uuid4().hex[:8]}",
            camera_id=camera_id,
            name=payload.name,
            enabled=payload.enabled,
            scene_type=payload.scene_type,
            lane_detection_enabled=payload.lane_detection_enabled,
            depth_enabled=payload.depth_enabled,
            trajectory_enabled=payload.trajectory_enabled,
            collision_risk_enabled=payload.collision_risk_enabled,
            bev_enabled=payload.bev_enabled,
            trajectory_horizon_seconds=payload.trajectory_horizon_seconds,
            collision_risk_threshold=payload.collision_risk_threshold,
            collision_grace_seconds=payload.collision_grace_seconds,
            configuration=payload.configuration,
            metadata=payload.metadata,
        )
        created = profiles.create(camera_id=camera_id, profile=profile)
    except HTTPException:
        raise
    except AutonomousProfileConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if engine:
        sync_camera_perception(engine, profiles, camera_id)
    return _profile_payload(created)


@router.get("/api/v1/cameras/{camera_id}/autonomous-profiles/{profile_id}")
def get_autonomous_profile(
    camera_id: str,
    profile_id: str,
    repository: CameraRepository = Depends(get_repository),
    profiles: Any = Depends(get_autonomous_repository),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    profile = profiles.get(camera_id, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="perception profile not found")
    return _profile_payload(profile)


@router.put("/api/v1/cameras/{camera_id}/autonomous-profiles/{profile_id}")
def update_autonomous_profile(
    camera_id: str,
    profile_id: str,
    payload: AutonomousProfileUpdate,
    repository: CameraRepository = Depends(get_repository),
    profiles: Any = Depends(get_autonomous_repository),
    engine: Any = Depends(get_autonomous_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    try:
        updated = profiles.update(camera_id, profile_id, **payload.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if updated is None:
        raise HTTPException(status_code=404, detail="perception profile not found")
    if engine:
        sync_camera_perception(engine, profiles, camera_id)
    return _profile_payload(profiles.get(camera_id, profile_id))


@router.delete("/api/v1/cameras/{camera_id}/autonomous-profiles/{profile_id}")
def delete_autonomous_profile(
    camera_id: str,
    profile_id: str,
    repository: CameraRepository = Depends(get_repository),
    profiles: Any = Depends(get_autonomous_repository),
    engine: Any = Depends(get_autonomous_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    if not profiles.delete(camera_id, profile_id):
        raise HTTPException(status_code=404, detail="perception profile not found")
    if engine:
        sync_camera_perception(engine, profiles, camera_id)
    return {"camera_id": camera_id, "profile_id": profile_id, "deleted": True}


@router.get("/api/v1/cameras/{camera_id}/autonomous/latest")
def latest_perception(
    camera_id: str,
    repository: CameraRepository = Depends(get_repository),
    engine: Any = Depends(get_autonomous_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    result = engine.latest_result(camera_id) if engine else None
    return {"camera_id": camera_id, "result": result.to_websocket() if result else None}


@router.get("/api/v1/cameras/{camera_id}/autonomous/events")
def perception_events(
    camera_id: str,
    status: str = Query(default="all"),
    limit: int = Query(default=50, ge=1, le=500),
    repository: CameraRepository = Depends(get_repository),
    engine: Any = Depends(get_autonomous_engine),
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


__all__ = [
    "AutonomousProfileCreate",
    "AutonomousProfileUpdate",
    "get_autonomous_engine",
    "get_autonomous_repository",
    "router",
    "sync_camera_perception",
]
