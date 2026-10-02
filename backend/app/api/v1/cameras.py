"""Cameras resource — V02 CRUD/lifecycle + V03 inference attach/detach.

Starting a stream also attaches an inference worker (best-effort: inference
failures never fail stream startup). Stopping/deleting detaches it.

Configuration persists in PostgreSQL (survives restarts); stream state,
buffers, and metrics stay in memory. ``source_secret`` is write-only and
never appears in responses or logs.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from backend.app.spatial.engine import SpatialEngine
    from backend.app.tracking.manager import TrackingManager

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.domain.camera import Camera
from backend.app.domain.stream import SourceType, StreamMetrics
from backend.app.infrastructure.db import get_db, get_session_factory
from backend.app.ingestion.manager import StreamSupervisor, create_source
from backend.app.ingestion.repository import CameraRepository

router = APIRouter(prefix="/cameras", tags=["cameras"])

logger = logging.getLogger("industrial-vision.api")

_fallback_supervisor = StreamSupervisor()


def _app_supervisor() -> StreamSupervisor:
    return StreamSupervisor()


def get_supervisor(request: Request) -> StreamSupervisor:
    supervisor = getattr(request.app.state, "supervisor", None)
    return supervisor if supervisor is not None else _fallback_supervisor


def get_repository(request: Request, session: Session = Depends(get_db)) -> CameraRepository:
    factory = getattr(request.app.state, "session_factory", None)
    if factory is None:
        engine_url = str(session.get_bind().url)  # type: ignore[union-attr]
        factory = get_session_factory(engine_url)
    return CameraRepository(factory)


class CameraCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    camera_id: str | None = Field(default=None, max_length=128)
    source_type: SourceType = SourceType.file
    source: str = Field(default="", max_length=1024)
    source_secret: str | None = Field(default=None, max_length=1024)
    enabled: bool = True
    width: int | None = Field(default=None, ge=1)
    height: int | None = Field(default=None, ge=1)
    target_fps: float | None = Field(default=None, ge=0)
    reconnect_enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class CameraUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    source_type: SourceType | None = None
    source: str | None = Field(default=None, max_length=1024)
    source_secret: str | None = Field(default=None, max_length=1024)
    enabled: bool | None = None
    width: int | None = Field(default=None, ge=1)
    height: int | None = Field(default=None, ge=1)
    target_fps: float | None = Field(default=None, ge=0)
    reconnect_enabled: bool | None = None
    metadata: dict[str, Any] | None = None


def _public_dict(camera: Camera) -> dict[str, Any]:
    data = camera.model_dump()
    data.pop("source_secret", None)
    # Serialize datetimes/UUIDs safely.
    for key in ("id", "timestamp", "created_at", "updated_at"):
        if key in data and data[key] is not None:
            data[key] = str(data[key])
    for key in ("source_type", "status"):
        value = data.get(key)
        if value is not None and hasattr(value, "value"):
            data[key] = value.value  # type: ignore[union-attr]
    return data


@router.get("")
def list_cameras(repository: CameraRepository = Depends(get_repository)) -> dict:
    return {"items": [_public_dict(camera) for camera in repository.list()]}


@router.post("", status_code=201)
def create_camera(
    payload: CameraCreateRequest,
    repository: CameraRepository = Depends(get_repository),
) -> dict:
    if payload.camera_id and repository.get(payload.camera_id):
        raise HTTPException(status_code=409, detail="camera_id already exists")
    camera = repository.create(
        name=payload.name,
        camera_id=payload.camera_id,
        source_type=payload.source_type,
        source=payload.source,
        source_secret=payload.source_secret,
        enabled=payload.enabled,
        width=payload.width,
        height=payload.height,
        target_fps=payload.target_fps,
        reconnect_enabled=payload.reconnect_enabled,
        metadata=payload.metadata,
    )
    return _public_dict(camera)


@router.get("/{camera_id}")
def get_camera(camera_id: str, repository: CameraRepository = Depends(get_repository)) -> dict:
    camera = repository.get(camera_id)
    if camera is None:
        raise HTTPException(status_code=404, detail="camera not found")
    return _public_dict(camera)


@router.put("/{camera_id}")
def update_camera(
    camera_id: str,
    payload: CameraUpdateRequest,
    request: Request,
    repository: CameraRepository = Depends(get_repository),
    supervisor: StreamSupervisor = Depends(get_supervisor),
) -> dict:
    updates = {key: value for key, value in payload.model_dump().items() if value is not None}
    camera = repository.update(camera_id, **updates)
    if camera is None:
        raise HTTPException(status_code=404, detail="camera not found")
    # Config changed → drop the running workers; next start uses fresh config.
    supervisor.remove(camera_id)
    _detach_inference(request, camera_id)
    return _public_dict(camera)


@router.delete("/{camera_id}", status_code=200)
def delete_camera(
    camera_id: str,
    request: Request,
    repository: CameraRepository = Depends(get_repository),
    supervisor: StreamSupervisor = Depends(get_supervisor),
) -> dict:
    supervisor.remove(camera_id)
    _detach_inference(request, camera_id)
    _drop_spatial(request, camera_id)
    if not repository.delete(camera_id):
        raise HTTPException(status_code=404, detail="camera not found")
    return {"deleted": camera_id}


def _detach_inference(request: Request, camera_id: str) -> None:
    supervisor = getattr(request.app.state, "inference_supervisor", None)
    if supervisor is not None:
        try:
            supervisor.detach(camera_id)
        except Exception:
            logger.debug("inference detach failed for %s", camera_id, exc_info=True)


def _tracking_manager(request: Request) -> TrackingManager | None:
    manager = getattr(request.app.state, "tracking_manager", None)
    # isinstance needs the runtime class; import locally to avoid cycles.
    from backend.app.tracking.manager import TrackingManager as _TM

    return manager if isinstance(manager, _TM) else None


def _spatial_engine(request: Request) -> SpatialEngine | None:
    from backend.app.spatial.engine import SpatialEngine as _SE

    engine = getattr(request.app.state, "spatial_engine", None)
    return engine if isinstance(engine, _SE) else None


def _reset_spatial(request: Request, camera_id: str) -> None:
    """Drop per-camera zone/proximity state and reload zone configuration.

    A restarted stream invalidates every track ID, so stale membership must not
    survive; zone configuration itself is reloaded from PostgreSQL.
    """
    engine = _spatial_engine(request)
    if engine is None:
        return
    try:
        engine.reset_camera(camera_id)
        factory = getattr(request.app.state, "session_factory", None)
        if factory is not None:
            from backend.app.api.v1.spatial import sync_camera_zones
            from backend.app.spatial.repository import ZoneRepository

            sync_camera_zones(engine, ZoneRepository(factory), camera_id)
    except Exception:
        logger.debug("spatial reset failed for %s", camera_id, exc_info=True)


def _drop_spatial(request: Request, camera_id: str) -> None:
    """Delete a camera's zones and forget its spatial runtime state."""
    engine = _spatial_engine(request)
    if engine is None:
        return
    try:
        engine.reset_camera(camera_id)
        factory = getattr(request.app.state, "session_factory", None)
        if factory is not None:
            from backend.app.spatial.repository import ZoneRepository

            ZoneRepository(factory).delete_for_camera(camera_id)
    except Exception:
        logger.debug("spatial cleanup failed for %s", camera_id, exc_info=True)


def _attach_inference(request: Request, camera_id: str, frame_source: object) -> None:
    """Best-effort: inference problems must never fail stream startup."""
    try:
        supervisor = getattr(request.app.state, "inference_supervisor", None)
        model_manager = getattr(request.app.state, "model_manager", None)
        if supervisor is None or model_manager is None:
            return
        tracking = _tracking_manager(request)
        safety_engine = getattr(request.app.state, "safety_engine", None)
        if tracking is not None:
            try:
                tracking.reset_camera(camera_id)  # type: ignore[union-attr]
            except Exception:
                logger.debug("tracking reset failed for %s", camera_id, exc_info=True)
        if safety_engine is not None:
            try:
                safety_engine.reset_camera(camera_id)
            except Exception:
                logger.debug("safety reset failed for %s", camera_id, exc_info=True)
        _reset_spatial(request, camera_id)
        worker = supervisor.attach(  # type: ignore[arg-type]
            camera_id,
            model_manager,
            frame_source,
            tracking_manager=tracking,
            safety_engine=safety_engine,
        )
        worker.start()
    except Exception:
        logger.warning("inference attach failed for %s", camera_id, exc_info=True)


@router.post("/{camera_id}/start")
def start_stream(
    camera_id: str,
    request: Request,
    repository: CameraRepository = Depends(get_repository),
    supervisor: StreamSupervisor = Depends(get_supervisor),
) -> dict:
    from backend.app.core.config import get_settings

    camera = repository.get(camera_id)
    if camera is None:
        raise HTTPException(status_code=404, detail="camera not found")
    settings = get_settings()
    manager = supervisor.get(camera_id)
    if manager is None:
        manager = supervisor.register(
            camera,
            source_secret=repository.get_secret(camera_id),
            source_factory=create_source,
            buffer_size=settings.buffer_size,
            target_processing_fps=camera.target_fps or settings.target_processing_fps,
            frame_skip=settings.frame_skip,
        )
    manager.start()
    _attach_inference(request, camera_id, manager.buffer.get_latest)
    return {"camera_id": camera_id, "state": manager.state.value}


@router.post("/{camera_id}/stop")
def stop_stream(
    camera_id: str,
    request: Request,
    supervisor: StreamSupervisor = Depends(get_supervisor),
) -> dict:
    manager = supervisor.get(camera_id)
    if manager is None:
        raise HTTPException(status_code=404, detail="stream not found")
    manager.stop()
    _detach_inference(request, camera_id)
    engine = _spatial_engine(request)
    if engine is not None:
        try:
            engine.reset_camera(camera_id)
        except Exception:
            logger.debug("spatial reset failed for %s", camera_id, exc_info=True)
    return {"camera_id": camera_id, "state": manager.state.value}


@router.get("/{camera_id}/status")
def stream_status(
    camera_id: str,
    repository: CameraRepository = Depends(get_repository),
    supervisor: StreamSupervisor = Depends(get_supervisor),
) -> dict:
    camera = repository.get(camera_id)
    if camera is None:
        raise HTTPException(status_code=404, detail="camera not found")
    manager = supervisor.get(camera_id)
    metrics: StreamMetrics | None = manager.status() if manager else None
    body: dict[str, Any] = {
        "camera_id": camera_id,
        "configured": True,
        "enabled": camera.enabled,
        "state": metrics.state.value if metrics else "DISCONNECTED",
    }
    if metrics:
        body["metrics"] = metrics.model_dump()
        if manager and manager.last_error:
            body["last_error"] = manager.last_error
    return body
