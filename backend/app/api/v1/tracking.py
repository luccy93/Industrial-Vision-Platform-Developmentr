"""Tracking API — status + current per-camera tracks (runtime state only).

Active tracker state stays in memory; PostgreSQL keeps configuration and
future historical events. No per-frame persistence in V04.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.app.api.v1.cameras import get_repository
from backend.app.inference.worker import InferenceSupervisor
from backend.app.ingestion.repository import CameraRepository
from backend.app.tracking.manager import TrackingManager

router = APIRouter(tags=["tracking"])


def get_tracking_manager(request: Request) -> TrackingManager:
    manager = getattr(request.app.state, "tracking_manager", None)
    if manager is None:
        from backend.app.core.config import get_settings

        manager = TrackingManager(get_settings())
    return manager


def get_inference_supervisor(request: Request) -> InferenceSupervisor:
    supervisor = getattr(request.app.state, "inference_supervisor", None)
    if supervisor is None:
        supervisor = InferenceSupervisor()
    return supervisor


@router.get("/api/v1/tracking/status", summary="Tracking engine status")
def tracking_status(manager: TrackingManager = Depends(get_tracking_manager)) -> dict[str, Any]:
    return manager.status()


@router.get("/api/v1/cameras/{camera_id}/tracks")
def camera_tracks(
    camera_id: str,
    repository: CameraRepository = Depends(get_repository),
    manager: TrackingManager = Depends(get_tracking_manager),
    supervisor: InferenceSupervisor = Depends(get_inference_supervisor),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    worker = supervisor.get(camera_id)
    _, tracks = worker.latest_tracked() if worker else (None, [])
    return {
        "camera_id": camera_id,
        "tracking_running": worker.running if worker else False,
        "count": len(tracks),
        "tracks": [track.to_websocket() for track in tracks],
    }
