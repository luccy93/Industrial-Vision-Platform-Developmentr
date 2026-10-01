"""Safety API — engine status + bounded in-memory events (no PG writes)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from backend.app.api.v1.cameras import get_repository
from backend.app.ingestion.repository import CameraRepository
from backend.app.safety.engine import SafetyEngine

router = APIRouter(tags=["safety"])


def get_safety_engine(request: Request) -> SafetyEngine:
    engine = getattr(request.app.state, "safety_engine", None)
    if engine is None:
        from backend.app.core.config import get_settings
        from backend.app.safety.rules import default_rules

        engine = SafetyEngine(get_settings(), default_rules(get_settings()))
    return engine


@router.get("/api/v1/safety/status")
def safety_status(engine: SafetyEngine = Depends(get_safety_engine)) -> dict[str, Any]:
    return engine.status()


@router.get("/api/v1/cameras/{camera_id}/safety/events")
def camera_safety_events(
    camera_id: str,
    status: str = Query(default="active", pattern="^(active|resolved|all)$"),
    limit: int = Query(default=50, ge=1, le=200),
    repository: CameraRepository = Depends(get_repository),
    engine: SafetyEngine = Depends(get_safety_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    active = engine.active_events(camera_id, limit)
    recent = engine.recent_events(camera_id, limit) if status in ("resolved", "all") else []
    shown = (active if status in ("active", "all") else []) + recent
    return {
        "camera_id": camera_id,
        "filter": status,
        "count": len(shown),
        "events": [
            {
                **event.to_websocket(),
                "camera_id": camera_id,
            }
            for event in shown[:limit]
        ],
    }


@router.post("/api/v1/cameras/{camera_id}/safety/suppress/{event_id}")
def suppress_event(
    camera_id: str,
    event_id: str,
    repository: CameraRepository = Depends(get_repository),
    engine: SafetyEngine = Depends(get_safety_engine),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    try:
        suppressed = engine.suppress(camera_id, event_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="event not found")
    return {"camera_id": camera_id, "event_id": event_id, "status": suppressed.value}
