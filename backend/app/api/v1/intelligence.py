"""Event & risk intelligence API — read-oriented intelligence endpoints.

All runtime intelligence state lives in memory in the engine; there is no
persistent store and no mutation API. In particular V09 exposes no
suppression, acknowledgement, or incident-management endpoints — those
belong to V10.

Commit 01 ships the request/response contracts and dependencies; the routes
land with the runtime engine in Commit 02.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from backend.app.infrastructure.db import get_db, get_session_factory
from backend.app.ingestion.repository import CameraRepository
from backend.app.intelligence.schemas import RiskCluster, UnifiedEvent

logger = logging.getLogger("industrial-vision.api")

router = APIRouter(tags=["intelligence"])


def get_intelligence_engine(request: Request) -> Any:
    from backend.app.intelligence.engine import IntelligenceEngine

    engine = getattr(request.app.state, "intelligence_engine", None)
    return engine if isinstance(engine, IntelligenceEngine) else None


def get_camera_repository(request: Request, session: Session = Depends(get_db)) -> Any:
    factory = getattr(request.app.state, "session_factory", None)
    if factory is None:
        factory = get_session_factory(str(session.get_bind().url))  # type: ignore[union-attr]
    return CameraRepository(factory)


def _event_payload(event: UnifiedEvent) -> dict[str, Any]:
    payload = event.to_websocket()
    payload["reason"] = event.reason
    return payload


def _cluster_payload(cluster: RiskCluster) -> dict[str, Any]:
    return cluster.to_websocket()


__all__ = [
    "_cluster_payload",
    "_event_payload",
    "get_camera_repository",
    "get_intelligence_engine",
    "router",
]


def _require_camera(repository: Any, camera_id: str) -> None:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")


def _require_engine(engine: Any) -> Any:
    if engine is None:
        raise HTTPException(status_code=503, detail="intelligence engine unavailable")
    return engine


@router.get("/api/v1/intelligence/status")
def intelligence_status(engine: Any = Depends(get_intelligence_engine)) -> dict[str, Any]:
    return _require_engine(engine).status()


@router.get("/api/v1/cameras/{camera_id}/intelligence/events")
def intelligence_events(
    camera_id: str,
    status: str = Query(default="all"),
    limit: int = Query(default=50, ge=1, le=200),
    repository: Any = Depends(get_camera_repository),
    engine: Any = Depends(get_intelligence_engine),
) -> dict[str, Any]:
    _require_camera(repository, camera_id)
    engine = _require_engine(engine)
    wanted = status.strip().upper()
    events = list(engine.active_events(camera_id, limit)) + list(engine.recent_events(camera_id, limit))
    if wanted != "ALL":
        events = [e for e in events if e.status.value == wanted]
    events = events[:limit]
    return {"camera_id": camera_id, "count": len(events), "events": [_event_payload(e) for e in events]}


@router.get("/api/v1/cameras/{camera_id}/intelligence/clusters")
def intelligence_clusters(
    camera_id: str,
    status: str = Query(default="all"),
    limit: int = Query(default=50, ge=1, le=200),
    repository: Any = Depends(get_camera_repository),
    engine: Any = Depends(get_intelligence_engine),
) -> dict[str, Any]:
    _require_camera(repository, camera_id)
    engine = _require_engine(engine)
    wanted = status.strip().upper()
    clusters = list(engine.active_clusters(camera_id, limit)) + list(engine.recent_clusters(camera_id, limit))
    if wanted != "ALL":
        clusters = [c for c in clusters if c.status.value == wanted]
    clusters = clusters[:limit]
    return {
        "camera_id": camera_id,
        "count": len(clusters),
        "clusters": [_cluster_payload(c) for c in clusters],
    }


@router.get("/api/v1/cameras/{camera_id}/intelligence/risk")
def intelligence_risk(
    camera_id: str,
    repository: Any = Depends(get_camera_repository),
    engine: Any = Depends(get_intelligence_engine),
) -> dict[str, Any]:
    _require_camera(repository, camera_id)
    engine = _require_engine(engine)
    latest = engine.latest(camera_id)
    if latest is None:
        return {
            "camera_id": camera_id,
            "risk_level": "UNKNOWN",
            "risk_score": 0.0,
            "priority": "P4",
            "active_events": 0,
            "active_clusters": 0,
            "timestamp": None,
        }
    return {
        "camera_id": camera_id,
        "risk_level": latest.highest_risk.risk_level.value,
        "risk_score": latest.highest_risk.risk_score,
        "priority": latest.highest_priority.value,
        "active_events": latest.active_event_count,
        "active_clusters": latest.active_cluster_count,
        "timestamp": latest.timestamp.isoformat(),
    }
