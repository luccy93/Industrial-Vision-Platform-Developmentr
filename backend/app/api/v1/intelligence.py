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

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from backend.app.infrastructure.db import get_db, get_session_factory
from backend.app.intelligence.schemas import RiskCluster, UnifiedEvent

logger = logging.getLogger("industrial-vision.api")

router = APIRouter(tags=["intelligence"])


def get_intelligence_engine(request: Request) -> Any:
    from backend.app.intelligence.engine import IntelligenceEngine

    engine = getattr(request.app.state, "intelligence_engine", None)
    return engine if isinstance(engine, IntelligenceEngine) else None


def get_camera_repository(request: Request, session: Session = Depends(get_db)) -> Any:
    from backend.app.ingestion.repository import CameraRepository

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
