"""Autonomous perception API — profile CRUD (PostgreSQL) + runtime status.

Configuration is durable; scenes, objects, trajectories, risks, and events
are in memory and reported separately. Every camera-scoped route validates
the camera exists so profiles can never attach to a missing camera.

Commit 01 ships the request/response contracts and dependencies; the routes
land with the runtime engine in Commit 02.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from backend.app.autonomous.schemas import AutonomousProfile, SceneType
from backend.app.infrastructure.db import get_db, get_session_factory

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


__all__ = [
    "AutonomousProfileCreate",
    "AutonomousProfileUpdate",
    "get_autonomous_engine",
    "get_autonomous_repository",
    "router",
]
