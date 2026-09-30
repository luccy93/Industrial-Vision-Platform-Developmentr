"""Tracking schemas — track identity, state, history, velocity.

Identity semantics (V04): track IDs are **per-camera** integers starting at
1. ``(camera_id, track_id)`` is the globally unique identity; the same
numeric ID on two cameras denotes two independent objects. IDs reset when the
camera's tracker is reset (e.g. stream restart).

Velocity is **image-space** (pixels/second from bounding-box center motion),
NOT physical m/s — no camera calibration exists in V04.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from backend.app.domain.common import utcnow
from backend.app.inference.schemas import InferenceBoundingBox


class TrackState(str, Enum):
    TENTATIVE = "TENTATIVE"
    CONFIRMED = "CONFIRMED"
    LOST = "LOST"
    REMOVED = "REMOVED"


class TrackVelocity(BaseModel):
    """Image-space velocity in pixels/second."""

    x: float = 0.0
    y: float = 0.0
    speed: float = Field(default=0.0, ge=0.0)


class TrackHistoryEntry(BaseModel):
    timestamp: datetime = Field(default_factory=utcnow)
    frame_id: UUID
    bounding_box: InferenceBoundingBox
    confidence: float = Field(ge=0.0, le=1.0)
    center_x: float
    center_y: float


class TrackedObject(BaseModel):
    """One persistent object identity within a camera stream."""

    track_id: int = Field(ge=1)
    camera_id: str = Field(min_length=1, max_length=128)
    class_id: int = Field(ge=0)
    class_name: str = Field(min_length=1, max_length=128)
    confidence: float = Field(ge=0.0, le=1.0)
    bounding_box: InferenceBoundingBox
    timestamp: datetime = Field(default_factory=utcnow)
    frame_id: UUID
    state: TrackState = TrackState.TENTATIVE
    age: int = Field(default=0, ge=0)
    hits: int = Field(default=0, ge=0)
    time_since_update: int = Field(default=0, ge=0)
    velocity: TrackVelocity = Field(default_factory=TrackVelocity)
    history: list[TrackHistoryEntry] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_websocket(self) -> dict[str, Any]:
        return {
            "track_id": self.track_id,
            "class_id": self.class_id,
            "class_name": self.class_name,
            "confidence": self.confidence,
            "bounding_box": {
                "x1": self.bounding_box.x1,
                "y1": self.bounding_box.y1,
                "x2": self.bounding_box.x2,
                "y2": self.bounding_box.y2,
            },
            "state": self.state.value,
            "age": self.age,
            "hits": self.hits,
            "time_since_update": self.time_since_update,
            "velocity": {
                "x": self.velocity.x,
                "y": self.velocity.y,
                "speed": self.velocity.speed,
            },
        }
