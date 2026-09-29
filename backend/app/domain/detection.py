"""Detection + tracking contracts."""

from __future__ import annotations

from typing import Any, Dict, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from backend.app.domain.common import EntityBase


class BoundingBox(BaseModel):
    """Axis-aligned box in pixel coordinates."""

    x: float = Field(ge=0)
    y: float = Field(ge=0)
    width: float = Field(gt=0)
    height: float = Field(gt=0)

    @property
    def x2(self) -> float:
        return self.x + self.width

    @property
    def y2(self) -> float:
        return self.y + self.height


class Detection(EntityBase):
    """Single-frame model observation."""

    camera_id: str = Field(min_length=1, max_length=128)
    frame_id: Optional[UUID] = None
    class_name: str = Field(min_length=1, max_length=128)
    confidence: float = Field(ge=0.0, le=1.0)
    bounding_box: BoundingBox


class TrackedObject(EntityBase):
    """Multi-frame identity produced by the tracker (full logic in later volumes)."""

    camera_id: str = Field(min_length=1, max_length=128)
    track_id: str = Field(min_length=1, max_length=128)
    class_name: str = Field(min_length=1, max_length=128)
    confidence: float = Field(ge=0.0, le=1.0)
    bounding_box: BoundingBox
    lost_frames: int = Field(default=0, ge=0)
