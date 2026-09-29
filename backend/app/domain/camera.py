"""Camera domain contract."""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from backend.app.domain.common import EntityBase


class CameraStatus(str, Enum):
    online = "online"
    offline = "offline"
    degraded = "degraded"
    unknown = "unknown"


class Camera(EntityBase):
    """Physical or virtual industrial camera."""

    name: str = Field(min_length=1, max_length=128)
    camera_id: str = Field(min_length=1, max_length=128)
    location: str | None = Field(default=None, max_length=256)
    stream_url: str | None = Field(default=None, max_length=1024)
    status: CameraStatus = CameraStatus.unknown
    resolution_width: int | None = Field(default=None, ge=1)
    resolution_height: int | None = Field(default=None, ge=1)
    fps: float | None = Field(default=None, ge=0)
