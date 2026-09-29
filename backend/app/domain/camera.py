"""Camera domain contract."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID

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
    location: Optional[str] = Field(default=None, max_length=256)
    stream_url: Optional[str] = Field(default=None, max_length=1024)
    status: CameraStatus = CameraStatus.unknown
    resolution_width: Optional[int] = Field(default=None, ge=1)
    resolution_height: Optional[int] = Field(default=None, ge=1)
    fps: Optional[float] = Field(default=None, ge=0)
