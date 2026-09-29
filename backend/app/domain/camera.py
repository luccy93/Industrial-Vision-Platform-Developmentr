"""Camera domain contract (V02: ingestion-ready, V01-compatible).

V01 fields (``location``, ``stream_url``, ``status``, ``resolution_*``,
``fps``) are retained as optional legacy aliases so existing callers keep
working. New code should use ``source_type``/``source``/``width``/``height``/
``target_fps`` which map 1:1 to the PostgreSQL ``cameras`` table.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import Field

from backend.app.domain.common import EntityBase, utcnow
from backend.app.domain.stream import SourceType


class CameraStatus(str, Enum):
    online = "online"
    offline = "offline"
    degraded = "degraded"
    unknown = "unknown"


class Camera(EntityBase):
    """Physical or virtual industrial camera."""

    name: str = Field(min_length=1, max_length=128)
    camera_id: str = Field(min_length=1, max_length=128)

    # --- V02 ingestion fields (persisted to PostgreSQL) ---
    source_type: SourceType = SourceType.file
    source: str = Field(default="", max_length=1024)
    enabled: bool = True
    width: int | None = Field(default=None, ge=1)
    height: int | None = Field(default=None, ge=1)
    target_fps: float | None = Field(default=None, ge=0)
    reconnect_enabled: bool = True
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    # --- V01 legacy fields (optional; prefer the V02 fields above) ---
    location: str | None = Field(default=None, max_length=256)
    stream_url: str | None = Field(default=None, max_length=1024)
    status: CameraStatus = CameraStatus.unknown
    resolution_width: int | None = Field(default=None, ge=1)
    resolution_height: int | None = Field(default=None, ge=1)
    fps: float | None = Field(default=None, ge=0)
