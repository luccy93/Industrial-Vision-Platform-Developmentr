"""Video stream + frame contracts."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import Field

from backend.app.domain.common import EntityBase


class StreamStatus(str, Enum):
    active = "active"
    paused = "paused"
    stopped = "stopped"
    error = "error"


class VideoStream(EntityBase):
    """Logical stream bound to a camera (RTSP/file/test pattern in later volumes)."""

    camera_id: str = Field(min_length=1, max_length=128)
    stream_id: str = Field(min_length=1, max_length=128)
    status: StreamStatus = StreamStatus.stopped
    source: Optional[str] = Field(default=None, max_length=1024)
    width: Optional[int] = Field(default=None, ge=1)
    height: Optional[int] = Field(default=None, ge=1)
    fps: Optional[float] = Field(default=None, ge=0)


class Frame(EntityBase):
    """Single decoded frame reference (pixels live outside the contract)."""

    camera_id: str = Field(min_length=1, max_length=128)
    stream_id: Optional[str] = Field(default=None, max_length=128)
    frame_number: int = Field(ge=0)
    width: Optional[int] = Field(default=None, ge=1)
    height: Optional[int] = Field(default=None, ge=1)
    # Storage pointer (e.g. object-store key); never raw pixels in V01.
    uri: Optional[str] = Field(default=None, max_length=1024)
