"""Ingestion frame model — metadata + efficient in-memory image handle.

The raw image lives as a ``numpy.ndarray`` (BGR, ``uint8``) held by
reference — it is never deep-copied between pipeline stages and is
excluded from JSON serialization. Downstream (V03+) stages receive the
same array reference.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from backend.app.domain.common import utcnow


class IngestionFrame(BaseModel):
    """Single captured frame with transport-safe metadata."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    frame_id: UUID = Field(default_factory=uuid4)
    camera_id: str = Field(min_length=1, max_length=128)
    timestamp: Any = Field(default_factory=utcnow)
    frame_number: int = Field(ge=0)
    width: int = Field(ge=1)
    height: int = Field(ge=1)
    fps: float = Field(default=0.0, ge=0.0)
    image: np.ndarray = Field(exclude=True, repr=False)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_dump_safe(self) -> dict[str, Any]:
        """Metadata-only dict for WebSocket/API transport (no image bytes)."""
        data = self.model_dump(exclude={"image"})
        data["frame_id"] = str(self.frame_id)
        data["timestamp"] = self.timestamp.isoformat()
        return data
