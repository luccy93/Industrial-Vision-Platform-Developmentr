"""Inference schemas — serializable detection contracts (V03 = detection only).

Coordinate convention: ``x1, y1`` = top-left corner, ``x2, y2`` =
bottom-right corner, all in **original frame pixels** (the adapter rescales
model outputs back to the input frame size). No tracking IDs in V03.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, model_validator

from backend.app.domain.common import utcnow


class InferenceBoundingBox(BaseModel):
    """Axis-aligned box in original-frame pixel coordinates."""

    x1: float = Field(ge=0)
    y1: float = Field(ge=0)
    x2: float = Field(ge=0)
    y2: float = Field(ge=0)

    @model_validator(mode="after")
    def _check_corners(self) -> InferenceBoundingBox:
        if self.x2 < self.x1 or self.y2 < self.y1:
            raise ValueError("bounding box requires x2 >= x1 and y2 >= y1")
        return self

    @property
    def width(self) -> float:
        return self.x2 - self.x1

    @property
    def height(self) -> float:
        return self.y2 - self.y1


class InferenceDetection(BaseModel):
    """One validated object observation from a single frame."""

    id: UUID = Field(default_factory=uuid4)
    camera_id: str = Field(min_length=1, max_length=128)
    frame_id: UUID
    timestamp: datetime = Field(default_factory=utcnow)
    class_id: int = Field(ge=0)
    class_name: str = Field(min_length=1, max_length=128)
    confidence: float = Field(ge=0.0, le=1.0)
    bounding_box: InferenceBoundingBox
    model_name: str = Field(min_length=1, max_length=128)
    inference_time_ms: float = Field(ge=0.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class InferenceResult(BaseModel):
    """Structured, serializable output of one inference pass."""

    frame_id: UUID
    camera_id: str = Field(min_length=1, max_length=128)
    timestamp: datetime = Field(default_factory=utcnow)
    detections: list[InferenceDetection] = Field(default_factory=list)
    inference_time_ms: float = Field(ge=0.0)
    processing_fps: float = Field(default=0.0, ge=0.0)
    model_name: str = Field(min_length=1, max_length=128)
    device: str = Field(min_length=1, max_length=32)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_websocket(self) -> dict[str, Any]:
        """Detection message payload for ``/ws/cameras/{camera_id}``."""
        return {
            "type": "detection",
            "camera_id": self.camera_id,
            "frame_id": str(self.frame_id),
            "timestamp": self.timestamp.isoformat(),
            "detections": [
                {
                    "class_id": detection.class_id,
                    "class_name": detection.class_name,
                    "confidence": detection.confidence,
                    "bounding_box": {
                        "x1": detection.bounding_box.x1,
                        "y1": detection.bounding_box.y1,
                        "x2": detection.bounding_box.x2,
                        "y2": detection.bounding_box.y2,
                    },
                }
                for detection in self.detections
            ],
            "inference_time_ms": self.inference_time_ms,
            "model_name": self.model_name,
        }
