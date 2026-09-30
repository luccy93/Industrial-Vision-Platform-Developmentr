"""Shared tracking test builders — synthetic detections (no model needed)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from backend.app.inference.schemas import InferenceBoundingBox, InferenceDetection


def utc(offset_seconds: float = 0.0) -> datetime:
    return datetime.now(UTC) + timedelta(seconds=offset_seconds)


def make_detection(
    x1: float = 100.0,
    conf: float = 0.9,
    class_id: int = 0,
    class_name: str = "person",
    camera_id: str = "cam-t",
    timestamp: datetime | None = None,
    frame_id: UUID | None = None,
) -> InferenceDetection:
    return InferenceDetection(
        camera_id=camera_id,
        frame_id=frame_id or uuid4(),
        timestamp=timestamp or utc(),
        class_id=class_id,
        class_name=class_name,
        confidence=conf,
        bounding_box=InferenceBoundingBox(x1=x1, y1=100.0, x2=x1 + 50.0, y2=200.0),
        model_name="mock",
        inference_time_ms=1.0,
    )
