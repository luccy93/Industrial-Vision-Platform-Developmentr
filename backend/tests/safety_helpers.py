"""Shared safety test builders — synthetic confirmed tracks (no model needed)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from backend.app.inference.schemas import InferenceBoundingBox
from backend.app.tracking.schemas import (
    TrackedObject,
    TrackHistoryEntry,
    TrackState,
    TrackVelocity,
)


def utc(offset_seconds: float = 0.0) -> datetime:
    return datetime.now(UTC) + timedelta(seconds=offset_seconds)


def make_track(
    track_id: int = 1,
    class_name: str = "person",
    box: tuple[float, float, float, float] = (100.0, 100.0, 150.0, 300.0),
    state: TrackState = TrackState.CONFIRMED,
    confidence: float = 0.9,
    history_boxes: list[tuple[float, float, float, float]] | None = None,
    history_span_seconds: float = 5.0,
    velocity: TrackVelocity | None = None,
    camera_id: str = "cam-s",
) -> TrackedObject:
    x1, y1, x2, y2 = box
    boxes = history_boxes if history_boxes is not None else [box] * 5
    span = max(history_span_seconds, 0.0)
    step = span / max(len(boxes), 1)
    history = [
        TrackHistoryEntry(
            timestamp=utc(i * step),
            frame_id=uuid4(),
            bounding_box=InferenceBoundingBox(x1=b[0], y1=b[1], x2=b[2], y2=b[3]),
            confidence=confidence,
            center_x=(b[0] + b[2]) / 2.0,
            center_y=(b[1] + b[3]) / 2.0,
        )
        for i, b in enumerate(boxes)
    ]
    return TrackedObject(
        track_id=track_id,
        camera_id=camera_id,
        class_id=0,
        class_name=class_name,
        confidence=confidence,
        bounding_box=InferenceBoundingBox(x1=x1, y1=y1, x2=x2, y2=y2),
        frame_id=uuid4(),
        timestamp=utc(span),
        state=state,
        age=len(boxes),
        hits=len(boxes),
        velocity=velocity or TrackVelocity(),
        history=history,
    )
