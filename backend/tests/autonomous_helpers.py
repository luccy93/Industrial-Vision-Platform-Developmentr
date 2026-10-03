"""Shared autonomous test builders — deterministic, hermetic, no models.

Mirrors ``backend/tests/quality_helpers.py``: a fixed synthetic epoch keeps
duration assertions stable. V04 tracks come from ``safety_helpers.make_track``
(no second track builder); lane frames are drawn with OpenCV so the geometry
baseline processes real pixels deterministically.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import cv2
import numpy as np

from backend.app.autonomous.schemas import (
    AutonomousProfile,
    Lane,
    LaneType,
    NormalizedPoint,
    PerceivedObject,
    PerceivedObjectState,
    SceneType,
)

_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


def utc(offset_seconds: float = 0.0) -> datetime:
    """Deterministic test clock: exact offsets from a fixed epoch."""
    return _EPOCH + timedelta(seconds=offset_seconds)


def make_profile(**overrides) -> AutonomousProfile:  # type: ignore[no-untyped-def]
    params: dict = {
        "profile_id": "profile-01",
        "camera_id": "cam-01",
        "name": "Road perception",
        "enabled": True,
        "scene_type": SceneType.UNKNOWN,
    }
    params.update(overrides)
    return AutonomousProfile(**params)  # type: ignore[arg-type]


def make_lane_points(
    x0: float = 0.2, x1: float = 0.3, top: float = 0.2, bottom: float = 0.9, n: int = 8
) -> list[NormalizedPoint]:
    """A straight normalized polyline from bottom to top of frame."""
    return [
        NormalizedPoint(x=x0 + (x1 - x0) * i / max(1, n - 1), y=bottom + (top - bottom) * i / max(1, n - 1))
        for i in range(n)
    ]


def make_lane(**overrides) -> Lane:  # type: ignore[no-untyped-def]
    params: dict = {
        "lane_id": "lane-left",
        "points": make_lane_points(),
        "confidence": 0.9,
        "lane_type": LaneType.SOLID,
        "side": "left",
    }
    params.update(overrides)
    return Lane(**params)  # type: ignore[arg-type]


def make_object(**overrides) -> PerceivedObject:  # type: ignore[no-untyped-def]
    params: dict = {
        "object_id": "track-1",
        "track_id": 1,
        "class_name": "car",
        "confidence": 0.9,
        "bounding_box": (0.4, 0.4, 0.6, 0.7),
        "center": (0.5, 0.55),
        "bottom_center": (0.5, 0.7),
        "object_state": PerceivedObjectState.UNKNOWN,
    }
    params.update(overrides)
    return PerceivedObject(**params)  # type: ignore[arg-type]


def make_lane_frame(
    width: int = 640,
    height: int = 480,
    lanes: list[tuple[float, float, float, float]] | None = None,
) -> np.ndarray:
    """BGR frame with bright lane lines on dark asphalt (deterministic)."""
    frame = np.full((height, width, 3), 40, dtype=np.uint8)
    for x0, y0, x1, y1 in lanes or [(0.2, 0.9, 0.35, 0.2), (0.8, 0.9, 0.65, 0.2)]:
        cv2.line(
            frame,
            (int(x0 * width), int(y0 * height)),
            (int(x1 * width), int(y1 * height)),
            (230, 230, 230),
            5,
            cv2.LINE_8,
        )
    return frame


def synthetic_frame(width: int = 640, height: int = 480, value: int = 40) -> np.ndarray:
    """Flat BGR uint8 frame — the no-lane-features control case."""
    return np.full((height, width, 3), value, dtype=np.uint8)
