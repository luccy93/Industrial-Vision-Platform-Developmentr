"""Deterministic lane-detection baseline — OpenCV edge + line geometry.

The baseline processes real frame pixels (grayscale → blur → Canny →
probabilistic Hough → slope/position clustering into left/right boundaries)
and emits normalized polylines with support-based confidence. It is suitable
for synthetic and structured test frames; marking-type classification is out
of scope, so ``lane_type`` is always ``UNKNOWN`` (honest, documented).
"""

from __future__ import annotations

import math
from uuid import UUID

import cv2
import numpy as np

from backend.app.autonomous.lanes import LaneDetector, RawLane
from backend.app.autonomous.schemas import LaneType


def _fit_line(points: list[tuple[float, float]]) -> tuple[float, float] | None:
    """Least-squares x = m*y + b over pixel points; ``None`` when degenerate."""
    if len(points) < 2:
        return None
    ys = np.array([p[1] for p in points], dtype=np.float64)
    xs = np.array([p[0] for p in points], dtype=np.float64)
    if float(np.ptp(ys)) < 1e-9:
        return None
    design = np.vstack([ys, np.ones_like(ys)]).T
    try:
        (slope, intercept), _, _, _ = np.linalg.lstsq(design, xs, rcond=None)
    except Exception:
        return None
    if not math.isfinite(slope) or not math.isfinite(intercept):
        return None
    return (float(slope), float(intercept))


class GeometryLaneDetector(LaneDetector):
    """Edge + Hough lane-boundary baseline in normalized coordinates."""

    def __init__(
        self,
        canny_low: int = 50,
        canny_high: int = 150,
        hough_threshold: int = 60,
        min_line_length: int = 80,
        max_line_gap: int = 20,
        min_slope: float = 0.3,
        name: str = "geometry-lanes",
    ) -> None:
        super().__init__(name=name, version="1.0.0-baseline")
        self.canny_low = canny_low
        self.canny_high = canny_high
        self.hough_threshold = hough_threshold
        self.min_line_length = min_line_length
        self.max_line_gap = max_line_gap
        self.min_slope = min_slope

    def _load(self) -> None:
        return None

    def detect(
        self,
        image: np.ndarray,
        *,
        camera_id: str,
        frame_id: UUID | None,
    ) -> list[RawLane]:
        if not isinstance(image, np.ndarray) or image.ndim not in (2, 3) or image.size == 0:
            raise ValueError("lane detector received an invalid frame")
        gray = image if image.ndim == 2 else cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        height, width = gray.shape[:2]
        if height < 16 or width < 16:
            return []
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        edges = cv2.Canny(blurred, self.canny_low, self.canny_high)
        lines = cv2.HoughLinesP(
            edges,
            1,
            np.pi / 180,
            self.hough_threshold,
            minLineLength=self.min_line_length,
            maxLineGap=self.max_line_gap,
        )
        if lines is None:
            return []

        left: list[tuple[float, float]] = []
        right: list[tuple[float, float]] = []
        segments = np.asarray(lines).reshape(-1, 4)
        for segment in segments:
            x1, y1, x2, y2 = (float(v) for v in segment)
            run = x2 - x1
            rise = y2 - y1
            if abs(run) < 1e-9:
                continue
            slope = rise / run
            if abs(slope) < self.min_slope:
                continue  # near-horizontal: not a lane boundary
            length = math.hypot(run, rise)
            if length < self.min_line_length / 2.0:
                continue
            # In image coords (y down), the left boundary runs bottom-left →
            # top-center (negative dx/dy); the right boundary mirrors it.
            fit = _fit_line([(x1, y1), (x2, y2)])
            if fit is None:
                continue
            (left if fit[0] < 0 else right).append((x1, y1))
            (left if fit[0] < 0 else right).append((x2, y2))

        lanes: list[RawLane] = []
        for index, (points, side) in enumerate(((left, "left"), (right, "right"))):
            if len(points) < 4:
                continue
            fit = _fit_line(points)
            if fit is None:
                continue
            slope, intercept = fit
            lane = self._to_lane(points, slope, intercept, width, height, side, index)
            if lane is not None:
                lanes.append(lane)
        return lanes

    def _to_lane(
        self,
        points: list[tuple[float, float]],
        slope: float,
        intercept: float,
        width: int,
        height: int,
        side: str,
        index: int,
    ) -> RawLane | None:
        ys = sorted({p[1] for p in points})
        if len(ys) < 2:
            return None
        samples = 8
        polyline = [
            (
                min(
                    1.0,
                    max(0.0, (slope * (ys[0] + (ys[-1] - ys[0]) * i / (samples - 1)) + intercept) / width),
                ),
                min(1.0, max(0.0, (ys[0] + (ys[-1] - ys[0]) * i / (samples - 1)) / height)),
            )
            for i in range(samples)
        ]
        support = sum(math.hypot(b[0] - a[0], b[1] - a[1]) for a, b in zip(polyline, polyline[1:]))
        confidence = round(min(1.0, support / 1.5), 3)
        if confidence <= 0.0:
            return None
        return RawLane(
            points=polyline,
            confidence=confidence,
            lane_type=LaneType.UNKNOWN,
            side=side,
            metadata={"model": "geometry", "support": round(support, 3)},
        )
