"""Lane perception boundary — the engine depends on this, never on a backend.

V08 ships a scripted fixture adapter (tests/dev) plus this boundary; the
deterministic OpenCV geometry baseline lands with the runtime in Commit 02.
Raw lanes carry normalized polylines — the single canonical representation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from uuid import UUID

import numpy as np

from backend.app.autonomous.schemas import LaneType, ModelState, NormalizedPoint, RiskLevel


@dataclass
class RawLane:
    """One lane candidate in normalized image coordinates."""

    points: list[tuple[float, float]]
    confidence: float = 0.0
    lane_type: LaneType = LaneType.UNKNOWN
    side: str | None = None
    metadata: dict = field(default_factory=dict)

    def to_normalized(self) -> list[NormalizedPoint]:
        return [NormalizedPoint(x=x, y=y) for x, y in self.points]


class LaneDetector(ABC):
    """Interface every lane-detection backend implements."""

    def __init__(self, name: str, version: str = "0.0.0") -> None:
        self.name = name
        self.version = version
        self._state = ModelState.NOT_LOADED

    @property
    def state(self) -> ModelState:
        return self._state

    @property
    def is_ready(self) -> bool:
        return self._state is ModelState.READY

    def load(self) -> None:
        if self._state is ModelState.READY:
            return
        self._state = ModelState.LOADING
        try:
            self._load()
        except Exception as exc:
            self._state = ModelState.NOT_READY
            raise RuntimeError(f"lane detector failed to load: {exc}") from exc
        self._state = ModelState.READY

    def unload(self) -> None:
        self._state = ModelState.NOT_LOADED

    @abstractmethod
    def _load(self) -> None:
        """Backend-specific initialization."""

    @abstractmethod
    def detect(
        self,
        image: np.ndarray,
        *,
        camera_id: str,
        frame_id: UUID | None,
    ) -> list[RawLane]:
        """Detect lane boundaries in one frame. Never returns fake lanes."""


class FixtureLaneDetector(LaneDetector):
    """Returns a scripted list of :class:`RawLane` lanes (or none)."""

    def __init__(
        self,
        lanes: list[RawLane] | None = None,
        name: str = "fixture-lanes",
    ) -> None:
        super().__init__(name=name, version="0.0.0-fixture")
        self._lanes = list(lanes or [])

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
            raise ValueError("fixture received an invalid frame")
        return list(self._lanes)


def analyze_lane_departure(
    lanes: list,
    reference_x: float = 0.5,
    bottom_y: float = 0.7,
    warn_edge_distance: float = 0.15,
    critical_edge_distance: float = 0.05,
) -> tuple[RiskLevel, dict]:
    """Lane-departure *risk proxy* from lane geometry (not a measurement).

    Uses the bottom-region average x of each lane polyline (accepting
    ``Lane`` models, ``RawLane`` values, or plain ``(x, y)`` point lists),
    finds the nearest lanes left and right of the camera-center reference,
    and maps the reference's distance to the nearest lane edge into a risk
    level. Returns ``(RiskLevel.UNKNOWN, {...})`` with fewer than two
    flanking lanes — never a fabricated measurement.
    """
    xs: list[float] = []
    for lane in lanes:
        points = lane.points if hasattr(lane, "points") else lane
        bottom = [
            (p.x if hasattr(p, "x") else p[0])
            for p in points
            if (p.y if hasattr(p, "y") else p[1]) >= bottom_y
        ]
        if bottom:
            xs.append(sum(bottom) / len(bottom))
    left = [x for x in xs if x < reference_x]
    right = [x for x in xs if x >= reference_x]
    if not left or not right:
        return RiskLevel.UNKNOWN, {"reason": "fewer than two flanking lanes"}
    lane_left, lane_right = max(left), min(right)
    width = lane_right - lane_left
    if width <= 0.0:
        return RiskLevel.UNKNOWN, {"reason": "degenerate lane geometry"}
    position = (reference_x - lane_left) / width
    edge_distance = min(position, 1.0 - position)
    evidence = {
        "lane_left": round(lane_left, 3),
        "lane_right": round(lane_right, 3),
        "edge_distance": round(edge_distance, 3),
    }
    if edge_distance < critical_edge_distance:
        return RiskLevel.CRITICAL, evidence
    if edge_distance < warn_edge_distance:
        return RiskLevel.HIGH, evidence
    if edge_distance < warn_edge_distance * 2.0:
        return RiskLevel.MEDIUM, evidence
    return RiskLevel.NONE, evidence
