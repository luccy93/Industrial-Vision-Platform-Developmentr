"""Deterministic scene-classification baseline (documented heuristic).

The baseline maps lightweight summary features — object class mix, object
count, lane presence — to a scene type with fixed confidences. It is a
transparent starting point for tests and uncalibrated deployments, not a
learned classifier: thresholds and vehicle-class sets are constructor
parameters, and every verdict carries its reason.
"""

from __future__ import annotations

from typing import Any

from backend.app.autonomous.scene import SceneClassifier
from backend.app.autonomous.schemas import SceneHypothesis, SceneType

DEFAULT_VEHICLE_CLASSES = frozenset(
    {"car", "truck", "bus", "motorcycle", "motorbike", "bicycle", "van", "vehicle"}
)
DEFAULT_WAREHOUSE_CLASSES = frozenset({"forklift", "pallet", "pallet_jack", "crate", "box", "shelf", "rack"})
DEFAULT_ROBOT_CLASSES = frozenset({"mobile_robot", "agv", "amr", "robot"})


class HeuristicSceneClassifier(SceneClassifier):
    """Rule-based scene baseline over class mix, counts, and lane presence."""

    def __init__(
        self,
        vehicle_classes: frozenset[str] | None = None,
        warehouse_classes: frozenset[str] | None = None,
        robot_classes: frozenset[str] | None = None,
        name: str = "heuristic-scene",
    ) -> None:
        super().__init__(name=name, version="1.0.0-baseline")
        self._vehicles = vehicle_classes or DEFAULT_VEHICLE_CLASSES
        self._warehouse = warehouse_classes or DEFAULT_WAREHOUSE_CLASSES
        self._robots = robot_classes or DEFAULT_ROBOT_CLASSES

    def _load(self) -> None:
        return None

    def classify(
        self,
        *,
        camera_id: str,
        object_classes: list[str],
        object_count: int,
        lane_count: int,
        metadata: dict[str, Any] | None = None,
    ) -> SceneHypothesis:
        classes = {c.strip().lower() for c in object_classes if c.strip()}
        vehicles = len(classes & self._vehicles)
        warehouse_hits = len(classes & self._warehouse)
        robot_hits = len(classes & self._robots)
        people = "person" in classes

        if object_count <= 0 and lane_count <= 0:
            return SceneHypothesis(
                scene_type=SceneType.UNKNOWN,
                confidence=0.0,
                reason="no scene evidence (no objects, no lanes)",
            )
        if robot_hits > 0:
            return SceneHypothesis(
                scene_type=SceneType.INDOOR_MOBILE_ROBOT,
                confidence=0.6,
                reason=f"mobile-robot classes present ({robot_hits})",
            )
        if warehouse_hits > 0 and vehicles == 0:
            return SceneHypothesis(
                scene_type=SceneType.WAREHOUSE,
                confidence=0.6,
                reason=f"warehouse classes present ({warehouse_hits}), no road vehicles",
            )
        if vehicles > 0 and lane_count > 0:
            return SceneHypothesis(
                scene_type=SceneType.ROAD,
                confidence=0.75,
                reason=f"{vehicles} vehicle class(es) with {lane_count} lane(s)",
            )
        if vehicles > 0 and 1 <= object_count <= 4 and not people:
            return SceneHypothesis(
                scene_type=SceneType.PARKING,
                confidence=0.4,
                reason="few vehicles, no lanes, no people (weak parking evidence)",
            )
        if people:
            return SceneHypothesis(
                scene_type=SceneType.INDUSTRIAL_YARD,
                confidence=0.5,
                reason="people with equipment but no road structure",
            )
        return SceneHypothesis(
            scene_type=SceneType.UNKNOWN,
            confidence=0.0,
            reason="class mix matches no baseline rule",
        )
