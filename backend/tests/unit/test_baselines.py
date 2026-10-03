"""Baseline tests — scene heuristic rules and geometry lane detection."""

from __future__ import annotations

from backend.app.autonomous.lane_baseline import GeometryLaneDetector
from backend.app.autonomous.scene_baseline import HeuristicSceneClassifier
from backend.app.autonomous.schemas import SceneType
from backend.tests.autonomous_helpers import make_lane_frame, synthetic_frame


def test_scene_empty_is_unknown() -> None:
    model = HeuristicSceneClassifier()
    model.load()
    hypothesis = model.classify(camera_id="c", object_classes=[], object_count=0, lane_count=0)
    assert hypothesis.scene_type is SceneType.UNKNOWN
    assert hypothesis.confidence == 0.0


def test_scene_road_with_vehicles_and_lanes() -> None:
    model = HeuristicSceneClassifier()
    model.load()
    hypothesis = model.classify(
        camera_id="c", object_classes=["car", "truck"], object_count=4, lane_count=2
    )
    assert hypothesis.scene_type is SceneType.ROAD
    assert hypothesis.confidence == 0.75


def test_scene_warehouse_without_road_vehicles() -> None:
    model = HeuristicSceneClassifier()
    model.load()
    hypothesis = model.classify(
        camera_id="c", object_classes=["forklift", "pallet"], object_count=3, lane_count=0
    )
    assert hypothesis.scene_type is SceneType.WAREHOUSE


def test_scene_robot_classes_win() -> None:
    model = HeuristicSceneClassifier()
    model.load()
    hypothesis = model.classify(
        camera_id="c", object_classes=["agv", "car"], object_count=2, lane_count=0
    )
    assert hypothesis.scene_type is SceneType.INDOOR_MOBILE_ROBOT


def test_scene_parking_weak_evidence() -> None:
    model = HeuristicSceneClassifier()
    model.load()
    hypothesis = model.classify(
        camera_id="c", object_classes=["car"], object_count=2, lane_count=0
    )
    assert hypothesis.scene_type is SceneType.PARKING
    assert hypothesis.confidence == 0.4


def test_scene_yard_with_people() -> None:
    model = HeuristicSceneClassifier()
    model.load()
    hypothesis = model.classify(
        camera_id="c", object_classes=["person", "toolbox"], object_count=3, lane_count=0
    )
    assert hypothesis.scene_type is SceneType.INDUSTRIAL_YARD


def test_scene_unmatched_mix_is_unknown() -> None:
    model = HeuristicSceneClassifier()
    model.load()
    hypothesis = model.classify(
        camera_id="c", object_classes=["dog"], object_count=1, lane_count=0
    )
    assert hypothesis.scene_type is SceneType.UNKNOWN


def test_geometry_lanes_on_synthetic_frame() -> None:
    detector = GeometryLaneDetector()
    detector.load()
    assert detector.is_ready
    lanes = detector.detect(make_lane_frame(), camera_id="c", frame_id=None)
    sides = {lane.side for lane in lanes}
    assert sides == {"left", "right"}
    for lane in lanes:
        assert len(lane.points) == 8
        assert all(0.0 <= x <= 1.0 and 0.0 <= y <= 1.0 for x, y in lane.points)
        assert lane.lane_type.value == "UNKNOWN"
        assert lane.confidence > 0.0


def test_geometry_lanes_blank_frame_has_none() -> None:
    detector = GeometryLaneDetector()
    detector.load()
    assert detector.detect(synthetic_frame(), camera_id="c", frame_id=None) == []


def test_geometry_lanes_rejects_invalid_frame() -> None:
    import numpy as np
    import pytest

    detector = GeometryLaneDetector()
    detector.load()
    with pytest.raises(ValueError):
        detector.detect(np.zeros((0, 0, 3), dtype=np.uint8), camera_id="c", frame_id=None)


def test_geometry_lanes_tiny_frame_returns_none() -> None:
    import numpy as np

    detector = GeometryLaneDetector()
    detector.load()
    assert detector.detect(np.zeros((8, 8, 3), dtype=np.uint8), camera_id="c", frame_id=None) == []
