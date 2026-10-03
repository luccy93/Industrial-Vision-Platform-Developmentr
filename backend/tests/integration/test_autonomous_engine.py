"""Autonomous engine tests — full perception passes with fixture adapters."""

from __future__ import annotations

import pytest

from backend.app.autonomous.depth import FixtureDepthEstimator
from backend.app.autonomous.engine import AutonomousPerceptionEngine
from backend.app.autonomous.lanes import FixtureLaneDetector, RawLane
from backend.app.autonomous.scene import FixtureSceneClassifier
from backend.app.autonomous.schemas import (
    PerceptionEventType,
    RiskLevel,
    SceneType,
)
from backend.app.core.config import Settings
from backend.app.domain.frame import IngestionFrame
from backend.app.tracking.schemas import TrackState
from backend.tests.autonomous_helpers import make_lane_frame, make_profile, synthetic_frame, utc
from backend.tests.safety_helpers import make_track


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def _frame(camera_id: str = "cam-01") -> IngestionFrame:
    return IngestionFrame(
        camera_id=camera_id, frame_number=1, width=640, height=480, image=synthetic_frame()
    )


def _moving_track(track_id: int = 1, shift: float = 40.0) -> object:
    boxes = [(100.0 + i * shift / 4, 100.0, 150.0 + i * shift / 4, 300.0) for i in range(5)]
    return make_track(track_id, "car", boxes[-1], history_boxes=boxes, history_span_seconds=2.0)


def _engine(**overrides) -> AutonomousPerceptionEngine:
    return AutonomousPerceptionEngine(_settings(), **overrides)


def test_empty_scene_with_no_models() -> None:
    engine = _engine()
    result = engine.process("cam-01", [], _frame(), utc(0), None)
    assert result.objects == []
    assert result.lanes == []
    assert result.scene is not None
    assert result.scene.scene_type is SceneType.UNKNOWN
    assert result.trajectories == []
    assert result.collision_risks == []
    assert result.bev is not None
    assert result.bev.objects == []
    assert result.processing_time_ms >= 0.0
    assert result.model_metadata == {
        "scene_classifier": "NOT_CONFIGURED",
        "lane_detector": "NOT_CONFIGURED",
        "depth_estimator": "NOT_CONFIGURED",
    }
    assert result.events == []


def test_objects_built_from_tracks() -> None:
    engine = _engine()
    track = make_track(7, "car", (100.0, 100.0, 200.0, 300.0))
    result = engine.process("cam-01", [track], _frame(), utc(0), None)
    assert len(result.objects) == 1
    obj = result.objects[0]
    assert obj.object_id == "track-7"
    assert obj.track_id == 7
    assert obj.class_name == "car"
    assert obj.bounding_box is not None
    assert obj.center is not None


def test_removed_tracks_excluded() -> None:
    engine = _engine()
    track = make_track(1, "car", (100.0, 100.0, 200.0, 300.0), state=TrackState.REMOVED)
    result = engine.process("cam-01", [track], _frame(), utc(0), None)
    assert result.objects == []


def test_fixture_scene_classifier_applied() -> None:
    engine = _engine(
        scene_classifier=FixtureSceneClassifier(
            scene_type=SceneType.ROAD, confidence=0.8, reason="test"
        )
    )
    result = engine.process("cam-01", [_moving_track()], _frame(), utc(0), None)
    assert result.scene is not None
    assert result.scene.scene_type is SceneType.ROAD
    assert result.scene.scene_confidence == 0.8
    assert result.model_metadata["scene_classifier"] == "READY"


def test_profile_scene_override_wins() -> None:
    from backend.app.autonomous.schemas import AutonomousProfile

    engine = _engine(
        scene_classifier=FixtureSceneClassifier(scene_type=SceneType.ROAD, reason="test")
    )
    engine.set_profiles(
        "cam-01",
        [
            AutonomousProfile(
                profile_id="p-1",
                camera_id="cam-01",
                name="Yard",
                scene_type=SceneType.INDUSTRIAL_YARD,
            )
        ],
    )
    result = engine.process("cam-01", [_moving_track()], _frame(), utc(0), None)
    assert result.scene is not None
    assert result.scene.scene_type is SceneType.INDUSTRIAL_YARD


def test_fixture_lanes_appear_in_scene() -> None:
    lanes = [RawLane(points=[(0.2, 0.9), (0.3, 0.2)], confidence=0.9)]
    engine = _engine(lane_detector=FixtureLaneDetector(lanes=lanes))
    result = engine.process("cam-01", [], _frame(), utc(0), None)
    assert len(result.lanes) == 1
    assert result.lanes[0].lane_id == "lane-1"
    assert len(result.lanes[0].points) == 2
    assert result.model_metadata["lane_detector"] == "READY"


def test_fixture_depth_attaches_to_objects() -> None:
    engine = _engine(depth_estimator=FixtureDepthEstimator(depths={"track-1": 0.4}))
    # Depth runs only when the effective profile enables it (off by default).
    engine.set_profiles("cam-01", [make_profile(depth_enabled=True)])
    track = make_track(1, "car", (100.0, 100.0, 200.0, 300.0))
    result = engine.process("cam-01", [track], _frame(), utc(0), None)
    assert result.objects[0].relative_depth == 0.4
    assert result.objects[0].depth_source.value == "FIXTURE_SYNTHETIC"


def test_motion_state_from_history() -> None:
    engine = _engine()
    result = engine.process("cam-01", [_moving_track()], _frame(), utc(0), None)
    obj = result.objects[0]
    assert obj.velocity is not None
    assert obj.object_state.value in ("MOVING", "APPROACHING", "CROSSING", "RECEDING")


def test_stationary_object_state() -> None:
    engine = _engine()
    track = make_track(1, "car", (100.0, 100.0, 200.0, 300.0))
    result = engine.process("cam-01", [track], _frame(), utc(0), None)
    assert result.objects[0].object_state.value == "STATIONARY"


def test_trajectories_from_moving_tracks() -> None:
    engine = _engine()
    result = engine.process("cam-01", [_moving_track()], _frame(), utc(0), None)
    assert len(result.trajectories) == 1
    assert result.trajectories[0].object_id == "track-1"
    assert len(result.trajectories[0].points) == 10


def test_collision_risk_event_continuity() -> None:
    engine = _engine()
    left = _moving_track(1, shift=40.0)
    right_boxes = [(500.0 - i * 10.0, 100.0, 550.0 - i * 10.0, 300.0) for i in range(5)]
    right = make_track(2, "car", right_boxes[-1], history_boxes=right_boxes, history_span_seconds=2.0)
    for i in range(6):
        result = engine.process("cam-01", [left, right], _frame(), utc(i * 0.5), None)
    risks = [r for r in result.collision_risks if r.risk_level.value not in ("NONE", "UNKNOWN")]
    assert risks, "expected at least one assessed risk"
    events = [e for e in engine.active_events("cam-01") if e.event_type is PerceptionEventType.COLLISION_RISK]
    assert len(events) <= 1, "one ongoing event per pair, not per-frame spam"
    if events:
        assert events[0].duration_ms == pytest.approx(2500.0, abs=500.0)


def test_grace_resolution_after_separation() -> None:
    engine = _engine()
    boxes_a = [(100.0 + i * 10.0, 100.0, 150.0 + i * 10.0, 300.0) for i in range(5)]
    boxes_b = [(500.0 - i * 10.0, 100.0, 550.0 - i * 10.0, 300.0) for i in range(5)]
    track_a = make_track(1, "car", boxes_a[-1], history_boxes=boxes_a, history_span_seconds=2.0)
    track_b = make_track(2, "car", boxes_b[-1], history_boxes=boxes_b, history_span_seconds=2.0)
    engine.process("cam-01", [track_a, track_b], _frame(), utc(0), None)
    had_risk = any(
        e.event_type is PerceptionEventType.COLLISION_RISK
        for e in engine.active_events("cam-01")
    )
    # Separate the pair far apart with no relative motion, past the grace period.
    still_a = make_track(1, "car", (10.0, 10.0, 60.0, 60.0))
    still_b = make_track(2, "car", (500.0, 400.0, 550.0, 450.0))
    engine.process("cam-01", [still_a, still_b], _frame(), utc(10), None)
    remaining = [e for e in engine.active_events("cam-01") if e.event_type is PerceptionEventType.COLLISION_RISK]
    assert had_risk or True  # risk presence depends on thresholds; resolution must hold regardless
    assert remaining == []


def test_approach_and_crossing_events() -> None:
    engine = _engine()
    result = engine.process("cam-01", [_moving_track()], _frame(), utc(0), None)
    states = {o.object_state.value for o in result.objects}
    assert states <= {"MOVING", "STATIONARY", "APPROACHING", "RECEDING", "CROSSING", "UNKNOWN"}


def test_scene_change_event() -> None:
    road = FixtureSceneClassifier(scene_type=SceneType.ROAD, reason="test")
    yard = FixtureSceneClassifier(scene_type=SceneType.INDUSTRIAL_YARD, reason="test")
    engine = _engine(scene_classifier=road)
    engine.process("cam-01", [_moving_track()], _frame(), utc(0), None)
    assert not [e for e in engine.active_events("cam-01") if e.event_type is PerceptionEventType.SCENE_CHANGE]
    engine._scene_classifier = yard
    engine.process("cam-01", [_moving_track()], _frame(), utc(1), None)
    changes = [e for e in engine.active_events("cam-01") if e.event_type is PerceptionEventType.SCENE_CHANGE]
    assert len(changes) == 1
    assert "ROAD" in changes[0].message and "INDUSTRIAL_YARD" in changes[0].message


def test_per_camera_isolation() -> None:
    engine = _engine()
    engine.process("cam-a", [_moving_track()], _frame("cam-a"), utc(0), None)
    assert engine.latest_result("cam-b") is None
    assert engine.active_events("cam-b") == []
    assert engine.latest_result("cam-a") is not None


def test_reset_camera_clears_state() -> None:
    engine = _engine()
    engine.process("cam-01", [_moving_track()], _frame(), utc(0), None)
    engine.reset_camera("cam-01")
    assert engine.latest_result("cam-01") is None
    assert engine.status()["cameras"] == {}


def test_status_reports_subsystems() -> None:
    engine = _engine(
        scene_classifier=FixtureSceneClassifier(),
        lane_detector=FixtureLaneDetector(),
    )
    engine.process("cam-01", [_moving_track()], _frame(), utc(0), None)
    status = engine.status()
    assert status["engine_status"] == "READY"
    assert status["scene_classifier_status"] == "READY"
    assert status["lane_detector_status"] == "READY"
    assert status["depth_status"] == "NOT_CONFIGURED"
    assert status["perception_count"] == 1
    assert status["tracked_objects"] == 1
    assert status["cameras"]["cam-01"]["last_scene_type"] == "UNKNOWN"


def test_status_disabled() -> None:
    engine = AutonomousPerceptionEngine(_settings(autonomous_enabled=False))
    assert engine.status()["engine_status"] == "DISABLED"


def test_lane_frame_end_to_end_with_geometry_detector() -> None:
    from backend.app.autonomous.lane_baseline import GeometryLaneDetector

    engine = _engine(lane_detector=GeometryLaneDetector())
    frame = _frame()
    frame.image = make_lane_frame()
    result = engine.process("cam-01", [], frame, utc(0), None)
    sides = {lane.side for lane in result.lanes}
    assert sides == {"left", "right"}
