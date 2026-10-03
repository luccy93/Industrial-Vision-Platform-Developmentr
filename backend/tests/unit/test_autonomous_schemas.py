"""Autonomous schemas + config tests — enums, validation, serialization."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.app.autonomous.schemas import (
    AutonomousPerceptionEvent,
    AutonomousPerceptionResult,
    BevObject,
    BevPoint,
    BirdsEyeView,
    CollisionRisk,
    CoordinateFrame,
    DepthReading,
    DepthSource,
    EgoState,
    LaneType,
    ModelState,
    NormalizedPoint,
    PerceivedObjectState,
    PerceptionEventStatus,
    PerceptionEventType,
    RiskLevel,
    SceneHypothesis,
    SceneType,
    Trajectory,
)
from backend.app.core.config import Settings
from backend.tests.autonomous_helpers import make_lane, make_object, make_profile


def test_enum_values() -> None:
    assert {t.value for t in SceneType} == {
        "ROAD",
        "PARKING",
        "WAREHOUSE",
        "INDUSTRIAL_YARD",
        "INDOOR_MOBILE_ROBOT",
        "UNKNOWN",
    }
    assert {s.value for s in PerceivedObjectState} == {
        "MOVING",
        "STATIONARY",
        "APPROACHING",
        "RECEDING",
        "CROSSING",
        "UNKNOWN",
    }
    assert {t.value for t in LaneType} == {"SOLID", "DASHED", "DOUBLE_SOLID", "UNKNOWN"}
    assert {r.value for r in RiskLevel} == {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
    assert {t.value for t in PerceptionEventType} == {
        "COLLISION_RISK",
        "LANE_DEPARTURE_RISK",
        "OBJECT_APPROACH",
        "OBJECT_CROSSING",
        "SCENE_CHANGE",
    }
    assert {s.value for s in PerceptionEventStatus} == {"ACTIVE", "RESOLVED"}
    assert {f.value for f in CoordinateFrame} == {"UNKNOWN", "IMAGE_SPACE_RELATIVE", "RELATIVE_BEV"}
    assert {s.value for s in DepthSource} == {"NOT_CONFIGURED", "FIXTURE_SYNTHETIC"}
    assert {s.value for s in ModelState} == {"NOT_LOADED", "LOADING", "READY", "NOT_READY"}


def test_ego_state_defaults_to_unavailable() -> None:
    ego = EgoState()
    assert ego.velocity is None
    assert ego.position is None
    assert ego.heading is None
    assert ego.coordinate_frame is CoordinateFrame.UNKNOWN


def test_object_defaults() -> None:
    obj = make_object()
    assert obj.object_state is PerceivedObjectState.UNKNOWN
    assert obj.relative_depth is None
    assert obj.depth_source is DepthSource.NOT_CONFIGURED
    assert obj.velocity is None


def test_lane_requires_two_points() -> None:
    lane = make_lane()
    assert len(lane.points) >= 2
    with pytest.raises(ValidationError):
        make_lane(points=[NormalizedPoint(x=0.5, y=0.5)])


def test_lane_points_normalized() -> None:
    with pytest.raises(ValidationError):
        make_lane(points=[NormalizedPoint(x=0.1, y=0.1), NormalizedPoint(x=1.5, y=0.5)])


def test_depth_reading_defaults_unavailable() -> None:
    reading = DepthReading()
    assert reading.depth is None
    assert reading.unit is None
    assert reading.source is DepthSource.NOT_CONFIGURED


def test_collision_risk_ttc_optional() -> None:
    risk = CollisionRisk(object_ids=["track-1", "track-2"], risk_level=RiskLevel.UNKNOWN)
    assert risk.time_to_collision is None
    assert risk.risk_score == 0.0
    with pytest.raises(ValidationError):
        CollisionRisk(object_ids=["only-one"], risk_level=RiskLevel.HIGH)
    with pytest.raises(ValidationError):
        CollisionRisk(object_ids=["a", "b", "c"], risk_level=RiskLevel.HIGH)


def test_bev_point_bounds() -> None:
    point = BevPoint(lateral=0.0, longitudinal=0.5)
    assert point.lateral == 0.0
    with pytest.raises(ValidationError):
        BevPoint(lateral=1.5, longitudinal=0.5)
    with pytest.raises(ValidationError):
        BevPoint(lateral=0.0, longitudinal=-0.1)


def test_bev_object_and_view() -> None:
    view = BirdsEyeView(
        objects=[BevObject(object_id="track-1", lateral=0.1, longitudinal=0.8)],
        lanes=[[BevPoint(lateral=-0.3, longitudinal=0.1), BevPoint(lateral=-0.2, longitudinal=0.9)]],
    )
    assert view.coordinate_frame is CoordinateFrame.RELATIVE_BEV


def test_event_touch_and_serialization() -> None:
    from datetime import timedelta

    event = AutonomousPerceptionEvent(
        camera_id="cam-01",
        event_type=PerceptionEventType.COLLISION_RISK,
        risk_level=RiskLevel.HIGH,
        object_ids=["track-1", "track-2"],
    )
    assert event.status is PerceptionEventStatus.ACTIVE
    assert event.duration_ms == 0.0
    event.touch(event.first_seen + timedelta(seconds=2))
    assert event.duration_ms == pytest.approx(2000.0)
    payload = event.to_websocket()
    assert payload["event_type"] == "COLLISION_RISK"
    assert payload["object_ids"] == ["track-1", "track-2"]


def test_result_websocket_has_no_image_payload() -> None:
    result = AutonomousPerceptionResult(camera_id="cam-01", frame_id="f-1")
    payload = result.to_websocket()
    assert "image" not in payload and "base64" not in payload
    assert payload["scene_type"] == "UNKNOWN"


def test_scene_hypothesis() -> None:
    hypothesis = SceneHypothesis(scene_type=SceneType.ROAD, confidence=0.8, reason="test")
    assert hypothesis.scene_type is SceneType.ROAD


def test_profile_defaults_and_validation() -> None:
    profile = make_profile()
    assert profile.enabled is True
    assert profile.scene_type is SceneType.UNKNOWN
    assert profile.trajectory_horizon_seconds == 2.0
    with pytest.raises(ValidationError):
        make_profile(trajectory_horizon_seconds=0.0)
    with pytest.raises(ValidationError):
        make_profile(collision_risk_threshold=1.5)


def test_trajectory_defaults() -> None:
    trajectory = Trajectory(object_id="track-1")
    assert trajectory.points == []
    assert trajectory.coordinate_frame is CoordinateFrame.IMAGE_SPACE_RELATIVE


def test_autonomous_config_defaults() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.autonomous_enabled is True
    assert settings.autonomous_scene_classifier == ""
    assert settings.autonomous_lane_detector == ""
    assert settings.autonomous_depth_model == ""
    assert settings.autonomous_lane_detection_enabled is True
    assert settings.autonomous_depth_enabled is False
    assert settings.autonomous_trajectory_enabled is True
    assert settings.autonomous_collision_risk_enabled is True
    assert settings.autonomous_bev_enabled is True
    assert settings.autonomous_perception_interval_frames == 10
    assert settings.autonomous_trajectory_horizon_seconds == 2.0
    assert settings.autonomous_trajectory_history_points == 8
    assert settings.autonomous_collision_grace_seconds == 0.5
    assert settings.autonomous_collision_risk_threshold == 0.5
    assert settings.autonomous_max_objects_per_scene == 100
    assert settings.autonomous_max_results_per_camera == 30
    assert settings.autonomous_max_events_per_camera == 100
    assert settings.autonomous_max_profiles_per_camera == 10
    assert settings.autonomous_motion_speed_threshold == 0.02
    assert settings.autonomous_approach_area_ratio == 0.02


def test_autonomous_config_bounds() -> None:
    with pytest.raises(ValueError):
        Settings(autonomous_perception_interval_frames=0, _env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(autonomous_trajectory_horizon_seconds=0.0, _env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(autonomous_collision_risk_threshold=1.5, _env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(autonomous_motion_speed_threshold=-0.1, _env_file=None)  # type: ignore[call-arg]
