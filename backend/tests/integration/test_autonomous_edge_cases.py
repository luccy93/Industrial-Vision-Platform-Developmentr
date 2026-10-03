"""Autonomous edge cases — departure, caps, disabled paths, lifecycle."""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app.autonomous.engine import AutonomousPerceptionEngine
from backend.app.autonomous.lanes import FixtureLaneDetector, RawLane, analyze_lane_departure
from backend.app.autonomous.schemas import PerceptionEventType, RiskLevel
from backend.app.core.config import Settings
from backend.app.domain.frame import IngestionFrame
from backend.app.tracking.schemas import TrackState
from backend.tests.autonomous_helpers import make_profile, synthetic_frame, utc
from backend.tests.safety_helpers import make_track


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def _frame(camera_id: str = "cam-01") -> IngestionFrame:
    return IngestionFrame(camera_id=camera_id, frame_number=1, width=640, height=480, image=synthetic_frame())


def _engine(**overrides) -> AutonomousPerceptionEngine:
    return AutonomousPerceptionEngine(_settings(), **overrides)


def test_departure_centered_is_none() -> None:
    lanes = [
        RawLane(points=[(0.2, 0.9), (0.3, 0.2)], confidence=0.9),
        RawLane(points=[(0.8, 0.9), (0.7, 0.2)], confidence=0.9),
    ]
    level, evidence = analyze_lane_departure(lanes)
    assert level is RiskLevel.NONE
    assert evidence["edge_distance"] == 0.5


def test_departure_near_edge_is_high() -> None:
    lanes = [
        RawLane(points=[(0.45, 0.9), (0.47, 0.2)], confidence=0.9),
        RawLane(points=[(0.8, 0.9), (0.7, 0.2)], confidence=0.9),
    ]
    level, _ = analyze_lane_departure(lanes)
    assert level is RiskLevel.HIGH


def test_departure_at_edge_is_critical() -> None:
    lanes = [
        RawLane(points=[(0.49, 0.9), (0.49, 0.2)], confidence=0.9),
        RawLane(points=[(0.8, 0.9), (0.7, 0.2)], confidence=0.9),
    ]
    level, _ = analyze_lane_departure(lanes)
    assert level is RiskLevel.CRITICAL


def test_departure_single_lane_is_unknown() -> None:
    lanes = [RawLane(points=[(0.2, 0.9), (0.3, 0.2)], confidence=0.9)]
    level, evidence = analyze_lane_departure(lanes)
    assert level is RiskLevel.UNKNOWN
    assert "reason" in evidence


def test_departure_no_lanes_is_unknown() -> None:
    level, _ = analyze_lane_departure([])
    assert level is RiskLevel.UNKNOWN


def test_departure_event_in_engine() -> None:
    lanes = [
        RawLane(points=[(0.45, 0.9), (0.47, 0.2)], confidence=0.9),
        RawLane(points=[(0.8, 0.9), (0.7, 0.2)], confidence=0.9),
    ]
    engine = _engine(lane_detector=FixtureLaneDetector(lanes=lanes))
    engine.process("cam-01", [], _frame(), utc(0), None)
    departures = [
        e for e in engine.active_events("cam-01") if e.event_type is PerceptionEventType.LANE_DEPARTURE_RISK
    ]
    assert len(departures) == 1
    assert departures[0].risk_level is RiskLevel.HIGH


def test_no_departure_event_when_centered() -> None:
    lanes = [
        RawLane(points=[(0.2, 0.9), (0.3, 0.2)], confidence=0.9),
        RawLane(points=[(0.8, 0.9), (0.7, 0.2)], confidence=0.9),
    ]
    engine = _engine(lane_detector=FixtureLaneDetector(lanes=lanes))
    engine.process("cam-01", [], _frame(), utc(0), None)
    assert [
        e for e in engine.active_events("cam-01") if e.event_type is PerceptionEventType.LANE_DEPARTURE_RISK
    ] == []


def test_separating_pair_ttc_null_at_engine_level() -> None:
    engine = _engine()
    boxes_a = [(300.0 - i * 10.0, 100.0, 350.0 - i * 10.0, 300.0) for i in range(5)]
    boxes_b = [(400.0 + i * 10.0, 100.0, 450.0 + i * 10.0, 300.0) for i in range(5)]
    track_a = make_track(1, "car", boxes_a[-1], history_boxes=boxes_a, history_span_seconds=2.0)
    track_b = make_track(2, "car", boxes_b[-1], history_boxes=boxes_b, history_span_seconds=2.0)
    result = engine.process("cam-01", [track_a, track_b], _frame(), utc(0), None)
    assert len(result.collision_risks) == 1
    assert result.collision_risks[0].time_to_collision is None
    assert result.collision_risks[0].risk_level is RiskLevel.NONE


def test_depth_configured_but_profile_disables() -> None:
    from backend.app.autonomous.depth import FixtureDepthEstimator

    engine = _engine(depth_estimator=FixtureDepthEstimator(depths={"track-1": 0.4}))
    track = make_track(1, "car", (100.0, 100.0, 200.0, 300.0))
    result = engine.process("cam-01", [track], _frame(), utc(0), None)
    # Profile default has depth off: the estimator never runs, depth stays unavailable.
    assert result.objects[0].relative_depth is None
    assert result.objects[0].depth_source.value == "NOT_CONFIGURED"


def test_disabled_subsystems_skip_cleanly() -> None:
    engine = _engine()
    engine.set_profiles(
        "cam-01",
        [
            make_profile(
                lane_detection_enabled=False,
                trajectory_enabled=False,
                collision_risk_enabled=False,
                bev_enabled=False,
            )
        ],
    )
    track = make_track(1, "car", (100.0, 100.0, 200.0, 300.0))
    result = engine.process("cam-01", [track], _frame(), utc(0), None)
    assert result.lanes == []
    assert result.trajectories == []
    assert result.collision_risks == []
    assert result.bev is None
    assert len(result.objects) == 1


def test_object_and_pair_caps() -> None:
    engine = AutonomousPerceptionEngine(_settings(autonomous_max_objects_per_scene=4))
    tracks = [make_track(i + 1, "car", (50.0 + i * 60.0, 100.0, 100.0 + i * 60.0, 300.0)) for i in range(10)]
    result = engine.process("cam-01", tracks, _frame(), utc(0), None)
    assert len(result.objects) == 4
    assert len(result.collision_risks) <= 6  # C(4,2) pairs


def test_lost_tracks_do_not_crash() -> None:
    engine = _engine()
    track = make_track(1, "car", (100.0, 100.0, 200.0, 300.0), state=TrackState.LOST)
    result = engine.process("cam-01", [track], _frame(), utc(0), None)
    assert len(result.objects) == 1
    assert result.objects[0].object_state.value in (
        "MOVING",
        "STATIONARY",
        "APPROACHING",
        "RECEDING",
        "CROSSING",
        "UNKNOWN",
    )


def test_profile_count_cap_409(client: TestClient) -> None:
    assert (
        client.post(
            "/api/v1/cameras",
            json={"name": "Cap", "camera_id": "cam-cap", "source_type": "file", "source": "v.mp4"},
        ).status_code
        == 201
    )
    for i in range(10):
        res = client.post(
            "/api/v1/cameras/cam-cap/autonomous-profiles",
            json={"name": f"P{i}", "profile_id": f"p-{i}"},
        )
        assert res.status_code == 201, res.text
    capped = client.post(
        "/api/v1/cameras/cam-cap/autonomous-profiles",
        json={"name": "Overflow", "profile_id": "p-overflow"},
    )
    assert capped.status_code == 409


def test_duplicate_profile_id_409_via_second_camera_ok(client: TestClient) -> None:
    for cam in ("cam-d1", "cam-d2"):
        assert (
            client.post(
                "/api/v1/cameras",
                json={"name": cam, "camera_id": cam, "source_type": "file", "source": "v.mp4"},
            ).status_code
            == 201
        )
    assert (
        client.post(
            "/api/v1/cameras/cam-d1/autonomous-profiles",
            json={"name": "P", "profile_id": "shared"},
        ).status_code
        == 201
    )
    # Same profile_id on another camera is independent (camera-scoped identity).
    assert (
        client.post(
            "/api/v1/cameras/cam-d2/autonomous-profiles",
            json={"name": "P", "profile_id": "shared"},
        ).status_code
        == 201
    )
