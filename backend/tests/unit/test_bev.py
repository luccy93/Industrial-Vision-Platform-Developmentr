"""BEV mapping tests — relative plane, clamping, risk flags."""

from __future__ import annotations

from backend.app.autonomous.bev import build_bev, to_bev
from backend.app.autonomous.schemas import RiskLevel
from backend.tests.autonomous_helpers import make_lane, make_object, utc


def test_to_bev_center_and_corners() -> None:
    center = to_bev(0.5, 0.5)
    assert center.lateral == 0.0
    assert center.longitudinal == 0.5
    bottom_left = to_bev(0.0, 1.0)
    assert bottom_left.lateral == -1.0
    assert bottom_left.longitudinal == 0.0
    top_right = to_bev(1.0, 0.0)
    assert top_right.lateral == 1.0
    assert top_right.longitudinal == 1.0


def test_to_bev_clamps() -> None:
    point = to_bev(1.5, -0.5)
    assert point.lateral == 1.0
    assert point.longitudinal == 1.0


def test_build_bev_maps_objects_lanes_trajectories() -> None:
    from backend.app.autonomous.schemas import CollisionRisk, Trajectory

    obj = make_object(center=(0.25, 0.75))
    lane = make_lane()
    trajectory = Trajectory(
        object_id="track-1",
        points=[],
        horizon_seconds=2.0,
    )
    risk = CollisionRisk(
        object_ids=["track-1", "track-2"], risk_level=RiskLevel.HIGH, risk_score=0.8
    )
    view = build_bev([obj], [lane], [trajectory], [risk], utc(0))
    assert view.coordinate_frame.value == "RELATIVE_BEV"
    assert len(view.objects) == 1
    assert view.objects[0].lateral == -0.5
    assert view.objects[0].longitudinal == 0.25
    assert view.objects[0].risk_level is RiskLevel.HIGH
    assert len(view.lanes) == 1
    assert len(view.lanes[0]) == len(lane.points)
    assert view.trajectories["track-1"] == []


def test_build_bev_skips_objects_without_center() -> None:
    obj = make_object(center=None)
    view = build_bev([obj], [], [], [], utc(0))
    assert view.objects == []


def test_build_bev_unknown_risk_without_assessment() -> None:
    obj = make_object()
    view = build_bev([obj], [], [], [], utc(0))
    assert view.objects[0].risk_level is RiskLevel.UNKNOWN
