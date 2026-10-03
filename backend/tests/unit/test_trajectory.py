"""Trajectory baseline tests — constant velocity, horizons, degenerate inputs."""

from __future__ import annotations

from backend.app.autonomous.trajectory import TrajectoryEstimator
from backend.tests.autonomous_helpers import utc


def _centers(n: int = 8, step: float = 10.0) -> tuple[list, list]:
    centers = [(100.0 + i * step, 200.0) for i in range(n)]
    timestamps = [utc(i * 0.1) for i in range(n)]
    return centers, timestamps


def test_constant_velocity_extrapolation() -> None:
    estimator = TrajectoryEstimator(horizon_seconds=2.0, history_points=8, steps=10)
    centers, timestamps = _centers()
    trajectory = estimator.estimate("track-1", centers, timestamps, 640.0, 480.0)
    assert trajectory is not None
    assert trajectory.object_id == "track-1"
    assert len(trajectory.points) == 10
    assert trajectory.horizon_seconds == 2.0
    # 100 px/s rightward: last center x=170px, +200px over 2s → 370px → 0.578125.
    assert trajectory.points[-1].x == 0.578125
    assert trajectory.points[-1].y == 200.0 / 480.0
    xs = [p.x for p in trajectory.points]
    assert xs == sorted(xs)
    assert all(0.0 <= p.x <= 1.0 and 0.0 <= p.y <= 1.0 for p in trajectory.points)


def test_stationary_object_high_confidence() -> None:
    estimator = TrajectoryEstimator()
    centers = [(100.0, 200.0)] * 8
    timestamps = [utc(i * 0.1) for i in range(8)]
    trajectory = estimator.estimate("track-1", centers, timestamps, 640.0, 480.0)
    assert trajectory is not None
    assert trajectory.confidence == 0.9
    assert all(p.x == trajectory.points[0].x for p in trajectory.points)


def test_too_few_points_returns_none() -> None:
    estimator = TrajectoryEstimator()
    assert estimator.estimate("t", [(1.0, 1.0)], [utc(0)], 640.0, 480.0) is None
    assert estimator.estimate("t", [], [], 640.0, 480.0) is None


def test_zero_time_deltas_return_none() -> None:
    estimator = TrajectoryEstimator()
    centers = [(100.0, 200.0), (110.0, 200.0)]
    same = [utc(0), utc(0)]
    assert estimator.estimate("t", centers, same, 640.0, 480.0) is None


def test_invalid_frame_returns_none() -> None:
    estimator = TrajectoryEstimator()
    centers, timestamps = _centers()
    assert estimator.estimate("t", centers, timestamps, 0.0, 480.0) is None
    assert estimator.estimate("t", centers, timestamps, 640.0, -1.0) is None


def test_confidence_decays_with_horizon() -> None:
    short = TrajectoryEstimator(horizon_seconds=0.5)
    long = TrajectoryEstimator(horizon_seconds=8.0)
    centers, timestamps = _centers()
    short_traj = short.estimate("t", centers, timestamps, 640.0, 480.0)
    long_traj = long.estimate("t", centers, timestamps, 640.0, 480.0)
    assert short_traj is not None and long_traj is not None
    assert short_traj.confidence > long_traj.confidence


def test_constructor_clamps() -> None:
    estimator = TrajectoryEstimator(horizon_seconds=0.0, history_points=1, steps=0)
    assert estimator.horizon_seconds == 0.1
    assert estimator.history_points == 2
    assert estimator.steps == 1
