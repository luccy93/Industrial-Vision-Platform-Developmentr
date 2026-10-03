"""Autonomous performance — latency budgets, bounded memory, concurrency."""

from __future__ import annotations

import threading
import time

from backend.app.autonomous.bev import build_bev
from backend.app.autonomous.collision import CollisionRiskEngine
from backend.app.autonomous.engine import AutonomousPerceptionEngine
from backend.app.autonomous.lane_baseline import GeometryLaneDetector
from backend.app.autonomous.scene import FixtureSceneClassifier
from backend.app.autonomous.schemas import SceneType
from backend.app.autonomous.trajectory import TrajectoryEstimator
from backend.app.core.config import Settings
from backend.app.domain.frame import IngestionFrame
from backend.tests.autonomous_helpers import make_lane_frame, synthetic_frame, utc
from backend.tests.safety_helpers import make_track


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def _frame(camera_id: str = "cam-01") -> IngestionFrame:
    return IngestionFrame(
        camera_id=camera_id, frame_number=1, width=640, height=480, image=synthetic_frame()
    )


def _tracks(n: int = 6) -> list:
    out = []
    for i in range(n):
        boxes = [
            (50.0 + i * 80.0 + j * 8.0, 100.0, 100.0 + i * 80.0 + j * 8.0, 300.0)
            for j in range(5)
        ]
        out.append(make_track(i + 1, "car", boxes[-1], history_boxes=boxes, history_span_seconds=2.0))
    return out


def _engine(**overrides) -> AutonomousPerceptionEngine:
    return AutonomousPerceptionEngine(
        _settings(),
        scene_classifier=FixtureSceneClassifier(scene_type=SceneType.ROAD),
        **overrides,
    )


def test_perception_latency_low_milliseconds() -> None:
    engine = _engine()
    tracks = _tracks()
    started = time.perf_counter()
    for i in range(30):
        engine.process("cam-01", tracks, _frame(), utc(i * 0.1), None)
    per_call_ms = (time.perf_counter() - started) * 1000.0 / 30
    assert per_call_ms < 100.0


def test_lane_latency_on_synthetic_frame() -> None:
    detector = GeometryLaneDetector()
    detector.load()
    frame = make_lane_frame()
    started = time.perf_counter()
    for _ in range(10):
        lanes = detector.detect(frame, camera_id="c", frame_id=None)
    per_call_ms = (time.perf_counter() - started) * 100.0
    assert len(lanes) == 2
    assert per_call_ms < 200.0


def test_trajectory_latency() -> None:
    estimator = TrajectoryEstimator()
    centers = [(100.0 + i * 10.0, 200.0) for i in range(8)]
    timestamps = [utc(i * 0.1) for i in range(8)]
    started = time.perf_counter()
    for _ in range(200):
        trajectory = estimator.estimate("t", centers, timestamps, 640.0, 480.0)
        assert trajectory is not None
    per_call_ms = (time.perf_counter() - started) * 5.0
    assert per_call_ms < 10.0


def test_collision_latency_with_busy_scene() -> None:
    engine = CollisionRiskEngine()
    started = time.perf_counter()
    for i in range(200):
        risk = engine.assess_pair(
            "track-1", "track-2", (0.3, 0.5), (0.7, 0.5), (0.2, 0.0), (-0.2, 0.0),
            0.6, 0.5, True, True, utc(i * 0.1),
        )
        assert risk.risk_level.value not in ("",)
    per_call_ms = (time.perf_counter() - started) * 5.0
    assert per_call_ms < 10.0


def test_bev_latency() -> None:
    engine = _engine()
    result = engine.process("cam-01", _tracks(), _frame(), utc(0), None)
    assert result.bev is not None
    started = time.perf_counter()
    for _ in range(100):
        view = build_bev(result.objects, result.lanes, result.trajectories, result.collision_risks, utc(0))
        assert view.coordinate_frame.value == "RELATIVE_BEV"
    per_call_ms = (time.perf_counter() - started) * 10.0
    assert per_call_ms < 20.0


def test_results_and_events_stay_bounded() -> None:
    engine = AutonomousPerceptionEngine(
        _settings(autonomous_max_results_per_camera=10, autonomous_max_events_per_camera=10)
    )
    for i in range(100):
        engine.process("cam-01", _tracks(), _frame(), utc(i * 0.5), None)
    assert len(engine.recent_results("cam-01", 1000)) <= 10


def test_concurrent_perception_is_safe() -> None:
    """Per-camera isolation must hold under parallel perception."""
    engine = _engine()
    errors: list[Exception] = []

    def run(camera_id: str) -> None:
        try:
            for i in range(50):
                engine.process(camera_id, _tracks(), _frame(camera_id), utc(i * 0.05), None)
                engine.status()
        except Exception as exc:  # pragma: no cover - only on a real race
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(cam,)) for cam in ("cam-a", "cam-b", "cam-a")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not errors
    assert engine._cameras["cam-a"].perceptions == 100
    assert engine._cameras["cam-b"].perceptions == 50
