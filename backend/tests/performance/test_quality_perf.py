"""Quality performance — latency budgets, bounded memory, concurrency."""

from __future__ import annotations

import threading
import time

from backend.app.core.config import Settings
from backend.app.domain.frame import IngestionFrame
from backend.app.quality.engine import QualityInspectionEngine
from backend.app.quality.fixture import FixtureInspectionModel
from backend.app.quality.inspection import RawDefect
from backend.app.quality.schemas import QualityDecision
from backend.tests.quality_helpers import make_category, make_profile, make_region, synthetic_frame, utc

_W, _H = 640, 480


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def _frame(camera_id: str = "cam-01") -> IngestionFrame:
    return IngestionFrame(
        camera_id=camera_id, frame_number=1, width=_W, height=_H, image=synthetic_frame(_W, _H)
    )


def _engine(defects=None, **overrides) -> QualityInspectionEngine:
    model = FixtureInspectionModel(observations=list(defects or []))
    return QualityInspectionEngine(_settings(**overrides), model)


def _load(engine: QualityInspectionEngine, camera_id: str = "cam-01") -> None:
    profile = make_profile(camera_id=camera_id)
    engine.set_profiles(camera_id, [profile], [make_region(camera_id=camera_id)], [make_category()], {})


def test_inspection_latency_low_milliseconds() -> None:
    defects = [RawDefect(code=f"D{i}", box=(10.0, 10.0, 100.0, 100.0), confidence=0.9) for i in range(5)]
    engine = _engine(defects)
    _load(engine)
    profile = engine._cameras["cam-01"].profiles["profile-01"]
    started = time.perf_counter()
    for i in range(100):
        engine.inspect("cam-01", profile, _frame(), utc(i * 0.1), None)
    per_call_ms = (time.perf_counter() - started) * 10.0
    assert per_call_ms < 50.0


def test_event_processing_latency_with_many_active() -> None:
    defects = [RawDefect(code=f"D{i}", box=(10.0, 10.0, 100.0, 100.0), confidence=0.9) for i in range(20)]
    engine = _engine(defects)
    _load(engine)
    profile = engine._cameras["cam-01"].profiles["profile-01"]
    started = time.perf_counter()
    for i in range(50):
        engine.inspect("cam-01", profile, _frame(), utc(i * 0.2), None)
    per_call_ms = (time.perf_counter() - started) * 20.0
    assert per_call_ms < 50.0


def test_results_and_events_stay_bounded() -> None:
    engine = _engine([], quality_max_results_per_camera=10, quality_max_events_per_camera=10)
    _load(engine)
    profile = engine._cameras["cam-01"].profiles["profile-01"]
    for i in range(100):
        engine.inspect("cam-01", profile, _frame(), utc(i * 0.5), None)
    assert len(engine.recent_results("cam-01", 1000)) <= 10
    # PASS produces no events; the rings never grow.
    assert engine.active_events("cam-01") == []


def test_error_events_stay_bounded() -> None:
    engine = QualityInspectionEngine(_settings(quality_max_events_per_camera=10), None)
    _load(engine)
    profile = engine._cameras["cam-01"].profiles["profile-01"]
    for i in range(50):
        result = engine.inspect("cam-01", profile, _frame(), utc(i * 0.5), None)
        assert result.decision is QualityDecision.ERROR
    # One ongoing ERROR event, not one per frame.
    assert len(engine.active_events("cam-01")) == 1


def test_concurrent_inspection_is_safe() -> None:
    """Per-camera isolation must hold under parallel inspection."""
    engine = _engine([RawDefect(code="CRACK", box=(10.0, 10.0, 100.0, 100.0), confidence=0.9)])
    _load(engine, "cam-a")
    _load(engine, "cam-b")
    errors: list[Exception] = []

    def run(camera_id: str) -> None:
        try:
            profile = engine._cameras[camera_id].profiles["profile-01"]
            for i in range(100):
                engine.inspect(camera_id, profile, _frame(camera_id), utc(i * 0.05), None)
                engine.status()
        except Exception as exc:  # pragma: no cover - only on a real race
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(cam,)) for cam in ("cam-a", "cam-b", "cam-a")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not errors
    assert engine._cameras["cam-a"].inspections == 200
    assert engine._cameras["cam-b"].inspections == 100


def test_throughput_scales_with_profiles() -> None:
    engine = _engine([RawDefect(code="CRACK", box=(10.0, 10.0, 100.0, 100.0), confidence=0.9)])
    profiles = [make_profile(profile_id=f"p-{n}", name=f"Profile {n}") for n in range(5)]
    engine.set_profiles("cam-01", profiles, [], [make_category()], {})
    started = time.perf_counter()
    for i in range(20):
        engine.process("cam-01", _frame(), utc(i * 0.1), None)
    per_frame_ms = (time.perf_counter() - started) * 50.0
    assert per_frame_ms < 100.0
