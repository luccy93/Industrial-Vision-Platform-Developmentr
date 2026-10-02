"""Safety performance tests — rule/engine latency, throughput, bounds."""

from __future__ import annotations

import time

from backend.app.core.config import Settings
from backend.app.safety.engine import SafetyEngine
from backend.app.safety.rules import default_rules
from backend.tests.safety_helpers import make_track, utc


def _engine() -> SafetyEngine:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    return SafetyEngine(settings, default_rules(settings))


def test_engine_latency_low_milliseconds() -> None:
    engine = _engine()
    tracks = [make_track(i) for i in range(1, 11)]
    started = time.perf_counter()
    for i in range(100):
        engine.process("perf", tracks, utc(i * 0.1))
    elapsed_ms = (time.perf_counter() - started) * 1000.0 / 100
    assert elapsed_ms < 50.0  # low-ms budget for synthetic scenes


def test_rule_evaluation_throughput() -> None:
    engine = _engine()
    tracks = [make_track(i) for i in range(1, 6)]
    # perf_counter (not time.time) — Windows' wall clock is too coarse to
    # measure sub-millisecond evaluation loops.
    started = time.perf_counter()
    evaluations = 200
    for i in range(evaluations):
        engine.process("tput", tracks, utc(i * 0.05))
    elapsed = max(time.perf_counter() - started, 1e-9)
    per_second = evaluations / elapsed
    assert per_second > 50  # 50+ scene evaluations/sec minimum


def test_memory_bounded_under_load() -> None:
    engine = _engine()
    for i in range(300):
        tracks = [make_track(j) for j in range(1, 7)] if i % 2 == 0 else []
        engine.process("mem", tracks, utc(i * 0.1))
    status = engine.status()
    assert status["active_event_count"] <= 10
    recent = engine.recent_events("mem", 10000)
    assert len(recent) <= 100  # bounded by safety_max_events_per_camera
