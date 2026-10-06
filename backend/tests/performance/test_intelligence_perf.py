"""Intelligence performance — latency budgets, bounded memory, concurrency."""

from __future__ import annotations

import threading
import time
from typing import Any

from backend.app.core.config import Settings
from backend.app.intelligence.engine import IntelligenceEngine
from backend.app.intelligence.normalize import (
    AutonomousEventAdapter,
    QualityEventAdapter,
    SafetyEventAdapter,
    SpatialEventAdapter,
)
from backend.app.safety.base import EventDraft, SafetyRule, SceneState
from backend.app.safety.engine import SafetyEngine
from backend.app.safety.schemas import SafetyEventType, SafetySeverity
from backend.tests.intelligence_helpers import (
    make_autonomous_event,
    make_quality_event,
    make_safety_event,
    make_spatial_event,
    utc,
)


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


class _BurstRule(SafetyRule):
    """Emits N distinct stub events per pass for storm testing."""

    def __init__(self, name: str, count: int) -> None:
        super().__init__(name, enabled=True)
        self._count = count

    @property
    def event_type(self):  # type: ignore[no-untyped-def]
        return SafetyEventType.CROWD_WARNING

    def evaluate(self, scene: SceneState):  # type: ignore[no-untyped-def]
        return [
            EventDraft(
                dedupe_key=f"burst:{scene.camera_id}:{i}",
                event_type=SafetyEventType.CROWD_WARNING,
                severity=SafetySeverity.MEDIUM,
                track_ids=[i],
                confidence=0.7,
                message="burst",
                evidence={},
            )
            for i in range(self._count)
        ]


def _storm_engine(event_count: int = 60, cameras: tuple[str, ...] = ("cam-01",)) -> IntelligenceEngine:
    safety = SafetyEngine(_settings(), [_BurstRule("burst", event_count)])
    for camera_id in cameras:
        safety.process(camera_id, [], utc(0))
    return IntelligenceEngine(_settings(), safety_engine=safety)


def test_normalization_latency() -> None:
    adapters: list[Any] = [
        SafetyEventAdapter(),
        SpatialEventAdapter(),
        QualityEventAdapter(),
        AutonomousEventAdapter(),
    ]
    sources = [make_safety_event(), make_spatial_event(), make_quality_event(), make_autonomous_event()]
    started = time.perf_counter()
    for _ in range(500):
        for adapter, source in zip(adapters, sources):
            adapter.normalize(source)
    per_call_ms = (time.perf_counter() - started) * 1000.0 / 2000
    assert per_call_ms < 5.0


def test_process_latency_with_many_events() -> None:
    engine = _storm_engine(60)
    started = time.perf_counter()
    for i in range(20):
        engine.process("cam-01", utc(i * 0.5))
    per_call_ms = (time.perf_counter() - started) * 1000.0 / 20
    assert per_call_ms < 100.0


def test_storm_stays_bounded() -> None:
    engine = _storm_engine(120)
    for i in range(30):
        engine.process("cam-01", utc(i * 0.5))
    state = engine._cameras["cam-01"]
    assert len(state.unified) <= 200
    assert len(state.clusters) <= 50
    result = engine.latest("cam-01")
    assert result is not None
    assert result.active_event_count <= 200
    assert result.active_cluster_count <= 50


def test_concurrent_process_is_safe() -> None:
    """Per-camera isolation must hold under parallel processing."""
    engine = _storm_engine(10, ("cam-a", "cam-b"))
    errors: list[Exception] = []

    def run(camera_id: str) -> None:
        try:
            for i in range(30):
                engine.process(camera_id, utc(i * 0.1))
                engine.status()
        except Exception as exc:  # pragma: no cover - only on a real race
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(cam,)) for cam in ("cam-a", "cam-b", "cam-a")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not errors
    assert engine._cameras["cam-a"].events_processed == 600
    assert engine._cameras["cam-b"].events_processed == 300
