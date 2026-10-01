"""Safety engine core tests — lifecycle with a stub rule (no real rules yet)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from backend.app.core.config import Settings
from backend.app.safety.base import EventDraft, SafetyRule, SceneState
from backend.app.safety.engine import SafetyEngine
from backend.app.safety.schemas import SafetyEventStatus, SafetyEventType, SafetySeverity


class StubRule(SafetyRule):
    def __init__(self, active: bool = True) -> None:
        super().__init__("stub", enabled=True)
        self._active = active

    @property
    def event_type(self) -> SafetyEventType:
        return SafetyEventType.CROWD_WARNING

    def evaluate(self, scene: SceneState) -> list[EventDraft]:
        if not self._active:
            return []
        return [
            EventDraft(
                dedupe_key=f"stub:{scene.camera_id}",
                event_type=self.event_type,
                severity=SafetySeverity.MEDIUM,
                track_ids=[t.track_id for t in scene.tracks],
                confidence=0.7,
                message="stub",
                evidence={},
            )
        ]


def _settings(**overrides: object) -> Settings:
    params: dict[str, object] = {"safety_event_resolution_grace_seconds": 3.0}
    params.update(overrides)
    return Settings(_env_file=None, **params)  # type: ignore


def _ts(seconds: float) -> datetime:
    return datetime.now(UTC) + timedelta(seconds=seconds)


def test_create_update_resolve_lifecycle() -> None:
    stub = StubRule(active=True)
    engine = SafetyEngine(_settings(), [stub])
    first = engine.process("cam-1", [], _ts(0))
    assert len(first.new_events) == 1 and len(first.active_events) == 1
    event_id = first.new_events[0].event_id

    second = engine.process("cam-1", [], _ts(1))
    assert second.new_events == []  # continuity, not a new event
    assert second.active_events[0].event_id == event_id  # stable ID
    assert second.active_events[0].duration_ms == 1000.0

    engine._rules[0]  # registered stub
    stub._active = False
    engine.process("cam-1", [], _ts(2))  # within grace → still active
    assert len(engine.active_events("cam-1")) == 1
    done = engine.process("cam-1", [], _ts(6))  # past grace → resolved
    assert len(done.resolved_events) == 1
    assert done.resolved_events[0].status == SafetyEventStatus.RESOLVED
    assert engine.active_events("cam-1") == []


def test_per_camera_isolation() -> None:
    engine = SafetyEngine(_settings(), [StubRule(active=True)])
    engine.process("cam-a", [], _ts(0))
    engine.process("cam-b", [], _ts(0))
    assert len(engine.active_events("cam-a")) == 1
    assert len(engine.active_events("cam-b")) == 1
    assert engine.active_events("cam-a")[0].event_id != engine.active_events("cam-b")[0].event_id


def test_disabled_engine_creates_nothing() -> None:
    engine = SafetyEngine(_settings(safety_enabled=False), [StubRule(active=True)])
    assert engine.process("cam-1", [], _ts(0)).active_events == []
    assert engine.status()["engine_status"] == "DISABLED"


def test_rule_failure_isolated() -> None:
    class Broken(StubRule):
        def evaluate(self, scene: SceneState) -> list[EventDraft]:
            raise RuntimeError("boom")

    engine = SafetyEngine(_settings(), [Broken(), StubRule(active=True)])
    result = engine.process("cam-1", [], _ts(0))
    assert len(result.active_events) == 1
    assert engine.status()["active_event_count"] == 1


def test_status_shape() -> None:
    engine = SafetyEngine(_settings(), [StubRule()])
    status = engine.status()
    assert status["enabled"] is True
    assert status["rules_loaded"] == ["stub"]
    assert status["active_camera_count"] == 0
