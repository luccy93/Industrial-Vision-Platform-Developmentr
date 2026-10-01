"""Safety engine integration — real rules, multi-event scenes, suppress."""

from __future__ import annotations

from backend.app.core.config import Settings
from backend.app.safety.engine import SafetyEngine
from backend.app.safety.rules import default_rules
from backend.app.safety.schemas import SafetyEventStatus, SafetyEventType
from backend.tests.safety_helpers import make_track, utc


def _engine(**overrides) -> SafetyEngine:  # type: ignore[no-untyped-def]
    settings = Settings(_env_file=None, **overrides)  # type: ignore
    return SafetyEngine(settings, default_rules(settings))


def test_quiet_scene_no_events() -> None:
    engine = _engine()
    result = engine.process("cam-1", [make_track(1)], utc())
    assert result.active_events == [] and result.new_events == []
    assert result.resolved_events == []


def test_multiple_simultaneous_events() -> None:
    engine = _engine()
    tracks = [make_track(i) for i in range(1, 7)]  # crowd warning
    tracks.append(
        make_track(
            50,
            box=(100.0, 200.0, 300.0, 280.0),
            history_boxes=[(100.0, 200.0, 300.0, 280.0)] * 6,
        )
    )  # possible fall → 7 persons total
    result = engine.process("cam-1", tracks, utc())
    types = {e.event_type for e in result.active_events}
    assert SafetyEventType.CROWD_WARNING in types
    assert SafetyEventType.POSSIBLE_FALL in types


def test_event_continuity_stable_id() -> None:
    engine = _engine()
    tracks = [make_track(i) for i in range(1, 7)]
    first = engine.process("cam-1", tracks, utc(0))
    second = engine.process("cam-1", tracks, utc(1))
    assert second.new_events == []
    assert first.active_events[0].event_id == second.active_events[0].event_id


def test_resolution_after_condition_clears() -> None:
    engine = _engine(safety_event_resolution_grace_seconds=1.0)
    engine.process("cam-1", [make_track(i) for i in range(1, 7)], utc(0))
    done = engine.process("cam-1", [make_track(1)], utc(5))
    assert len(done.resolved_events) == 1
    assert done.resolved_events[0].status == SafetyEventStatus.RESOLVED
    assert engine.recent_events("cam-1")[0].event_id == done.resolved_events[0].event_id


def test_suppress_moves_to_suppressed() -> None:
    engine = _engine()
    engine.process("cam-1", [make_track(i) for i in range(1, 7)], utc(0))
    event_id = str(engine.active_events("cam-1")[0].event_id)
    status = engine.suppress("cam-1", event_id)
    assert status == SafetyEventStatus.SUPPRESSED
    assert engine.active_events("cam-1") == []
    try:
        engine.suppress("cam-1", event_id)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_per_camera_isolation_with_rules() -> None:
    engine = _engine()
    engine.process("cam-a", [make_track(i, camera_id="cam-a") for i in range(1, 7)], utc(0))
    assert engine.active_events("cam-b") == []
    assert len(engine.active_events("cam-a")) == 1
