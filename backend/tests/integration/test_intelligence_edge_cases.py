"""Intelligence edge cases — caps, clock skew, idempotency, identity."""

from __future__ import annotations

from datetime import timedelta

from backend.app.intelligence.engine import IntelligenceEngine
from backend.app.intelligence.schemas import EventSourceDomain
from backend.app.safety.base import EventDraft, SafetyRule, SceneState
from backend.app.safety.engine import SafetyEngine
from backend.app.safety.schemas import SafetyEventType, SafetySeverity
from backend.tests.intelligence_helpers import make_unified_event, utc
from backend.tests.safety_helpers import make_track


class StubRule(SafetyRule):
    active: bool

    def __init__(self, name: str, severity: SafetySeverity = SafetySeverity.MEDIUM) -> None:
        super().__init__(name, enabled=True)
        self.active = True
        self._severity = severity

    @property
    def event_type(self) -> SafetyEventType:
        return SafetyEventType.CROWD_WARNING

    def evaluate(self, scene: SceneState) -> list[EventDraft]:
        if not self.active:
            return []
        return [
            EventDraft(
                dedupe_key=f"stub:{scene.camera_id}:{self.name}",
                event_type=self.event_type,
                severity=self._severity,
                track_ids=[t.track_id for t in scene.tracks],
                confidence=0.7,
                message="stub",
                evidence={},
            )
        ]


def _settings(**overrides):  # type: ignore[no-untyped-def]
    from backend.app.core.config import Settings

    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def _intel(safety=None, **overrides):  # type: ignore[no-untyped-def]
    return IntelligenceEngine(_settings(**overrides), safety_engine=safety)


def test_same_timestamp_twice_is_idempotent() -> None:
    safety = SafetyEngine(_settings(), [StubRule("stub")])
    safety.process("cam-01", [], utc(0))
    engine = _intel(safety=safety)
    first = engine.process("cam-01", utc(0))
    second = engine.process("cam-01", utc(0))
    assert first.active_event_count == second.active_event_count == 1
    assert len(engine.active_clusters("cam-01")) == 1


def test_future_source_timestamp_no_crash() -> None:
    """Clock-skewed (future) source timestamps resolve safely, never crash."""
    safety = SafetyEngine(_settings(), [StubRule("stub")])
    safety.process("cam-01", [], utc(3600))
    engine = _intel(safety=safety)
    result = engine.process("cam-01", utc(0))
    assert result.active_event_count == 1
    # Grace math against a future last_seen stays negative → stays active.
    again = engine.process("cam-01", utc(1))
    assert again.active_event_count == 1


def test_cap_eviction_preserves_visibility() -> None:
    settings = _settings(intelligence_max_events_per_camera=200, intelligence_max_clusters_per_camera=1)
    rules: list[SafetyRule] = [StubRule(f"stub-{i}") for i in range(3)]
    safety = SafetyEngine(settings, rules)
    safety.process("cam-01", [], utc(0))
    engine = IntelligenceEngine(settings, safety_engine=safety)
    engine.process("cam-01", utc(0))
    state = engine._cameras["cam-01"]
    assert len(state.clusters) == 1
    # Evicted clusters remain readable in the recent ring, not counted resolved.
    assert len(state.recent_clusters) == 2
    assert state.clusters_resolved == 0


def test_duplicate_source_ids_across_domains_stay_distinct() -> None:
    first = make_unified_event(source_event_id="same-id", source_domain=EventSourceDomain.SAFETY)
    second = make_unified_event(source_event_id="same-id", source_domain=EventSourceDomain.QUALITY)
    assert (first.source_domain.value, first.source_event_id) != (
        second.source_domain.value,
        second.source_event_id,
    )


def test_empty_tracks_process_cleanly() -> None:
    safety = SafetyEngine(_settings(), [StubRule("stub")])
    safety.process("cam-01", [], utc(0))
    engine = _intel(safety=safety)
    result = engine.process("cam-01", utc(0))
    assert result.events[0].track_ids == []
    assert result.clusters[0].track_ids == []


def test_resolved_cluster_recreates_on_reactivation() -> None:
    stub = StubRule("stub")
    rule_engine = SafetyEngine(_settings(safety_event_resolution_grace_seconds=0.5), [stub])
    rule_engine.process("cam-01", [], utc(0))
    engine = _intel(safety=rule_engine)
    engine.process("cam-01", utc(0))
    assert len(engine.active_clusters("cam-01")) == 1
    stub.active = False
    rule_engine.process("cam-01", [], utc(10))
    engine.process("cam-01", utc(10))
    engine.process("cam-01", utc(20))
    assert engine.active_clusters("cam-01") == []
    # Reactivation mints a fresh cluster (new source event id from the domain).
    stub.active = True
    rule_engine.process("cam-01", [], utc(30))
    engine.process("cam-01", utc(30))
    assert len(engine.active_clusters("cam-01")) == 1


def test_far_past_grace_resolves_stale_state() -> None:
    safety = SafetyEngine(_settings(), [StubRule("stub")])
    safety.process("cam-01", [], utc(0))
    engine = _intel(safety=safety)
    engine.process("cam-01", utc(0))
    # Source vanishes entirely (fresh engine state simulates restart mid-stream).
    engine2 = _intel(safety=SafetyEngine(_settings(), [StubRule("stub")]))
    result = engine2.process("cam-01", utc(1000))
    assert result.active_event_count == 0


def test_track_identity_flows_into_cluster() -> None:
    safety = SafetyEngine(_settings(), [StubRule("stub", SafetySeverity.HIGH)])
    track = make_track(11, "person", (100.0, 100.0, 150.0, 300.0))
    safety.process("cam-01", [track], utc(0))
    engine = _intel(safety=safety)
    result = engine.process("cam-01", utc(0))
    assert result.clusters[0].track_ids == [11]
    assert result.events[0].related_event_ids == []
    # A far-future touch keeps the timeline monotonic and non-negative.
    event = result.events[0]
    event.touch(event.first_seen + timedelta(seconds=5))
    assert event.last_seen == event.first_seen + timedelta(seconds=5)
    assert event.timestamp >= event.first_seen
