"""Safety rule tests — geometry, thresholds, disabled rules."""

from __future__ import annotations

from backend.app.core.config import Settings
from backend.app.safety.base import SceneState
from backend.app.safety.rules import (
    CrowdDensityRule,
    FallRiskRule,
    PersonVehicleProximityRule,
    StationaryObjectRule,
    default_rules,
)
from backend.app.safety.schemas import SafetyEventType, SafetySeverity
from backend.app.tracking.schemas import TrackState
from backend.tests.safety_helpers import make_track, utc

_WIDE = (100.0, 200.0, 300.0, 280.0)  # aspect 2.5 → horizontal
_TALL = (100.0, 100.0, 150.0, 300.0)  # aspect 0.25 → vertical


def _scene(*tracks, camera_id: str = "cam-s") -> SceneState:  # type: ignore[no-untyped-def]
    return SceneState(camera_id=camera_id, timestamp=utc(), tracks=list(tracks))


def test_fall_risk_fires_on_persistent_horizontal() -> None:
    rule = FallRiskRule(aspect_threshold=1.2, persistence_frames=5)
    track = make_track(box=_WIDE, history_boxes=[_WIDE] * 6)
    drafts = rule.evaluate(_scene(track))
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.event_type == SafetyEventType.POSSIBLE_FALL
    assert draft.severity == SafetySeverity.MEDIUM
    assert draft.track_ids == [track.track_id]
    assert "fall" in draft.message.lower()


def test_fall_risk_ignores_vertical_and_tentative() -> None:
    rule = FallRiskRule()
    assert rule.evaluate(_scene(make_track(box=_TALL, history_boxes=[_TALL] * 6))) == []
    tentative = make_track(box=_WIDE, history_boxes=[_WIDE] * 6, state=TrackState.TENTATIVE)
    assert rule.evaluate(_scene(tentative)) == []


def test_fall_risk_needs_persistence() -> None:
    rule = FallRiskRule(persistence_frames=5)
    short = make_track(box=_WIDE, history_boxes=[_TALL, _TALL] + [_WIDE] * 2)
    assert rule.evaluate(_scene(short)) == []


def test_fall_risk_disabled_rule() -> None:
    rule = FallRiskRule()
    rule.enabled = False
    assert rule.enabled is False


def test_crowd_warning_and_critical() -> None:
    rule = CrowdDensityRule(warning_count=5, critical_count=10)
    assert rule.evaluate(_scene(*[make_track(i) for i in range(1, 5)])) == []
    warning = rule.evaluate(_scene(*[make_track(i) for i in range(1, 7)]))
    assert len(warning) == 1
    assert warning[0].event_type == SafetyEventType.CROWD_WARNING
    critical = rule.evaluate(_scene(*[make_track(i) for i in range(1, 12)]))
    assert critical[0].event_type == SafetyEventType.CROWD_CRITICAL
    assert critical[0].severity == SafetySeverity.CRITICAL


def test_proximity_overlap_fires() -> None:
    rule = PersonVehicleProximityRule()
    person = make_track(1, "person", box=(100.0, 100.0, 200.0, 300.0))
    vehicle = make_track(2, "forklift", box=(150.0, 150.0, 300.0, 350.0))
    drafts = rule.evaluate(_scene(person, vehicle))
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.event_type == SafetyEventType.PERSON_VEHICLE_PROXIMITY
    assert draft.severity == SafetySeverity.HIGH
    assert set(draft.track_ids) == {1, 2}
    assert "meter" not in draft.message.lower().replace("parameters", "")


def test_proximity_distant_pair_silent() -> None:
    rule = PersonVehicleProximityRule()
    person = make_track(1, "person", box=(0.0, 0.0, 50.0, 200.0))
    vehicle = make_track(2, "car", box=(1000.0, 800.0, 1400.0, 1000.0))
    assert rule.evaluate(_scene(person, vehicle)) == []


def test_proximity_needs_both_roles() -> None:
    rule = PersonVehicleProximityRule()
    pair = [make_track(1, "person", box=(100.0, 100.0, 200.0, 300.0)) for _ in range(2)]
    assert rule.evaluate(_scene(*pair)) == []


def test_stationary_fires_for_still_person() -> None:
    rule = StationaryObjectRule(speed_threshold=15.0, duration_seconds=10.0)
    track = make_track(box=(100.0, 100.0, 150.0, 300.0), history_span_seconds=15.0)
    drafts = rule.evaluate(_scene(track))
    assert len(drafts) == 1
    assert drafts[0].event_type == SafetyEventType.PROLONGED_STATIONARY
    assert drafts[0].severity == SafetySeverity.LOW


def test_stationary_ignores_moving_and_short_span() -> None:
    rule = StationaryObjectRule(speed_threshold=15.0, duration_seconds=10.0)
    moving_boxes = [(100.0 + i * 50.0, 100.0, 150.0 + i * 50.0, 300.0) for i in range(5)]
    moving = make_track(history_boxes=moving_boxes, history_span_seconds=12.0)
    assert rule.evaluate(_scene(moving)) == []
    brief = make_track(history_span_seconds=3.0)
    assert rule.evaluate(_scene(brief)) == []


def test_stationary_ignores_non_configured_class() -> None:
    rule = StationaryObjectRule(duration_seconds=1.0)
    animal = make_track(class_name="dog", history_span_seconds=5.0)
    assert rule.evaluate(_scene(animal)) == []


def test_default_rules_from_settings() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    rules = default_rules(settings)
    assert [r.name for r in rules] == [
        "fall_risk",
        "crowd_density",
        "person_vehicle_proximity",
        "stationary_object",
    ]
    assert all(r.enabled for r in rules)
