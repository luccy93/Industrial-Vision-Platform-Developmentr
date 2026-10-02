"""V06 spatial runtime tests — zones, transitions, dwell, disappearance."""

from __future__ import annotations

from typing import Any

from backend.app.core.config import Settings
from backend.app.spatial.engine import SpatialEngine
from backend.app.spatial.rules import ZoneRule, spatial_rules
from backend.app.spatial.schemas import (
    SafetyZone,
    ZonePoint,
    ZoneTransition,
    ZoneType,
)
from backend.tests.safety_helpers import make_track, utc

_WIDTH, _HEIGHT = 1000.0, 1000.0

# Polygon covering the middle band of the frame in normalized coordinates.
_POLYGON = [
    ZonePoint(x=0.2, y=0.4),
    ZonePoint(x=0.8, y=0.4),
    ZonePoint(x=0.8, y=0.9),
    ZonePoint(x=0.2, y=0.9),
]


def _settings(**overrides: Any) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def _zone(**overrides: object) -> SafetyZone:
    params: dict = {
        "zone_id": "restricted-01",
        "camera_id": "cam-01",
        "name": "Furnace hall",
        "zone_type": ZoneType.RESTRICTED,
        "polygon": _POLYGON,
    }
    params.update(overrides)
    return SafetyZone(**params)  # type: ignore[arg-type]


def _engine(zones: list[SafetyZone] | None = None, **overrides: object) -> SpatialEngine:
    engine = SpatialEngine(_settings(**overrides))
    if zones:
        engine.set_zones("cam-01", zones)
    return engine


def _person(track_id: int, x: float, y_bottom: float = 500.0):  # type: ignore[no-untyped-def]
    # Anchor point is the bbox bottom-center → (x + 25, y_bottom).
    return make_track(track_id, "person", (x, y_bottom - 200.0, x + 50.0, y_bottom))


def test_entry_and_exit_transitions() -> None:
    engine = _engine([_zone()])
    inside = engine.process_zones("cam-01", [_person(1, 450.0)], _WIDTH, _HEIGHT, utc(0))
    assert [e.transition for e in inside] == [ZoneTransition.ENTRY]
    assert inside[0].severity.value == "HIGH"
    assert inside[0].evidence["anchor_x"] == 0.475

    steady = engine.process_zones("cam-01", [_person(1, 450.0)], _WIDTH, _HEIGHT, utc(1))
    assert steady == []  # no churn while it stays inside

    outside = engine.process_zones("cam-01", [_person(1, 50.0)], _WIDTH, _HEIGHT, utc(2))
    assert [e.transition for e in outside] == [ZoneTransition.EXIT]
    assert outside[0].reason == "anchor_exited"


def test_dwell_emits_once_threshold_and_keeps_refreshing() -> None:
    engine = _engine([_zone(dwell_threshold_seconds=2.0)])
    track = _person(1, 450.0)
    entry = engine.process_zones("cam-01", [track], _WIDTH, _HEIGHT, utc(0))
    assert [e.transition for e in entry] == [ZoneTransition.ENTRY]
    assert entry[0].camera_id == "cam-01"  # processing camera, not the track's
    assert not engine.process_zones("cam-01", [track], _WIDTH, _HEIGHT, utc(1))

    dwell = engine.process_zones("cam-01", [track], _WIDTH, _HEIGHT, utc(2))
    assert [e.transition for e in dwell] == [ZoneTransition.STATIONARY_INSIDE]
    assert dwell[0].reason == "dwell_threshold"
    assert dwell[0].dwell_seconds == 2.0
    assert dwell[0].evidence["first_observation"] is True

    again = engine.process_zones("cam-01", [track], _WIDTH, _HEIGHT, utc(3))
    assert again[0].evidence["first_observation"] is False
    assert again[0].dwell_seconds == 3.0


def test_dwell_uses_zone_override_then_default() -> None:
    engine = _engine([_zone(dwell_threshold_seconds=None)], spatial_default_dwell_seconds=1.0)
    track = _person(1, 450.0)
    engine.process_zones("cam-01", [track], _WIDTH, _HEIGHT, utc(0))
    events = engine.process_zones("cam-01", [track], _WIDTH, _HEIGHT, utc(1))
    assert events and events[0].transition == ZoneTransition.STATIONARY_INSIDE


def test_safe_zones_do_not_emit() -> None:
    engine = _engine([_zone(zone_type=ZoneType.SAFE)])
    assert engine.process_zones("cam-01", [_person(1, 450.0)], _WIDTH, _HEIGHT, utc(0)) == []


def test_zone_class_filter_from_metadata() -> None:
    engine = _engine([_zone(metadata={"classes": ["forklift"]})])
    assert engine.process_zones("cam-01", [_person(1, 450.0)], _WIDTH, _HEIGHT, utc(0)) == []
    forklift = make_track(2, "forklift", (400.0, 300.0, 700.0, 500.0))
    assert engine.process_zones("cam-01", [forklift], _WIDTH, _HEIGHT, utc(0))


def test_disappearance_exits_after_grace_and_purges_state() -> None:
    engine = _engine([_zone()], spatial_state_grace_seconds=2.0)
    engine.process_zones("cam-01", [_person(1, 450.0)], _WIDTH, _HEIGHT, utc(0))

    # Within grace: nothing yet, state retained (single-frame dropout).
    assert engine.process_zones("cam-01", [], _WIDTH, _HEIGHT, utc(1)) == []
    assert engine.state_count() == 1

    expired = engine.process_zones("cam-01", [], _WIDTH, _HEIGHT, utc(5))
    assert [e.transition for e in expired] == [ZoneTransition.EXIT]
    assert expired[0].reason == "track_disappeared"
    assert engine.state_count() == 0


def test_tentative_and_unknown_classes_ignored() -> None:
    from backend.app.tracking.schemas import TrackState

    engine = _engine([_zone()])
    tentative = make_track(1, "person", (450.0, 300.0, 500.0, 500.0), state=TrackState.TENTATIVE)
    other = make_track(2, "dog", (450.0, 300.0, 500.0, 500.0))
    assert engine.process_zones("cam-01", [tentative, other], _WIDTH, _HEIGHT, utc(0)) == []


def test_zone_removal_clears_state() -> None:
    engine = _engine([_zone()])
    engine.process_zones("cam-01", [_person(1, 450.0)], _WIDTH, _HEIGHT, utc(0))
    assert engine.state_count() == 1
    engine.remove_zone("cam-01", "restricted-01")
    assert engine.state_count() == 0
    assert engine.zones_for("cam-01") == []


def test_camera_reset_clears_zones_and_states() -> None:
    engine = _engine([_zone()])
    engine.process_zones("cam-01", [_person(1, 450.0)], _WIDTH, _HEIGHT, utc(0))
    engine.reset_camera("cam-01")
    assert engine.zone_count() == 0 and engine.state_count() == 0


def test_membership_snapshot() -> None:
    engine = _engine([_zone()])
    engine.process_zones("cam-01", [_person(1, 450.0)], _WIDTH, _HEIGHT, utc(0))
    members = engine.membership_snapshot("cam-01")
    assert len(members) == 1
    assert members[0].zone_id == "restricted-01"
    assert members[0].inside is True
    assert members[0].entered_at is not None
    engine.reset_camera("cam-01")
    assert engine.membership_snapshot("cam-01") == []


def test_zone_rule_drafts_map_to_event_types() -> None:
    engine = _engine([_zone(dwell_threshold_seconds=0.0)])
    rule = ZoneRule(engine)
    from backend.app.safety.base import SceneState

    scene = SceneState(
        camera_id="cam-01",
        timestamp=utc(0),
        tracks=[_person(1, 450.0)],
        frame_width=_WIDTH,
        frame_height=_HEIGHT,
    )
    drafts = rule.evaluate(scene)
    keys = {d.event_type.value for d in drafts}
    assert keys == {"RESTRICTED_ZONE_ENTRY", "ZONE_DWELL"}
    assert all("image_space" in d.evidence for d in drafts)
    assert {r.name for r in spatial_rules(engine)} == {"restricted_zone", "proximity_relationships"}
