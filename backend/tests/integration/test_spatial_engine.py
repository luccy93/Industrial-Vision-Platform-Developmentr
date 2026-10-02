"""Spatial engine end-to-end — V06 rules inside the V05 event lifecycle."""

from __future__ import annotations

from typing import Any

from backend.app.core.config import Settings
from backend.app.safety.engine import SafetyEngine
from backend.app.safety.schemas import SafetyEventStatus
from backend.app.spatial.engine import SpatialEngine
from backend.app.spatial.rules import spatial_rules
from backend.app.spatial.schemas import SafetyZone, ZonePoint, ZoneType
from backend.tests.safety_helpers import make_track, utc

_WIDTH, _HEIGHT = 1000.0, 1000.0
_POLYGON = [
    ZonePoint(x=0.2, y=0.4),
    ZonePoint(x=0.8, y=0.4),
    ZonePoint(x=0.8, y=0.9),
    ZonePoint(x=0.2, y=0.9),
]


def _build(**overrides: Any) -> tuple[SafetyEngine, SpatialEngine]:
    settings = Settings(  # type: ignore[call-arg]
        _env_file=None,
        safety_event_resolution_grace_seconds=1.0,
        **overrides,
    )
    spatial = SpatialEngine(settings)
    spatial.set_zones(
        "cam-01",
        [
            SafetyZone(
                zone_id="restricted-01",
                camera_id="cam-01",
                name="Furnace hall",
                zone_type=ZoneType.RESTRICTED,
                polygon=_POLYGON,
                dwell_threshold_seconds=2.0,
            )
        ],
    )
    return SafetyEngine(settings, spatial_rules(spatial)), spatial


def _person(track_id: int, x: float):  # type: ignore[no-untyped-def]
    return make_track(track_id, "person", (x, 300.0, x + 50.0, 500.0), camera_id="cam-01")


def _vehicle(track_id: int):  # type: ignore[no-untyped-def]
    return make_track(track_id, "forklift", (420.0, 320.0, 780.0, 600.0), camera_id="cam-01")


def test_zone_entry_exit_share_v05_lifecycle() -> None:
    engine, _ = _build()
    first = engine.process("cam-01", [_person(1, 400.0)], utc(0), _WIDTH, _HEIGHT)
    types = [e.event_type.value for e in first.new_events]
    assert "RESTRICTED_ZONE_ENTRY" in types
    entry = next(e for e in first.new_events if e.event_type.value == "RESTRICTED_ZONE_ENTRY")
    assert entry.is_spatial is True
    assert entry.metadata["rule"] == "restricted_zone"
    assert entry.evidence["zone_id"] == "restricted-01"
    assert entry.status == SafetyEventStatus.ACTIVE

    # Same condition next frame → no new event, same event_id.
    second = engine.process("cam-01", [_person(1, 400.0)], utc(0.5), _WIDTH, _HEIGHT)
    assert second.new_events == []

    # Entry resolves after the grace window without new observations.
    resolved = engine.process("cam-01", [_person(1, 400.0)], utc(5), _WIDTH, _HEIGHT)
    entry_ids = {e.event_id for e in first.new_events}
    resolved_entry = next(e for e in resolved.resolved_events if e.event_id in entry_ids)
    assert resolved_entry.status == SafetyEventStatus.RESOLVED


def test_dwell_event_resolves_after_exit() -> None:
    engine, _ = _build()
    track = _person(1, 400.0)
    engine.process("cam-01", [track], utc(0), _WIDTH, _HEIGHT)
    engine.process("cam-01", [track], utc(1), _WIDTH, _HEIGHT)
    dwell_pass = engine.process("cam-01", [track], utc(2), _WIDTH, _HEIGHT)
    dwell = next(e for e in dwell_pass.active_events if e.event_type.value == "ZONE_DWELL")
    dwell_id = dwell.event_id

    # Leaving emits the exit event and stops refreshing dwell.
    exit_pass = engine.process("cam-01", [_person(1, 50.0)], utc(3), _WIDTH, _HEIGHT)
    assert any(e.event_type.value == "RESTRICTED_ZONE_EXIT" for e in exit_pass.new_events)
    resolved_ids = {e.event_id for e in exit_pass.resolved_events}

    after = engine.process("cam-01", [_person(1, 50.0)], utc(6), _WIDTH, _HEIGHT)
    resolved_ids |= {e.event_id for e in after.resolved_events}
    # Never stuck: the dwell event always resolves once the object is gone.
    assert dwell_id in resolved_ids


def test_proximity_event_lifecycle_and_suppression() -> None:
    engine, _ = _build()
    tracks = [_person(1, 400.0), _vehicle(2)]
    first = engine.process("cam-01", tracks, utc(0), _WIDTH, _HEIGHT)
    prox = [e for e in first.new_events if e.event_type.value == "PERSON_VEHICLE_PROXIMITY"]
    assert prox, [e.event_type.value for e in first.new_events]
    event = prox[0]
    assert event.metadata["rule"] == "proximity_relationships"
    assert event.is_spatial is True
    assert event.track_ids == [1, 2]
    assert event.evidence["strategy"] == "HYBRID"

    again = engine.process("cam-01", tracks, utc(1), _WIDTH, _HEIGHT)
    assert not [e for e in again.new_events if e.event_type.value == "PERSON_VEHICLE_PROXIMITY"]

    assert engine.suppress("cam-01", str(event.event_id)) == SafetyEventStatus.SUPPRESSED
    fresh = engine.process("cam-01", tracks, utc(2), _WIDTH, _HEIGHT)
    assert any(e.event_type.value == "PERSON_VEHICLE_PROXIMITY" for e in fresh.new_events)


def test_cameras_are_isolated() -> None:
    engine, spatial = _build()
    spatial.set_zones(
        "cam-02",
        [
            SafetyZone(
                zone_id="restricted-02",
                camera_id="cam-02",
                name="Other",
                polygon=_POLYGON,
                dwell_threshold_seconds=2.0,
            )
        ],
    )
    engine.process("cam-01", [_person(1, 400.0)], utc(0), _WIDTH, _HEIGHT)
    other = engine.process("cam-02", [], utc(0), _WIDTH, _HEIGHT)
    assert other.new_events == []
    assert engine.active_events("cam-02") == []


def test_disabled_engine_emits_nothing() -> None:
    engine, _ = _build(spatial_enabled=False)
    result = engine.process("cam-01", [_person(1, 400.0), _vehicle(2)], utc(0), _WIDTH, _HEIGHT)
    assert result.new_events == []


def test_zero_frame_size_degrades_without_crashing() -> None:
    """Unknown frame size falls back to unit coordinates instead of failing."""
    engine, _ = _build()
    # Boxes already expressed in unit coordinates stay inside the polygon.
    unit_track = make_track(1, "person", (0.4, 0.0, 0.45, 0.5), camera_id="cam-01")
    result = engine.process("cam-01", [unit_track], utc(0), 0.0, 0.0)
    assert [e.event_type.value for e in result.new_events] == ["RESTRICTED_ZONE_ENTRY"]
