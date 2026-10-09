"""Event envelope tests — validation, versions, bounds, malformed input."""

from __future__ import annotations

import pytest

from backend.app.events.envelope import BUS_EVENT_TYPES, EVENT_ENVELOPE_VERSION, EventEnvelope


def _envelope(**overrides) -> EventEnvelope:
    payload = {
        "event_id": "evt-1",
        "event_type": "incident_created",
        "domain": "INCIDENT",
        "camera_id": "cam-01",
        "origin": "proc-test",
        "payload": {"incident_id": "abc"},
    }
    payload.update(overrides)
    return EventEnvelope.model_validate(payload)


def test_envelope_round_trip() -> None:
    envelope = _envelope()
    assert envelope.v == EVENT_ENVELOPE_VERSION
    restored = EventEnvelope.from_bytes(envelope.to_bytes())
    assert restored.event_id == "evt-1"
    assert restored.domain == "INCIDENT"
    assert restored.payload == {"incident_id": "abc"}


def test_domain_normalized_uppercase() -> None:
    assert _envelope(domain="safety").domain == "SAFETY"


def test_oversize_envelope_rejected() -> None:
    envelope = _envelope(payload={"blob": "x" * 4096})
    with pytest.raises(ValueError):
        envelope.to_bytes(max_payload_bytes=2048)
    # And the floor never lets callers disable the bound entirely.
    with pytest.raises(ValueError):
        envelope.to_bytes(max_payload_bytes=100)


def test_malformed_bytes_rejected() -> None:
    for raw in (b"not json", b"[1,2]", b'{"event_id": 1}', b""):
        with pytest.raises(ValueError):
            EventEnvelope.from_bytes(raw)


def test_unsupported_version_rejected() -> None:
    envelope = _envelope()
    raw = envelope.to_bytes().replace(b'"v":1', b'"v":99')
    with pytest.raises(ValueError):
        EventEnvelope.from_bytes(raw)


def test_bus_event_types_cover_locked_scope() -> None:
    for event_type in (
        "safety_event",
        "zone_event",
        "proximity_event",
        "quality_event",
        "quality_result",
        "autonomous_perception",
        "collision_risk",
        "lane_event",
        "intelligence_event",
        "risk_cluster",
        "risk_update",
        "incident_created",
        "incident_status_changed",
        "incident_assigned",
        "incident_resolved",
        "incident_closed",
        "incident_evidence_added",
    ):
        assert event_type in BUS_EVENT_TYPES, event_type
    # High-frequency perception traffic is never bus cargo.
    for banned in ("detection", "tracking", "frame", "stream_status"):
        assert banned not in BUS_EVENT_TYPES, banned


def test_new_id_unique_and_prefixed() -> None:
    first = EventEnvelope.new_id("incident")
    second = EventEnvelope.new_id("incident")
    assert first != second
    assert first.startswith("incident-")
