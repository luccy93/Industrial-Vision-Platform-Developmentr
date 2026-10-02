"""Safety model tests — enums, validation, serialization."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.app.safety.schemas import (
    SafetyAnalysisResult,
    SafetyEvent,
    SafetyEventStatus,
    SafetyEventType,
    SafetySeverity,
)


def _event(**overrides) -> SafetyEvent:  # type: ignore[no-untyped-def]
    params: dict = {
        "camera_id": "cam-01",
        "track_ids": [17],
        "event_type": SafetyEventType.PERSON_VEHICLE_PROXIMITY,
        "severity": SafetySeverity.HIGH,
        "confidence": 0.91,
        "message": "Person and vehicle proximity risk detected",
    }
    params.update(overrides)
    return SafetyEvent(**params)


def test_event_defaults_and_enums() -> None:
    event = _event()
    assert event.status == SafetyEventStatus.ACTIVE
    assert event.duration_ms == 0.0
    assert event.evidence == {} and event.metadata == {}
    assert {t.value for t in SafetyEventType} == {
        "POSSIBLE_FALL",
        "CROWD_WARNING",
        "CROWD_CRITICAL",
        "PERSON_VEHICLE_PROXIMITY",
        "PROLONGED_STATIONARY",
        "RESTRICTED_ZONE_ENTRY",
        "RESTRICTED_ZONE_EXIT",
        "ZONE_DWELL",
        "PERSON_PERSON_PROXIMITY",
        "VEHICLE_VEHICLE_PROXIMITY",
    }
    assert {s.value for s in SafetySeverity} == {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert {s.value for s in SafetyEventStatus} == {"ACTIVE", "RESOLVED", "SUPPRESSED"}


def test_confidence_bounds() -> None:
    with pytest.raises(ValidationError):
        _event(confidence=1.5)


def test_touch_updates_duration() -> None:
    from datetime import timedelta

    event = _event()
    event.touch(event.first_seen + timedelta(seconds=4))
    assert event.duration_ms == 4000.0
    assert event.last_seen == event.first_seen + timedelta(seconds=4)


def test_websocket_payload() -> None:
    payload = _event().to_websocket()
    assert payload["event_type"] == "PERSON_VEHICLE_PROXIMITY"
    assert payload["severity"] == "HIGH"
    assert payload["track_ids"] == [17]
    assert "meters" not in str(payload).lower()


def test_analysis_result_shape() -> None:
    result = SafetyAnalysisResult(camera_id="c", timestamp=__import__("datetime").datetime.now())
    assert result.active_events == [] and result.new_events == []
    assert result.resolved_events == [] and result.metrics == {}


def test_malformed_inputs_rejected() -> None:
    with pytest.raises(ValidationError):
        SafetyEvent(camera_id="", track_ids=[], event_type="NOPE")  # type: ignore[arg-type]
