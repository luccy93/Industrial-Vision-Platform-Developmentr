"""Normalizer tests — every active domain, taxonomy, preservation, edges."""

from __future__ import annotations

import pytest

from backend.app.autonomous.schemas import PerceptionEventType, RiskLevel
from backend.app.intelligence.normalize import (
    ADAPTERS,
    AutonomousEventAdapter,
    QualityEventAdapter,
    SafetyEventAdapter,
    SpatialEventAdapter,
    is_spatial_safety_event,
)
from backend.app.intelligence.schemas import (
    EventSourceDomain,
    UnifiedEventStatus,
    UnifiedEventType,
    UnifiedSeverity,
)
from backend.app.quality.schemas import QualityDecision, QualityEventStatus, QualityEventType
from backend.app.safety.schemas import SafetyEventStatus, SafetyEventType
from backend.tests.intelligence_helpers import (
    make_autonomous_event,
    make_collision_risk,
    make_quality_event,
    make_safety_event,
    make_spatial_event,
    utc,
)


def test_registered_adapters_cover_active_domains_only() -> None:
    assert set(ADAPTERS) == {
        EventSourceDomain.SAFETY,
        EventSourceDomain.SPATIAL,
        EventSourceDomain.QUALITY,
        EventSourceDomain.AUTONOMOUS,
    }


def test_spatial_detection_by_rule() -> None:
    assert is_spatial_safety_event(make_spatial_event()) is True
    assert is_spatial_safety_event(make_safety_event()) is False
    assert is_spatial_safety_event(make_safety_event(metadata={"rule": "proximity_relationships"})) is True


def test_safety_adapter_mapping() -> None:
    event = SafetyEventAdapter().normalize(make_safety_event())
    assert event.source_domain is EventSourceDomain.SAFETY
    assert event.event_type is UnifiedEventType.PERSON_VEHICLE_PROXIMITY
    assert event.severity is UnifiedSeverity.HIGH
    assert event.track_ids == [7]
    assert event.source_event_id
    assert event.metadata["source_event_type"] == "PERSON_VEHICLE_PROXIMITY"
    assert event.camera_id == "cam-01"
    assert event.confidence == 0.8
    assert event.message == "person near vehicle"


def test_safety_adapter_type_map() -> None:
    cases = [
        (SafetyEventType.POSSIBLE_FALL, UnifiedEventType.FALL_RISK),
        (SafetyEventType.CROWD_WARNING, UnifiedEventType.CROWD_WARNING),
        (SafetyEventType.CROWD_CRITICAL, UnifiedEventType.CROWD_CRITICAL),
        (SafetyEventType.PROLONGED_STATIONARY, UnifiedEventType.STATIONARY_OBJECT),
    ]
    for source, expected in cases:
        unified = SafetyEventAdapter().normalize(make_safety_event(event_type=source))
        assert unified.event_type is expected


def test_safety_adapter_unknown_type_preserves_source() -> None:
    unified = SafetyEventAdapter().normalize(
        make_safety_event(event_type=SafetyEventType.PERSON_PERSON_PROXIMITY)
    )
    assert unified.event_type is UnifiedEventType.UNKNOWN
    assert unified.metadata["source_event_type"] == "PERSON_PERSON_PROXIMITY"


def test_spatial_adapter_mapping_and_location() -> None:
    unified = SpatialEventAdapter().normalize(make_spatial_event())
    assert unified.source_domain is EventSourceDomain.SPATIAL
    assert unified.event_type is UnifiedEventType.RESTRICTED_ZONE_ENTRY
    assert unified.location == "zone-1"
    assert unified.metadata["source_event_type"] == "RESTRICTED_ZONE_ENTRY"


def test_spatial_adapter_dwell_and_exit() -> None:
    dwell = SpatialEventAdapter().normalize(make_spatial_event(event_type=SafetyEventType.ZONE_DWELL))
    assert dwell.event_type is UnifiedEventType.RESTRICTED_ZONE_DWELL
    exited = SpatialEventAdapter().normalize(
        make_spatial_event(event_type=SafetyEventType.RESTRICTED_ZONE_EXIT)
    )
    assert exited.event_type is UnifiedEventType.RESTRICTED_ZONE_EXIT


def test_quality_adapter_mapping() -> None:
    unified = QualityEventAdapter().normalize(make_quality_event())
    assert unified.source_domain is EventSourceDomain.QUALITY
    assert unified.event_type is UnifiedEventType.QUALITY_FAIL
    assert unified.severity is UnifiedSeverity.HIGH
    assert unified.location == "region-1"
    assert unified.metadata["decision"] == "FAIL"
    assert unified.metadata["defect_code"] == "CRACK"


def test_quality_adapter_review_and_error() -> None:
    review = QualityEventAdapter().normalize(
        make_quality_event(event_type=QualityEventType.QUALITY_REVIEW, decision=QualityDecision.REVIEW)
    )
    assert review.event_type is UnifiedEventType.QUALITY_REVIEW
    error = QualityEventAdapter().normalize(
        make_quality_event(event_type=QualityEventType.QUALITY_ERROR, decision=QualityDecision.ERROR)
    )
    assert error.event_type is UnifiedEventType.QUALITY_ERROR


def test_quality_result_pass_yields_none() -> None:
    from backend.app.quality.schemas import InspectionResult, QualityDecision

    result = InspectionResult(
        camera_id="cam-01",
        profile_id="p-1",
        decision=QualityDecision.PASS,
        timestamp=utc(0),
        first_seen=utc(0),
        last_seen=utc(0),
    )
    assert QualityEventAdapter().normalize_result(result) is None


def test_quality_result_fail_normalizes() -> None:
    from backend.app.quality.schemas import InspectionResult, QualityDecision

    result = InspectionResult(
        camera_id="cam-01",
        profile_id="p-1",
        decision=QualityDecision.FAIL,
        decision_reason="crack found",
        timestamp=utc(0),
        first_seen=utc(0),
        last_seen=utc(0),
        regions_evaluated=["region-1"],
    )
    unified = QualityEventAdapter().normalize_result(result)
    assert unified is not None
    assert unified.event_type is UnifiedEventType.QUALITY_FAIL
    assert unified.location == "region-1"
    assert unified.metadata["source_event_type"] == "RESULT_FAIL"


def test_autonomous_adapter_mapping() -> None:
    unified = AutonomousEventAdapter().normalize(make_autonomous_event())
    assert unified.source_domain is EventSourceDomain.AUTONOMOUS
    assert unified.event_type is UnifiedEventType.COLLISION_RISK
    assert unified.severity is UnifiedSeverity.HIGH
    assert unified.object_ids == ["track-3", "track-5"]
    assert unified.metadata["source_event_type"] == "COLLISION_RISK"


def test_autonomous_adapter_all_types() -> None:
    cases = [
        (PerceptionEventType.LANE_DEPARTURE_RISK, UnifiedEventType.LANE_DEPARTURE_RISK),
        (PerceptionEventType.OBJECT_APPROACH, UnifiedEventType.OBJECT_APPROACH),
        (PerceptionEventType.OBJECT_CROSSING, UnifiedEventType.OBJECT_CROSSING),
        (PerceptionEventType.SCENE_CHANGE, UnifiedEventType.SCENE_CHANGE),
    ]
    for source, expected in cases:
        unified = AutonomousEventAdapter().normalize(make_autonomous_event(event_type=source))
        assert unified.event_type is expected


def test_autonomous_risk_level_severity_map() -> None:
    cases = [
        ("NONE", "INFO"),
        ("LOW", "LOW"),
        ("MEDIUM", "MEDIUM"),
        ("HIGH", "HIGH"),
        ("CRITICAL", "CRITICAL"),
    ]
    for risk, severity in cases:
        unified = AutonomousEventAdapter().normalize(make_autonomous_event(risk_level=RiskLevel(risk)))
        assert unified.severity.value == severity


def test_collision_risk_adapter() -> None:
    unified = AutonomousEventAdapter().normalize_risk(make_collision_risk(), "cam-09")
    assert unified.event_type is UnifiedEventType.COLLISION_RISK
    assert unified.camera_id == "cam-09"
    assert unified.object_ids == ["track-3", "track-5"]
    assert unified.source_event_id == "collision-risk:track-3:track-5"
    assert unified.evidence["risk_score"] == 0.82
    assert unified.evidence["time_to_collision"] == 1.5
    with pytest.raises(ValueError):
        AutonomousEventAdapter().normalize_risk(make_collision_risk(), "  ")


def test_status_mirroring() -> None:
    resolved = SafetyEventAdapter().normalize(make_safety_event(status=SafetyEventStatus.RESOLVED))
    assert resolved.status is UnifiedEventStatus.RESOLVED
    suppressed = QualityEventAdapter().normalize(make_quality_event(status=QualityEventStatus.SUPPRESSED))
    assert suppressed.status is UnifiedEventStatus.SUPPRESSED


def test_missing_identity_rejected() -> None:
    with pytest.raises(ValueError):
        SafetyEventAdapter().normalize(None)
    with pytest.raises(ValueError):
        SafetyEventAdapter().normalize(make_safety_event(camera_id="  "))
    with pytest.raises(ValueError):
        QualityEventAdapter().normalize(None)
    with pytest.raises(ValueError):
        AutonomousEventAdapter().normalize(None)
    with pytest.raises(ValueError):
        QualityEventAdapter().normalize_result(None)
    with pytest.raises(ValueError):
        AutonomousEventAdapter().normalize_risk(None, "cam-01")


def test_missing_optionals_degrade_safely() -> None:
    event = make_safety_event(track_ids=[], metadata={"rule": "x"})
    event.message = None  # type: ignore[assignment]
    event.evidence = None  # type: ignore[assignment]
    unified = SafetyEventAdapter().normalize(event)
    assert unified.track_ids == []
    assert unified.evidence == {}
    assert unified.message == ""


def test_timestamps_preserved() -> None:
    unified = QualityEventAdapter().normalize(
        make_quality_event(timestamp=utc(10), first_seen=utc(2), last_seen=utc(9))
    )
    assert unified.timestamp == utc(10)
    assert unified.first_seen == utc(2)
    assert unified.last_seen == utc(9)
