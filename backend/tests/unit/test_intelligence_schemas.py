"""Intelligence schema tests — enums, taxonomy, lifecycle, serialization."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.app.intelligence.schemas import (
    ACTIVE_DOMAINS,
    RESERVED_DOMAINS,
    EventPriority,
    EventSourceDomain,
    RiskAssessment,
    RiskCluster,
    RiskFactor,
    RiskIntelligenceResult,
    RiskLevel,
    UnifiedEventStatus,
    UnifiedEventType,
    UnifiedSeverity,
)
from backend.tests.intelligence_helpers import make_unified_event, utc


def test_source_domains() -> None:
    assert {d.value for d in EventSourceDomain} == {
        "SAFETY",
        "SPATIAL",
        "QUALITY",
        "AUTONOMOUS",
        "TRACKING",
        "PERCEPTION",
        "SYSTEM",
    }
    assert ACTIVE_DOMAINS == frozenset(
        {
            EventSourceDomain.SAFETY,
            EventSourceDomain.SPATIAL,
            EventSourceDomain.QUALITY,
            EventSourceDomain.AUTONOMOUS,
        }
    )
    assert RESERVED_DOMAINS == frozenset(
        {EventSourceDomain.TRACKING, EventSourceDomain.PERCEPTION, EventSourceDomain.SYSTEM}
    )
    assert ACTIVE_DOMAINS.isdisjoint(RESERVED_DOMAINS)


def test_taxonomy_covers_spec_types() -> None:
    values = {t.value for t in UnifiedEventType}
    for expected in (
        "PERSON_VEHICLE_PROXIMITY",
        "RESTRICTED_ZONE_ENTRY",
        "RESTRICTED_ZONE_DWELL",
        "FALL_RISK",
        "CROWD_WARNING",
        "CROWD_CRITICAL",
        "STATIONARY_OBJECT",
        "QUALITY_FAIL",
        "QUALITY_REVIEW",
        "DEFECT_DETECTED",
        "COLLISION_RISK",
        "LANE_DEPARTURE_RISK",
        "OBJECT_APPROACH",
        "OBJECT_CROSSING",
        "SCENE_CHANGE",
        "SYSTEM_ERROR",
        # V09 additions beyond the spec examples:
        "RESTRICTED_ZONE_EXIT",
        "QUALITY_ERROR",
        "UNKNOWN",
    ):
        assert expected in values


def test_severity_and_lifecycle_enums() -> None:
    assert {s.value for s in UnifiedSeverity} == {
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "UNKNOWN",
    }
    assert {r.value for r in RiskLevel} == {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
    assert [p.value for p in EventPriority] == ["P0", "P1", "P2", "P3", "P4"]
    assert {s.value for s in UnifiedEventStatus} == {"ACTIVE", "RESOLVED", "SUPPRESSED"}


def test_unified_event_defaults() -> None:
    event = make_unified_event()
    assert event.status is UnifiedEventStatus.ACTIVE
    assert event.risk_score == 0.0
    assert event.priority is EventPriority.P4
    assert event.related_event_ids == []
    assert event.location is None


def test_unified_event_validation() -> None:
    with pytest.raises(ValidationError):
        make_unified_event(camera_id="")
    with pytest.raises(ValidationError):
        make_unified_event(source_event_id="")
    with pytest.raises(ValidationError):
        make_unified_event(confidence=1.5)
    with pytest.raises(ValidationError):
        make_unified_event(risk_score=-0.1)


def test_touch_updates_last_seen() -> None:
    event = make_unified_event()
    event.touch(utc(90))
    assert event.last_seen == utc(90)
    assert event.timestamp == utc(90)


def test_websocket_shape_is_bounded() -> None:
    payload = make_unified_event().to_websocket()
    assert set(payload) == {
        "event_id",
        "source_event_id",
        "camera_id",
        "source_domain",
        "event_type",
        "severity",
        "status",
        "confidence",
        "risk_score",
        "priority",
        "timestamp",
        "first_seen",
        "last_seen",
        "track_ids",
        "object_ids",
        "related_event_ids",
        "location",
        "message",
        "reason",
    }
    assert "evidence" not in payload
    assert "metadata" not in payload


def test_risk_factor_validation() -> None:
    factor = RiskFactor(name="severity", value=0.75, weight=0.35, contribution=0.2625, reason="r")
    assert factor.contribution == 0.2625
    with pytest.raises(ValidationError):
        RiskFactor(name="x", value=1.5, weight=0.5, contribution=0.5, reason="r")


def test_cluster_defaults_and_serialization() -> None:
    cluster = RiskCluster(camera_id="cam-01")
    assert cluster.status is UnifiedEventStatus.ACTIVE
    assert cluster.priority is EventPriority.P4
    assert cluster.event_count == 0
    payload = cluster.to_websocket()
    assert payload["risk_level"] == "UNKNOWN"
    assert payload["factors"] == []
    assert payload["source_domains"] == []


def test_result_defaults() -> None:
    result = RiskIntelligenceResult(camera_id="cam-01")
    assert result.highest_priority is EventPriority.P4
    assert result.active_event_count == 0
    assert result.highest_risk.risk_score == 0.0


def test_assessment_defaults() -> None:
    assessment = RiskAssessment()
    assert assessment.risk_level is RiskLevel.UNKNOWN
    assert assessment.factors == []
