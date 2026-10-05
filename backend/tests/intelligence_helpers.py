"""Shared intelligence test builders — deterministic, hermetic, no services.

Mirrors the domain helper modules: a fixed synthetic epoch keeps duration
assertions stable. Builders return real domain event objects (never
hand-rolled dicts) so adapter tests exercise genuine source shapes.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from backend.app.autonomous.schemas import (
    AutonomousPerceptionEvent,
    CollisionRisk,
    PerceptionEventType,
    RiskLevel,
)
from backend.app.intelligence.schemas import (
    EventSourceDomain,
    UnifiedEvent,
    UnifiedEventType,
    UnifiedSeverity,
)
from backend.app.quality.schemas import (
    DefectSeverity,
    QualityDecision,
    QualityEvent,
    QualityEventStatus,
    QualityEventType,
)
from backend.app.safety.schemas import SafetyEvent, SafetyEventStatus, SafetyEventType, SafetySeverity

_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


def utc(offset_seconds: float = 0.0) -> datetime:
    """Deterministic test clock: exact offsets from a fixed epoch."""
    return _EPOCH + timedelta(seconds=offset_seconds)


def make_safety_event(**overrides: Any) -> SafetyEvent:
    params: dict[str, Any] = {
        "event_id": uuid4(),
        "camera_id": "cam-01",
        "track_ids": [7],
        "event_type": SafetyEventType.PERSON_VEHICLE_PROXIMITY,
        "severity": SafetySeverity.HIGH,
        "status": SafetyEventStatus.ACTIVE,
        "confidence": 0.8,
        "timestamp": utc(0),
        "first_seen": utc(0),
        "last_seen": utc(0),
        "message": "person near vehicle",
        "evidence": {},
        "metadata": {"rule": "person_vehicle_proximity"},
    }
    params.update(overrides)
    return SafetyEvent(**params)


def make_spatial_event(**overrides: Any) -> SafetyEvent:
    params: dict[str, Any] = {
        "event_type": SafetyEventType.RESTRICTED_ZONE_ENTRY,
        "severity": SafetySeverity.HIGH,
        "message": "person entered restricted zone",
        "evidence": {"zone_id": "zone-1", "zone_name": "Furnace"},
        "metadata": {"rule": "restricted_zone"},
    }
    params.update(overrides)
    return make_safety_event(**params)


def make_quality_event(**overrides: Any) -> QualityEvent:
    params: dict[str, Any] = {
        "event_id": uuid4(),
        "camera_id": "cam-01",
        "event_type": QualityEventType.QUALITY_FAIL,
        "decision": QualityDecision.FAIL,
        "severity": DefectSeverity.HIGH,
        "status": QualityEventStatus.ACTIVE,
        "confidence": 0.85,
        "defect_code": "CRACK",
        "region_id": "region-1",
        "timestamp": utc(0),
        "first_seen": utc(0),
        "last_seen": utc(0),
        "message": "crack detected",
    }
    params.update(overrides)
    return QualityEvent(**params)


def make_autonomous_event(**overrides: Any) -> AutonomousPerceptionEvent:
    params: dict[str, Any] = {
        "event_id": uuid4(),
        "camera_id": "cam-01",
        "event_type": PerceptionEventType.COLLISION_RISK,
        "risk_level": RiskLevel.HIGH,
        "object_ids": ["track-3", "track-5"],
        "confidence": 0.78,
        "timestamp": utc(0),
        "first_seen": utc(0),
        "last_seen": utc(0),
        "message": "closing pair",
    }
    params.update(overrides)
    return AutonomousPerceptionEvent(**params)


def make_collision_risk(**overrides: Any) -> CollisionRisk:
    params: dict[str, Any] = {
        "object_ids": ["track-3", "track-5"],
        "risk_level": RiskLevel.HIGH,
        "risk_score": 0.82,
        "time_to_collision": 1.5,
        "confidence": 0.78,
        "reason": "relative approach trajectory",
        "timestamp": utc(0),
    }
    params.update(overrides)
    return CollisionRisk(**params)


def make_unified_event(**overrides: Any) -> UnifiedEvent:
    params: dict[str, Any] = {
        "source_event_id": str(uuid4()),
        "camera_id": "cam-01",
        "source_domain": EventSourceDomain.SAFETY,
        "event_type": UnifiedEventType.PERSON_VEHICLE_PROXIMITY,
        "severity": UnifiedSeverity.HIGH,
        "confidence": 0.8,
        "timestamp": utc(0),
        "first_seen": utc(0),
        "last_seen": utc(0),
        "track_ids": [7],
        "message": "person near vehicle",
    }
    params.update(overrides)
    return UnifiedEvent(**params)
