"""Unified event and risk intelligence domain model.

A ``UnifiedEvent`` is the canonical, source-preserving view of one domain
event. A ``RiskCluster`` groups unified events that share identity, location,
and time. A ``RiskAssessment`` explains one score through named factors —
scores are never emitted without their explanation.

Risk score semantics: ``risk_score`` is a normalized operational heuristic in
[0, 1]. It is NOT a calibrated probability, statistical forecast, or
certified safety measurement.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from backend.app.domain.common import utcnow


class EventSourceDomain(str, Enum):
    SAFETY = "SAFETY"
    SPATIAL = "SPATIAL"
    QUALITY = "QUALITY"
    AUTONOMOUS = "AUTONOMOUS"
    TRACKING = "TRACKING"
    PERCEPTION = "PERCEPTION"
    SYSTEM = "SYSTEM"


# Domains with no registered adapter in V09. They exist in the taxonomy for
# future extensibility; V09 never synthesizes events for them.
RESERVED_DOMAINS: frozenset[EventSourceDomain] = frozenset(
    {EventSourceDomain.TRACKING, EventSourceDomain.PERCEPTION, EventSourceDomain.SYSTEM}
)

ACTIVE_DOMAINS: frozenset[EventSourceDomain] = frozenset(
    {
        EventSourceDomain.SAFETY,
        EventSourceDomain.SPATIAL,
        EventSourceDomain.QUALITY,
        EventSourceDomain.AUTONOMOUS,
    }
)


class UnifiedEventType(str, Enum):
    PERSON_VEHICLE_PROXIMITY = "PERSON_VEHICLE_PROXIMITY"
    RESTRICTED_ZONE_ENTRY = "RESTRICTED_ZONE_ENTRY"
    RESTRICTED_ZONE_EXIT = "RESTRICTED_ZONE_EXIT"
    RESTRICTED_ZONE_DWELL = "RESTRICTED_ZONE_DWELL"
    FALL_RISK = "FALL_RISK"
    CROWD_WARNING = "CROWD_WARNING"
    CROWD_CRITICAL = "CROWD_CRITICAL"
    STATIONARY_OBJECT = "STATIONARY_OBJECT"
    QUALITY_FAIL = "QUALITY_FAIL"
    QUALITY_REVIEW = "QUALITY_REVIEW"
    QUALITY_ERROR = "QUALITY_ERROR"
    DEFECT_DETECTED = "DEFECT_DETECTED"
    COLLISION_RISK = "COLLISION_RISK"
    LANE_DEPARTURE_RISK = "LANE_DEPARTURE_RISK"
    OBJECT_APPROACH = "OBJECT_APPROACH"
    OBJECT_CROSSING = "OBJECT_CROSSING"
    SCENE_CHANGE = "SCENE_CHANGE"
    SYSTEM_ERROR = "SYSTEM_ERROR"
    UNKNOWN = "UNKNOWN"


class UnifiedSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


# Deterministic severity rank used by risk scoring (higher = more severe).
SEVERITY_RANK: dict[UnifiedSeverity, float] = {
    UnifiedSeverity.INFO: 0.0,
    UnifiedSeverity.LOW: 0.25,
    UnifiedSeverity.MEDIUM: 0.5,
    UnifiedSeverity.HIGH: 0.75,
    UnifiedSeverity.CRITICAL: 1.0,
    UnifiedSeverity.UNKNOWN: 0.25,
}


class RiskLevel(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class EventPriority(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class UnifiedEventStatus(str, Enum):
    ACTIVE = "ACTIVE"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class RiskFactor(BaseModel):
    """One explainable contribution to a risk score."""

    name: str = Field(min_length=1, max_length=64)
    value: float = Field(ge=0.0, le=1.0)
    weight: float = Field(ge=0.0, le=1.0)
    contribution: float = Field(ge=0.0, le=1.0)
    reason: str = Field(default="", max_length=1024)


class RiskAssessment(BaseModel):
    """One explainable risk assessment: score plus the factors behind it."""

    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    factors: list[RiskFactor] = Field(default_factory=list)
    reason: str = Field(default="", max_length=1024)
    timestamp: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class UnifiedEvent(BaseModel):
    """Canonical, source-preserving view of one domain event."""

    event_id: UUID = Field(default_factory=uuid4)
    source_event_id: str = Field(min_length=1, max_length=128)
    camera_id: str = Field(min_length=1, max_length=128)
    source_domain: EventSourceDomain
    event_type: UnifiedEventType = UnifiedEventType.UNKNOWN
    severity: UnifiedSeverity = UnifiedSeverity.UNKNOWN
    status: UnifiedEventStatus = UnifiedEventStatus.ACTIVE
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    priority: EventPriority = EventPriority.P4
    timestamp: datetime = Field(default_factory=utcnow)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    track_ids: list[int] = Field(default_factory=list)
    object_ids: list[str] = Field(default_factory=list)
    related_event_ids: list[str] = Field(default_factory=list)
    location: str | None = Field(default=None, max_length=256)
    message: str = Field(default="", max_length=1024)
    reason: str = Field(default="", max_length=1024)
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def touch(self, timestamp: datetime) -> None:
        self.last_seen = timestamp
        self.timestamp = timestamp

    def to_websocket(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "source_event_id": self.source_event_id,
            "camera_id": self.camera_id,
            "source_domain": self.source_domain.value,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "priority": self.priority.value,
            "timestamp": self.timestamp.isoformat(),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "track_ids": list(self.track_ids),
            "object_ids": list(self.object_ids),
            "related_event_ids": list(self.related_event_ids),
            "location": self.location,
            "message": self.message,
            "reason": self.reason,
        }


class RiskCluster(BaseModel):
    """One correlated risk cluster: linked unified events on one camera."""

    cluster_id: UUID = Field(default_factory=uuid4)
    camera_id: str = Field(min_length=1, max_length=128)
    event_ids: list[str] = Field(default_factory=list)
    track_ids: list[int] = Field(default_factory=list)
    object_ids: list[str] = Field(default_factory=list)
    source_domains: list[EventSourceDomain] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    event_count: int = Field(default=0, ge=0)
    risk_assessment: RiskAssessment = Field(default_factory=RiskAssessment)
    priority: EventPriority = EventPriority.P4
    status: UnifiedEventStatus = UnifiedEventStatus.ACTIVE
    metadata: dict[str, Any] = Field(default_factory=dict)

    def touch(self, timestamp: datetime) -> None:
        self.last_seen = timestamp

    def to_websocket(self) -> dict[str, Any]:
        return {
            "cluster_id": str(self.cluster_id),
            "camera_id": self.camera_id,
            "event_ids": list(self.event_ids),
            "track_ids": list(self.track_ids),
            "object_ids": list(self.object_ids),
            "source_domains": [d.value for d in self.source_domains],
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "event_count": self.event_count,
            "risk_level": self.risk_assessment.risk_level.value,
            "risk_score": self.risk_assessment.risk_score,
            "priority": self.priority.value,
            "status": self.status.value,
            "factors": [
                {
                    "name": f.name,
                    "value": f.value,
                    "weight": f.weight,
                    "contribution": f.contribution,
                    "reason": f.reason,
                }
                for f in self.risk_assessment.factors
            ],
        }


class RiskIntelligenceResult(BaseModel):
    """Main V09 output: per-camera intelligence snapshot for V10 and UIs."""

    timestamp: datetime = Field(default_factory=utcnow)
    camera_id: str = Field(min_length=1, max_length=128)
    events: list[UnifiedEvent] = Field(default_factory=list)
    clusters: list[RiskCluster] = Field(default_factory=list)
    risk_assessments: list[RiskAssessment] = Field(default_factory=list)
    highest_risk: RiskAssessment = Field(default_factory=RiskAssessment)
    highest_priority: EventPriority = EventPriority.P4
    active_event_count: int = Field(default=0, ge=0)
    active_cluster_count: int = Field(default=0, ge=0)
    metrics: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
