"""Safety domain model — reusable event contracts for V05 and later volumes.

Confidence semantics: ``confidence`` is a deterministic *rule confidence /
strength score* in [0, 1] derived from geometry, persistence, and detection
confidence. It is NOT a statistically calibrated probability.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from backend.app.domain.common import utcnow


class SafetyEventType(str, Enum):
    POSSIBLE_FALL = "POSSIBLE_FALL"
    CROWD_WARNING = "CROWD_WARNING"
    CROWD_CRITICAL = "CROWD_CRITICAL"
    PERSON_VEHICLE_PROXIMITY = "PERSON_VEHICLE_PROXIMITY"
    PROLONGED_STATIONARY = "PROLONGED_STATIONARY"


class SafetySeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SafetyEventStatus(str, Enum):
    ACTIVE = "ACTIVE"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class SafetyEvent(BaseModel):
    """One continuing safety condition (not one per frame)."""

    event_id: UUID = Field(default_factory=uuid4)
    camera_id: str = Field(min_length=1, max_length=128)
    track_ids: list[int] = Field(default_factory=list)
    event_type: SafetyEventType
    severity: SafetySeverity = SafetySeverity.INFO
    status: SafetyEventStatus = SafetyEventStatus.ACTIVE
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=utcnow)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    duration_ms: float = Field(default=0.0, ge=0.0)
    message: str = Field(default="", max_length=1024)
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def touch(self, timestamp: datetime) -> None:
        self.last_seen = timestamp
        self.timestamp = timestamp
        self.duration_ms = max(0.0, (timestamp - self.first_seen).total_seconds() * 1000.0)

    def to_websocket(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "track_ids": list(self.track_ids),
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_ms": self.duration_ms,
            "message": self.message,
        }


class SafetyAnalysisResult(BaseModel):
    """Outcome of one engine pass over a camera's tracked objects."""

    camera_id: str = Field(min_length=1, max_length=128)
    timestamp: datetime = Field(default_factory=utcnow)
    active_events: list[SafetyEvent] = Field(default_factory=list)
    new_events: list[SafetyEvent] = Field(default_factory=list)
    resolved_events: list[SafetyEvent] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
