"""Incident domain model — operational records over V09 intelligence.

An ``Incident`` is the operator-facing record of a risk that deserves
attention. Priority reuses the V09 ``EventPriority`` scale verbatim (no
second scale); severity reuses ``UnifiedSeverity``; risk levels reuse V09
``RiskLevel``. Category is V10's own deterministic mapping from source
domains — never inferred from arbitrary strings.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from backend.app.domain.common import utcnow
from backend.app.intelligence.schemas import (
    EventPriority,
    RiskLevel,
    UnifiedSeverity,
)

IncidentPriority = EventPriority


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    MITIGATED = "MITIGATED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class IncidentCategory(str, Enum):
    SAFETY = "SAFETY"
    SECURITY = "SECURITY"
    QUALITY = "QUALITY"
    COLLISION = "COLLISION"
    SPATIAL = "SPATIAL"
    OPERATIONAL = "OPERATIONAL"
    SYSTEM = "SYSTEM"
    UNKNOWN = "UNKNOWN"


class TimelineEventType(str, Enum):
    CREATED = "CREATED"
    RISK_UPDATED = "RISK_UPDATED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    ASSIGNED = "ASSIGNED"
    UNASSIGNED = "UNASSIGNED"
    PRIORITY_CHANGED = "PRIORITY_CHANGED"
    ESCALATED = "ESCALATED"
    INVESTIGATION_STARTED = "INVESTIGATION_STARTED"
    NOTE_ADDED = "NOTE_ADDED"
    MITIGATED = "MITIGATED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    EVIDENCE_ADDED = "EVIDENCE_ADDED"


class EvidenceType(str, Enum):
    FRAME = "FRAME"
    IMAGE = "IMAGE"
    VIDEO = "VIDEO"
    SNAPSHOT = "SNAPSHOT"
    LINK = "LINK"
    OTHER = "OTHER"


class ResolutionReason(str, Enum):
    FALSE_ALARM = "FALSE_ALARM"
    HAZARD_REMOVED = "HAZARD_REMOVED"
    OPERATOR_ACTION = "OPERATOR_ACTION"
    AUTOMATIC_CLEAR = "AUTOMATIC_CLEAR"
    QUALITY_REWORKED = "QUALITY_REWORKED"
    OTHER = "OTHER"


class ActorType(str, Enum):
    SYSTEM = "SYSTEM"
    OPERATOR = "OPERATOR"


class NoteKind(str, Enum):
    NOTE = "NOTE"
    FINDING = "FINDING"
    ACTION = "ACTION"
    OBSERVATION = "OBSERVATION"


class Actor(BaseModel):
    """Who performed an operation. Until V16 there is no authentication:
    operator identities are opaque, unvalidated identifier strings."""

    actor_id: str | None = Field(default=None, max_length=256)
    actor_type: ActorType = ActorType.SYSTEM


class Incident(BaseModel):
    """One operational incident record."""

    id: UUID = Field(default_factory=uuid4)
    incident_number: str = Field(min_length=1, max_length=32)
    camera_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=4096)

    source_cluster_id: str | None = Field(default=None, max_length=128)
    primary_event_id: str | None = Field(default=None, max_length=128)

    severity: UnifiedSeverity = UnifiedSeverity.UNKNOWN
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    priority: IncidentPriority = IncidentPriority.P4

    status: IncidentStatus = IncidentStatus.OPEN
    category: IncidentCategory = IncidentCategory.UNKNOWN

    source: str = Field(default="AUTOMATIC", max_length=16)

    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)

    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    closed_at: datetime | None = None

    assigned_to: str | None = Field(default=None, max_length=256)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def touch(self, timestamp: datetime) -> None:
        self.last_seen = timestamp
        self.updated_at = timestamp


class IncidentTimelineEntry(BaseModel):
    """One immutable timeline record. History is append-only."""

    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    event_type: TimelineEventType
    actor: Actor = Field(default_factory=Actor)
    message: str = Field(default="", max_length=4096)
    previous_state: str | None = Field(default=None, max_length=64)
    new_state: str | None = Field(default=None, max_length=64)
    timestamp: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentEvidence(BaseModel):
    """Evidence metadata only. V10 stores no object bytes and invents no files."""

    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    camera_id: str = Field(min_length=1, max_length=128)
    evidence_type: EvidenceType = EvidenceType.OTHER
    uri: str = Field(min_length=1, max_length=2048)
    timestamp: datetime = Field(default_factory=utcnow)
    frame_id: str | None = Field(default=None, max_length=128)
    description: str = Field(default="", max_length=4096)
    checksum: str | None = Field(default=None, max_length=256)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class IncidentAssignment(BaseModel):
    """One assignment audit row. The current assignee also lives on the incident."""

    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    assignee: str | None = Field(default=None, max_length=256)
    previous_assignee: str | None = Field(default=None, max_length=256)
    actor: Actor = Field(default_factory=Actor)
    timestamp: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)
