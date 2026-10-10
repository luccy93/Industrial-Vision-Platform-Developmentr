"""Alerting domain model — rules, notifications, deliveries (V15).

Severity reuses V09 ``UnifiedSeverity`` rank semantics verbatim; priority
reuses ``EventPriority`` (no parallel taxonomies). Incident transitions
reuse V10 vocabulary (statuses, timeline event types, resolution reasons).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

from backend.app.domain.common import utcnow

# Locked V09 domains that may source alerts. TRACKING/PERCEPTION/SYSTEM
# are reserved and must never match (enforced in validation + matching).
ALERTABLE_DOMAINS = frozenset({"SAFETY", "SPATIAL", "QUALITY", "AUTONOMOUS", "INTELLIGENCE", "INCIDENT"})

# Incident lifecycle states a rule may subscribe to (entered-state match).
ALERTABLE_INCIDENT_STATUSES = frozenset(
    {"OPEN", "ACKNOWLEDGED", "INVESTIGATING", "MITIGATED", "RESOLVED", "CLOSED"}
)


# Incident lifecycle transition types a rule may subscribe to. These are
# the authoritative mutation names (mirroring V10 timeline vocabulary);
# rejected/no-op actions never produce them.
ALERTABLE_TRANSITION_TYPES = frozenset(
    {
        "CREATED",
        "ACKNOWLEDGED",
        "ASSIGNED",
        "UNASSIGNED",
        "ESCALATED",
        "INVESTIGATION_STARTED",
        "MITIGATED",
        "RESOLVED",
        "CLOSED",
        "PRIORITY_CHANGED",
    }
)


def _alertable_event_types() -> frozenset[str]:
    from backend.app.intelligence.schemas import UnifiedEventType

    return frozenset(t.value for t in UnifiedEventType) | ALERTABLE_TRANSITION_TYPES


def validate_rule_filters(
    *,
    domains: list[str] | None,
    event_types: list[str] | None,
    incident_statuses: list[str] | None,
) -> None:
    """Reject unknown filter values at rule creation/update (422).

    Unknown domains or event types are never interpreted as wildcards;
    empty lists deliberately mean "match all" (documented). Raises
    ``ValueError`` with an actionable message.
    """
    for domain in domains or []:
        if str(domain).upper() not in ALERTABLE_DOMAINS:
            raise ValueError(f"unknown alert domain: {domain!r} (allowed: {sorted(ALERTABLE_DOMAINS)})")
    allowed_types = _alertable_event_types()
    for event_type in event_types or []:
        if str(event_type).upper() not in allowed_types:
            raise ValueError(f"unknown alert event type: {event_type!r}")
    for status in incident_statuses or []:
        if str(status).upper() not in ALERTABLE_INCIDENT_STATUSES:
            raise ValueError(
                f"unknown incident status: {status!r} (allowed: {sorted(ALERTABLE_INCIDENT_STATUSES)})"
            )


class AlertChannel(str, Enum):
    IN_APP = "in_app"
    EMAIL = "email"
    WEBHOOK = "webhook"


class EvaluationOutcome(str, Enum):
    NOTIFIED = "NOTIFIED"
    SUPPRESSED_COOLDOWN = "SUPPRESSED_COOLDOWN"


class SuppressionScope(str, Enum):
    RULE = "RULE"
    RULE_CAMERA = "RULE_CAMERA"


class DeliveryStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"


class AlertRule(BaseModel):
    """A persisted, configurable alert rule."""

    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    enabled: bool = True
    domains: list[str] = Field(default_factory=list)
    event_types: list[str] = Field(default_factory=list)
    min_severity: str | None = None
    min_priority: str | None = None
    camera_ids: list[str] = Field(default_factory=list)
    incident_statuses: list[str] = Field(default_factory=list)
    channels: list[AlertChannel] = Field(min_length=1)
    cooldown_seconds: int = Field(default=0, ge=0, le=86400)
    suppression_scope: SuppressionScope = SuppressionScope.RULE
    trigger_count: int = 0
    suppressed_count: int = 0
    last_triggered_at: datetime | None = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class RuleCreate(BaseModel):
    """API request: create a rule. Empty filter lists match all (documented)."""

    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    enabled: bool = True
    domains: list[str] = Field(default_factory=list)
    event_types: list[str] = Field(default_factory=list)
    min_severity: str | None = None
    min_priority: str | None = None
    camera_ids: list[str] = Field(default_factory=list)
    incident_statuses: list[str] = Field(default_factory=list)
    channels: list[AlertChannel] = Field(min_length=1)
    cooldown_seconds: int = Field(default=0, ge=0, le=86400)
    suppression_scope: SuppressionScope = SuppressionScope.RULE

    _upper_domains = field_validator("domains", mode="before")(
        lambda values: [str(v).strip().upper() for v in (values or [])]
    )
    _upper_types = field_validator("event_types", mode="before")(
        lambda values: [str(v).strip().upper() for v in (values or [])]
    )
    _upper_statuses = field_validator("incident_statuses", mode="before")(
        lambda values: [str(v).strip().upper() for v in (values or [])]
    )

    @model_validator(mode="after")
    def _validate_filters(self) -> RuleCreate:
        validate_rule_filters(
            domains=self.domains,
            event_types=self.event_types,
            incident_statuses=self.incident_statuses,
        )
        return self


class RuleUpdate(BaseModel):
    """API request: partial rule update. All fields optional."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1024)
    enabled: bool | None = None
    domains: list[str] | None = None
    event_types: list[str] | None = None
    min_severity: str | None = None
    min_priority: str | None = None
    camera_ids: list[str] | None = None
    incident_statuses: list[str] | None = None
    channels: list[AlertChannel] | None = None
    cooldown_seconds: int | None = Field(default=None, ge=0, le=86400)
    suppression_scope: SuppressionScope | None = None


class Notification(BaseModel):
    """A durable, system-wide notification instance (no per-user state)."""

    id: UUID = Field(default_factory=uuid4)
    rule_id: UUID
    source_event_id: str = Field(min_length=1, max_length=256)
    source_domain: str = ""
    event_type: str = ""
    camera_id: str | None = None
    incident_id: str | None = None
    title: str = ""
    message: str = ""
    severity: str = "UNKNOWN"
    priority: str = "P4"
    context: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class DeliveryAttempt(BaseModel):
    """One channel's delivery state for a notification (independently observable)."""

    id: UUID = Field(default_factory=uuid4)
    notification_id: UUID
    channel: AlertChannel
    destination: str = ""
    status: DeliveryStatus = DeliveryStatus.PENDING
    attempts: int = 0
    next_retry_at: datetime | None = None
    last_attempt_at: datetime | None = None
    delivered_at: datetime | None = None
    last_error: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


class TransitionRecord(BaseModel):
    """A committed incident mutation eligible for alert evaluation."""

    id: UUID = Field(default_factory=uuid4)
    incident_id: str
    transition_type: str
    previous_state: str | None = None
    new_state: str | None = None
    actor_id: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvaluationRecord(BaseModel):
    """Durable evaluation outcome: notified or suppressed (never both)."""

    id: UUID = Field(default_factory=uuid4)
    rule_id: UUID
    source_event_id: str
    outcome: EvaluationOutcome
    suppression_reason: str | None = None
    suppression_scope: SuppressionScope | None = None
    next_eligible_at: datetime | None = None
    evaluated_at: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "ALERTABLE_DOMAINS",
    "ALERTABLE_INCIDENT_STATUSES",
    "AlertChannel",
    "AlertRule",
    "DeliveryAttempt",
    "DeliveryStatus",
    "EvaluationOutcome",
    "EvaluationRecord",
    "Notification",
    "RuleCreate",
    "RuleUpdate",
    "SuppressionScope",
    "TransitionRecord",
    "validate_rule_filters",
]
