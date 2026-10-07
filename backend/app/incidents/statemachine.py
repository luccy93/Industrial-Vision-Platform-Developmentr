"""Incident lifecycle state machine — explicit, validated, documented.

Allowed transitions::

    OPEN
     ├── ACKNOWLEDGED
     ├── INVESTIGATING
     └── RESOLVED

    ACKNOWLEDGED
     ├── INVESTIGATING
     ├── MITIGATED
     └── RESOLVED

    INVESTIGATING
     ├── MITIGATED
     └── RESOLVED

    MITIGATED
     └── RESOLVED

    RESOLVED
     └── CLOSED

    CLOSED: terminal (no outgoing transitions).

There is intentionally no REOPENED state: a new V09 cluster after closure
creates a new incident, and incidents are never silently reopened.
"""

from __future__ import annotations

from backend.app.incidents.schemas import IncidentCategory, IncidentStatus
from backend.app.intelligence.schemas import EventSourceDomain

TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset(
        {IncidentStatus.ACKNOWLEDGED, IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED}
    ),
    IncidentStatus.ACKNOWLEDGED: frozenset(
        {IncidentStatus.INVESTIGATING, IncidentStatus.MITIGATED, IncidentStatus.RESOLVED}
    ),
    IncidentStatus.INVESTIGATING: frozenset({IncidentStatus.MITIGATED, IncidentStatus.RESOLVED}),
    IncidentStatus.MITIGATED: frozenset({IncidentStatus.RESOLVED}),
    IncidentStatus.RESOLVED: frozenset({IncidentStatus.CLOSED}),
    IncidentStatus.CLOSED: frozenset(),
}

# Operator actions exposed per status (single source of truth for API + UI).
# Assignment, notes, evidence, and escalation are available from any
# non-terminal state; lifecycle moves follow TRANSITIONS.
STATUS_ACTIONS: dict[IncidentStatus, tuple[str, ...]] = {
    IncidentStatus.OPEN: ("acknowledge", "investigate", "assign", "note", "resolve", "evidence"),
    IncidentStatus.ACKNOWLEDGED: (
        "investigate",
        "mitigate",
        "assign",
        "unassign",
        "escalate",
        "note",
        "resolve",
        "evidence",
    ),
    IncidentStatus.INVESTIGATING: (
        "mitigate",
        "assign",
        "unassign",
        "escalate",
        "note",
        "resolve",
        "evidence",
    ),
    IncidentStatus.MITIGATED: ("assign", "unassign", "escalate", "note", "resolve", "evidence"),
    IncidentStatus.RESOLVED: ("close", "note", "evidence"),
    IncidentStatus.CLOSED: (),
}


class InvalidTransitionError(ValueError):
    """Raised when a lifecycle move is not in TRANSITIONS."""

    def __init__(self, current: IncidentStatus, attempted: IncidentStatus) -> None:
        super().__init__(f"invalid incident transition: {current.value} -> {attempted.value}")
        self.current = current
        self.attempted = attempted


def validate_transition(current: IncidentStatus, attempted: IncidentStatus) -> None:
    """Raise InvalidTransitionError unless the move is explicitly allowed."""
    if attempted not in TRANSITIONS[current]:
        raise InvalidTransitionError(current, attempted)


def allowed_actions(status: IncidentStatus) -> tuple[str, ...]:
    """Operator actions valid from a status (drives API + UI, never bypassed)."""
    return STATUS_ACTIONS[status]


def category_for_domains(domains: list[EventSourceDomain]) -> IncidentCategory:
    """Deterministic category from V09 source domains (no string inference).

    Precedence is fixed: AUTONOMOUS → COLLISION, QUALITY → QUALITY,
    SPATIAL → SPATIAL, SAFETY → SAFETY, otherwise OPERATIONAL. SECURITY and
    SYSTEM are reserved for future explicit sources and are never inferred.
    """
    ordered = list(domains)
    if EventSourceDomain.AUTONOMOUS in ordered:
        return IncidentCategory.COLLISION
    if EventSourceDomain.QUALITY in ordered:
        return IncidentCategory.QUALITY
    if EventSourceDomain.SPATIAL in ordered:
        return IncidentCategory.SPATIAL
    if EventSourceDomain.SAFETY in ordered:
        return IncidentCategory.SAFETY
    return IncidentCategory.OPERATIONAL
