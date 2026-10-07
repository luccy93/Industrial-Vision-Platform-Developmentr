"""Incident schema tests — enums, models, validation, serialization."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.app.incidents.schemas import (
    Actor,
    ActorType,
    EvidenceType,
    IncidentAssignment,
    IncidentCategory,
    IncidentPriority,
    IncidentStatus,
    IncidentTimelineEntry,
    NoteKind,
    ResolutionReason,
    TimelineEventType,
)
from backend.tests.incident_helpers import make_evidence, make_incident


def test_status_lifecycle_values() -> None:
    assert [s.value for s in IncidentStatus] == [
        "OPEN",
        "ACKNOWLEDGED",
        "INVESTIGATING",
        "MITIGATED",
        "RESOLVED",
        "CLOSED",
    ]


def test_category_values() -> None:
    assert {c.value for c in IncidentCategory} == {
        "SAFETY",
        "SECURITY",
        "QUALITY",
        "COLLISION",
        "SPATIAL",
        "OPERATIONAL",
        "SYSTEM",
        "UNKNOWN",
    }


def test_priority_reuses_v09_scale() -> None:
    from backend.app.intelligence.schemas import EventPriority

    assert [p.value for p in IncidentPriority] == [p.value for p in EventPriority]
    assert [p.value for p in IncidentPriority] == ["P0", "P1", "P2", "P3", "P4"]


def test_timeline_event_types() -> None:
    assert {t.value for t in TimelineEventType} == {
        "CREATED",
        "RISK_UPDATED",
        "ACKNOWLEDGED",
        "ASSIGNED",
        "UNASSIGNED",
        "PRIORITY_CHANGED",
        "ESCALATED",
        "INVESTIGATION_STARTED",
        "NOTE_ADDED",
        "MITIGATED",
        "RESOLVED",
        "CLOSED",
        "EVIDENCE_ADDED",
    }


def test_evidence_types() -> None:
    assert {e.value for e in EvidenceType} == {"FRAME", "IMAGE", "VIDEO", "SNAPSHOT", "LINK", "OTHER"}


def test_resolution_reasons() -> None:
    assert {r.value for r in ResolutionReason} == {
        "FALSE_ALARM",
        "HAZARD_REMOVED",
        "OPERATOR_ACTION",
        "AUTOMATIC_CLEAR",
        "QUALITY_REWORKED",
        "OTHER",
    }


def test_actor_defaults_to_system() -> None:
    actor = Actor()
    assert actor.actor_id is None
    assert actor.actor_type is ActorType.SYSTEM
    operator = Actor(actor_id="op-7", actor_type=ActorType.OPERATOR)
    assert operator.actor_id == "op-7"


def test_note_kinds() -> None:
    assert {k.value for k in NoteKind} == {"NOTE", "FINDING", "ACTION", "OBSERVATION"}


def test_incident_defaults() -> None:
    incident = make_incident()
    assert incident.status is IncidentStatus.OPEN
    assert incident.priority.value == "P1"
    assert incident.source == "AUTOMATIC"
    assert incident.assigned_to is None
    assert incident.acknowledged_at is None
    assert incident.resolved_at is None
    assert incident.closed_at is None
    assert incident.metadata == {}


def test_incident_validation() -> None:
    with pytest.raises(ValidationError):
        make_incident(title="")
    with pytest.raises(ValidationError):
        make_incident(camera_id="")
    with pytest.raises(ValidationError):
        make_incident(risk_score=1.5)
    with pytest.raises(ValidationError):
        make_incident(incident_number="")


def test_incident_touch_updates_seen() -> None:
    from backend.tests.incident_helpers import utc

    incident = make_incident()
    incident.touch(utc(90))
    assert incident.last_seen == utc(90)
    assert incident.updated_at == utc(90)


def test_timeline_entry_defaults() -> None:
    from uuid import uuid4

    entry = IncidentTimelineEntry(incident_id=uuid4(), event_type=TimelineEventType.CREATED)
    assert entry.actor.actor_type is ActorType.SYSTEM
    assert entry.message == ""
    assert entry.previous_state is None
    assert entry.new_state is None


def test_evidence_validation() -> None:
    with pytest.raises(ValidationError):
        make_evidence(uri="")
    with pytest.raises(ValidationError):
        make_evidence(camera_id="")
    evidence = make_evidence()
    assert evidence.evidence_type.value == "OTHER"
    assert evidence.checksum is None


def test_assignment_defaults() -> None:
    from uuid import uuid4

    assignment = IncidentAssignment(incident_id=uuid4())
    assert assignment.assignee is None
    assert assignment.previous_assignee is None
    assert assignment.actor.actor_type is ActorType.SYSTEM
