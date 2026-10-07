"""Incident WebSocket message builders.

Seven typed messages join the existing V01–V09 channels, all derived from
the manager's change feed (never full timeline/evidence payloads):

* ``incident_created`` / ``incident_updated`` — upserts with summary fields.
* ``incident_status_changed`` — lifecycle moves with old/new status.
* ``incident_assigned`` — assignment changes with previous/new assignee.
* ``incident_resolved`` / ``incident_closed`` — terminal transitions.
* ``incident_evidence_added`` — evidence metadata reference.
"""

from __future__ import annotations

from typing import Any

from backend.app.incidents.schemas import Incident


def _summary(incident: Incident) -> dict[str, Any]:
    return {
        "incident_id": str(incident.id),
        "incident_number": incident.incident_number,
        "camera_id": incident.camera_id,
        "title": incident.title,
        "status": incident.status.value,
        "priority": incident.priority.value,
        "severity": incident.severity.value,
        "risk_level": incident.risk_level.value,
        "risk_score": incident.risk_score,
        "category": incident.category.value,
        "assigned_to": incident.assigned_to,
        "timestamp": incident.updated_at.isoformat(),
    }


def incident_created_message(incident: Incident) -> dict[str, Any]:
    return {"type": "incident_created", **_summary(incident)}


def incident_updated_message(incident: Incident) -> dict[str, Any]:
    return {"type": "incident_updated", **_summary(incident)}


def incident_status_changed_message(
    incident: Incident, previous_status: str, actor_id: str | None
) -> dict[str, Any]:
    return {
        "type": "incident_status_changed",
        "previous_status": previous_status,
        "actor_id": actor_id,
        **_summary(incident),
    }


def incident_assigned_message(
    incident: Incident, previous_assignee: str | None, actor_id: str | None
) -> dict[str, Any]:
    return {
        "type": "incident_assigned",
        "previous_assignee": previous_assignee,
        "new_assignee": incident.assigned_to,
        "actor_id": actor_id,
        **_summary(incident),
    }


def incident_resolved_message(incident: Incident, reason: str) -> dict[str, Any]:
    return {"type": "incident_resolved", "resolution_reason": reason, **_summary(incident)}


def incident_closed_message(incident: Incident, closure_reason: str) -> dict[str, Any]:
    return {"type": "incident_closed", "closure_reason": closure_reason, **_summary(incident)}


def incident_evidence_added_message(
    incident: Incident, evidence_id: str, evidence_type: str
) -> dict[str, Any]:
    return {
        "type": "incident_evidence_added",
        "evidence_id": evidence_id,
        "evidence_type": evidence_type,
        **_summary(incident),
    }
