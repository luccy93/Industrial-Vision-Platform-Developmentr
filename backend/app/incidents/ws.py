"""Incident WebSocket message builders.

Seven typed messages join the existing V01–V09 channels, all derived from
the manager's change feed (never full timeline/evidence payloads):

* ``incident_created`` / ``incident_updated`` — upserts with summary fields.
* ``incident_status_changed`` — lifecycle moves with old/new status.
* ``incident_assigned`` — assignment changes with previous/new assignee.
* ``incident_resolved`` / ``incident_closed`` — terminal transitions.
* ``incident_evidence_added`` — evidence metadata reference.

Every builder takes ``(incident, change)`` where ``change`` is one feed
entry, so the socket loop dispatches uniformly.
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


def incident_created_message(incident: Incident, change: dict[str, Any]) -> dict[str, Any]:
    return {"type": "incident_created", **_summary(incident)}


def incident_updated_message(incident: Incident, change: dict[str, Any]) -> dict[str, Any]:
    return {"type": "incident_updated", **_summary(incident)}


def incident_status_changed_message(incident: Incident, change: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "incident_status_changed",
        "previous_status": change.get("previous_status"),
        "actor_id": change.get("actor_id"),
        **_summary(incident),
    }


def incident_assigned_message(incident: Incident, change: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "incident_assigned",
        "previous_assignee": change.get("previous_assignee"),
        "new_assignee": incident.assigned_to,
        "actor_id": change.get("actor_id"),
        **_summary(incident),
    }


def incident_resolved_message(incident: Incident, change: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "incident_resolved",
        "resolution_reason": change.get("resolution_reason"),
        **_summary(incident),
    }


def incident_closed_message(incident: Incident, change: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "incident_closed",
        "closure_reason": change.get("closure_reason"),
        **_summary(incident),
    }


def incident_evidence_added_message(incident: Incident, change: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "incident_evidence_added",
        "evidence_id": change.get("evidence_id"),
        "evidence_type": change.get("evidence_type"),
        **_summary(incident),
    }


BUILDERS = {
    "created": incident_created_message,
    "updated": incident_updated_message,
    "status_changed": incident_status_changed_message,
    "assigned": incident_assigned_message,
    "resolved": incident_resolved_message,
    "closed": incident_closed_message,
    "evidence_added": incident_evidence_added_message,
}
