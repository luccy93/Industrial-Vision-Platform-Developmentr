"""Incident operations API — operator-facing incident management.

All runtime incident state lives in PostgreSQL via ``IncidentRepository``.
Every lifecycle move is validated against the state machine (invalid moves
return 409); every manual change is recorded in the timeline. There is no
authentication yet (V16): actors are opaque identifier strings.

Commit 01 ships the request/response contracts and dependencies; the routes
land with the runtime workflow in Commit 02.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from backend.app.incidents.schemas import (
    ActorType,
    EvidenceType,
    IncidentCategory,
    IncidentPriority,
    NoteKind,
    ResolutionReason,
)
from backend.app.infrastructure.db import get_db, get_session_factory

logger = logging.getLogger("industrial-vision.api")

router = APIRouter(tags=["incidents"])


def get_incident_repository(request: Request, session: Session = Depends(get_db)) -> Any:
    from backend.app.incidents.repository import IncidentRepository

    factory = getattr(request.app.state, "session_factory", None)
    if factory is None:
        factory = get_session_factory(str(session.get_bind().url))  # type: ignore[union-attr]
    return IncidentRepository(factory)


def get_incident_manager(request: Request) -> Any:

    manager = getattr(request.app.state, "incident_manager", None)
    return manager


class IncidentCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=4096)
    category: IncidentCategory = IncidentCategory.UNKNOWN
    priority: IncidentPriority = IncidentPriority.P4
    camera_id: str | None = Field(default=None, min_length=1, max_length=128)
    source_cluster_id: str | None = Field(default=None, min_length=1, max_length=128)
    source_event_id: str | None = Field(default=None, min_length=1, max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)

    _normalize_enums = field_validator("category", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )
    _normalize_priority = field_validator("priority", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )


class IncidentPatchRequest(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=4096)
    metadata: dict[str, Any] | None = None


class AcknowledgeRequest(BaseModel):
    actor_id: str | None = Field(default=None, max_length=256)
    reason: str = Field(default="", max_length=4096)


class AssignRequest(BaseModel):
    assignee: str = Field(min_length=1, max_length=256)
    actor_id: str | None = Field(default=None, max_length=256)


class UnassignRequest(BaseModel):
    actor_id: str | None = Field(default=None, max_length=256)


class EscalateRequest(BaseModel):
    priority: IncidentPriority
    reason: str = Field(min_length=1, max_length=4096)
    actor_id: str | None = Field(default=None, max_length=256)

    _normalize_priority = field_validator("priority", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )


class InvestigateRequest(BaseModel):
    actor_id: str | None = Field(default=None, max_length=256)
    reason: str = Field(default="", max_length=4096)


class NoteRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4096)
    kind: NoteKind = NoteKind.NOTE
    actor_id: str | None = Field(default=None, max_length=256)

    _normalize_kind = field_validator("kind", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )


class MitigateRequest(BaseModel):
    actor_id: str | None = Field(default=None, max_length=256)
    reason: str = Field(min_length=1, max_length=4096)


class ResolveRequest(BaseModel):
    reason: ResolutionReason
    actor_id: str | None = Field(default=None, max_length=256)
    detail: str = Field(default="", max_length=4096)

    _normalize_reason = field_validator("reason", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )


class CloseRequest(BaseModel):
    closure_reason: str = Field(min_length=1, max_length=4096)
    actor_id: str | None = Field(default=None, max_length=256)


class EvidenceCreateRequest(BaseModel):
    evidence_type: EvidenceType = EvidenceType.OTHER
    uri: str = Field(min_length=1, max_length=2048)
    description: str = Field(default="", max_length=4096)
    frame_id: str | None = Field(default=None, max_length=128)
    checksum: str | None = Field(default=None, max_length=256)
    timestamp: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    _normalize_type = field_validator("evidence_type", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )


class IncidentListQuery(BaseModel):
    status: list[str] = Field(default_factory=list)
    priority: list[str] = Field(default_factory=list)
    severity: list[str] = Field(default_factory=list)
    category: list[str] = Field(default_factory=list)
    camera_id: str | None = None
    assigned_to: str | None = None
    risk_level: list[str] = Field(default_factory=list)
    created_from: datetime | None = None
    created_to: datetime | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


def _actor_type(actor_id: str | None) -> ActorType:
    return ActorType.OPERATOR if actor_id else ActorType.SYSTEM


__all__ = [
    "AcknowledgeRequest",
    "AssignRequest",
    "CloseRequest",
    "EscalateRequest",
    "EvidenceCreateRequest",
    "IncidentCreateRequest",
    "IncidentListQuery",
    "IncidentPatchRequest",
    "InvestigateRequest",
    "MitigateRequest",
    "NoteRequest",
    "ResolveRequest",
    "UnassignRequest",
    "get_incident_manager",
    "get_incident_repository",
    "router",
]


def _require_manager(manager: Any) -> Any:
    if manager is None:
        raise HTTPException(status_code=503, detail="incident manager unavailable")
    return manager


def _require_camera(camera_id: str | None, request: Request) -> None:
    if camera_id is None:
        return
    from backend.app.ingestion.repository import CameraRepository

    factory = getattr(request.app.state, "session_factory", None)
    if factory is None:
        return
    if CameraRepository(factory).get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")


def _parse_list(values: list[str]) -> list[str]:
    items: list[str] = []
    for value in values:
        items.extend(part.strip() for part in str(value).split(",") if part.strip())
    return items


def _incident_error(exc: Exception) -> HTTPException:
    from backend.app.incidents.manager import InvalidIncidentStateError
    from backend.app.incidents.repository import IncidentNotFoundError
    from backend.app.incidents.statemachine import InvalidTransitionError

    if isinstance(exc, IncidentNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (InvalidTransitionError, InvalidIncidentStateError)):
        detail: dict[str, Any] = {"code": "invalid_state", "message": str(exc)}
        if isinstance(exc, InvalidTransitionError):
            detail = {
                "code": "invalid_transition",
                "message": str(exc),
                "current_status": exc.current.value,
                "attempted_status": exc.attempted.value,
            }
        return HTTPException(status_code=409, detail=detail)
    if isinstance(exc, ValueError):
        return HTTPException(status_code=422, detail=str(exc))
    raise exc


@router.get("/api/v1/incidents")
def list_incidents(
    status: list[str] = Query(default=[]),
    priority: list[str] = Query(default=[]),
    severity: list[str] = Query(default=[]),
    category: list[str] = Query(default=[]),
    camera_id: str | None = Query(default=None),
    assigned_to: str | None = Query(default=None),
    risk_level: list[str] = Query(default=[]),
    created_from: datetime | None = Query(default=None),
    created_to: datetime | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    manager: Any = Depends(get_incident_manager),
) -> dict[str, Any]:
    manager = _require_manager(manager)
    try:
        incidents, total = manager.repository.list_incidents(
            status=_parse_list(status),
            priority=_parse_list(priority),
            severity=_parse_list(severity),
            category=_parse_list(category),
            camera_id=camera_id,
            assigned_to=assigned_to,
            risk_level=_parse_list(risk_level),
            created_from=created_from,
            created_to=created_to,
            page=page,
            page_size=page_size,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {
        "incidents": [manager.get_detail(str(i.id))["incident"] for i in incidents],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/api/v1/incidents/{incident_id}")
def get_incident(incident_id: str, manager: Any = Depends(get_incident_manager)) -> dict[str, Any]:
    manager = _require_manager(manager)
    detail = manager.get_detail(incident_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return detail


@router.post("/api/v1/incidents", status_code=201)
def create_incident(
    payload: IncidentCreateRequest,
    request: Request,
    manager: Any = Depends(get_incident_manager),
) -> dict[str, Any]:
    manager = _require_manager(manager)
    _require_camera(payload.camera_id, request)
    try:
        incident = manager.create_manual(
            title=payload.title,
            category=payload.category,
            priority=payload.priority,
            description=payload.description,
            camera_id=payload.camera_id,
            source_cluster_id=payload.source_cluster_id,
            source_event_id=payload.source_event_id,
            metadata=payload.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    detail = manager.get_detail(str(incident.id))
    assert detail is not None
    return detail


@router.patch("/api/v1/incidents/{incident_id}")
def patch_incident(
    incident_id: str,
    payload: IncidentPatchRequest,
    manager: Any = Depends(get_incident_manager),
) -> dict[str, Any]:
    manager = _require_manager(manager)
    try:
        manager.patch(
            incident_id,
            title=payload.title,
            description=payload.description,
            metadata=payload.metadata,
        )
    except Exception as exc:
        raise _incident_error(exc)
    detail = manager.get_detail(incident_id)
    assert detail is not None
    return detail


def _action(incident_id: str, manager: Any, call: Any) -> dict[str, Any]:
    manager = _require_manager(manager)
    try:
        call()
    except Exception as exc:
        raise _incident_error(exc)
    detail = manager.get_detail(incident_id)
    assert detail is not None
    return detail


@router.post("/api/v1/incidents/{incident_id}/acknowledge")
def acknowledge_incident(
    incident_id: str, payload: AcknowledgeRequest, manager: Any = Depends(get_incident_manager)
) -> dict[str, Any]:
    return _action(
        incident_id, manager, lambda: manager.acknowledge(incident_id, payload.actor_id, payload.reason)
    )


@router.post("/api/v1/incidents/{incident_id}/assign")
def assign_incident(
    incident_id: str, payload: AssignRequest, manager: Any = Depends(get_incident_manager)
) -> dict[str, Any]:
    return _action(
        incident_id, manager, lambda: manager.assign(incident_id, payload.assignee, payload.actor_id)
    )


@router.post("/api/v1/incidents/{incident_id}/unassign")
def unassign_incident(
    incident_id: str, payload: UnassignRequest, manager: Any = Depends(get_incident_manager)
) -> dict[str, Any]:
    return _action(incident_id, manager, lambda: manager.unassign(incident_id, payload.actor_id))


@router.post("/api/v1/incidents/{incident_id}/escalate")
def escalate_incident(
    incident_id: str, payload: EscalateRequest, manager: Any = Depends(get_incident_manager)
) -> dict[str, Any]:
    return _action(
        incident_id,
        manager,
        lambda: manager.escalate(incident_id, payload.priority, payload.reason, payload.actor_id),
    )


@router.post("/api/v1/incidents/{incident_id}/investigate")
def investigate_incident(
    incident_id: str, payload: InvestigateRequest, manager: Any = Depends(get_incident_manager)
) -> dict[str, Any]:
    return _action(
        incident_id, manager, lambda: manager.investigate(incident_id, payload.actor_id, payload.reason)
    )


@router.post("/api/v1/incidents/{incident_id}/notes")
def add_incident_note(
    incident_id: str, payload: NoteRequest, manager: Any = Depends(get_incident_manager)
) -> dict[str, Any]:
    return _action(
        incident_id,
        manager,
        lambda: manager.add_note(incident_id, payload.message, payload.kind, payload.actor_id),
    )


@router.post("/api/v1/incidents/{incident_id}/mitigate")
def mitigate_incident(
    incident_id: str, payload: MitigateRequest, manager: Any = Depends(get_incident_manager)
) -> dict[str, Any]:
    return _action(
        incident_id, manager, lambda: manager.mitigate(incident_id, payload.actor_id, payload.reason)
    )


@router.post("/api/v1/incidents/{incident_id}/resolve")
def resolve_incident(
    incident_id: str, payload: ResolveRequest, manager: Any = Depends(get_incident_manager)
) -> dict[str, Any]:
    return _action(
        incident_id,
        manager,
        lambda: manager.resolve(incident_id, payload.reason, payload.actor_id, payload.detail),
    )


@router.post("/api/v1/incidents/{incident_id}/close")
def close_incident(
    incident_id: str, payload: CloseRequest, manager: Any = Depends(get_incident_manager)
) -> dict[str, Any]:
    return _action(
        incident_id,
        manager,
        lambda: manager.close(incident_id, payload.closure_reason, payload.actor_id),
    )


@router.get("/api/v1/incidents/{incident_id}/evidence")
def list_incident_evidence(incident_id: str, manager: Any = Depends(get_incident_manager)) -> dict[str, Any]:
    manager = _require_manager(manager)
    try:
        items = manager.repository.list_evidence(incident_id)
    except Exception as exc:
        raise _incident_error(exc)
    # Unknown incidents yield an empty list only when the incident exists;
    # missing incidents are 404 so callers can distinguish the two.
    if manager.repository.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return {
        "incident_id": incident_id,
        "count": len(items),
        "evidence": [
            {
                "id": str(e.id),
                "camera_id": e.camera_id,
                "evidence_type": e.evidence_type.value,
                "uri": e.uri,
                "timestamp": e.timestamp.isoformat(),
                "frame_id": e.frame_id,
                "description": e.description,
                "checksum": e.checksum,
                "created_at": e.created_at.isoformat(),
            }
            for e in items
        ],
    }


@router.post("/api/v1/incidents/{incident_id}/evidence", status_code=201)
def add_incident_evidence(
    incident_id: str, payload: EvidenceCreateRequest, manager: Any = Depends(get_incident_manager)
) -> dict[str, Any]:
    manager = _require_manager(manager)
    if manager.repository.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="incident not found")
    try:
        evidence = manager.add_evidence(
            incident_id,
            payload.evidence_type,
            payload.uri,
            description=payload.description,
            frame_id=payload.frame_id,
            checksum=payload.checksum,
            metadata=payload.metadata,
        )
    except Exception as exc:
        raise _incident_error(exc)
    return {
        "id": str(evidence.id),
        "camera_id": evidence.camera_id,
        "evidence_type": evidence.evidence_type.value,
        "uri": evidence.uri,
        "timestamp": evidence.timestamp.isoformat(),
        "frame_id": evidence.frame_id,
        "description": evidence.description,
        "checksum": evidence.checksum,
        "created_at": evidence.created_at.isoformat(),
    }


@router.delete("/api/v1/incidents/{incident_id}/evidence/{evidence_id}")
def delete_incident_evidence(
    incident_id: str, evidence_id: str, manager: Any = Depends(get_incident_manager)
) -> dict[str, Any]:
    manager = _require_manager(manager)
    if manager.repository.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="incident not found")
    try:
        manager.delete_evidence(incident_id, evidence_id)
    except Exception as exc:
        raise _incident_error(exc)
    return {"incident_id": incident_id, "evidence_id": evidence_id, "deleted": True}
