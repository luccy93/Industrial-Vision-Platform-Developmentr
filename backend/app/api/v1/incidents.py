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

from fastapi import APIRouter, Depends, Request
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
