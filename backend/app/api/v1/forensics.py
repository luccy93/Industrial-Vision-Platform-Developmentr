"""V34 forensic investigation API.

Every route requires authentication (``read``). Case mutations require
``forensic_case_write`` (ADMIN/OPERATOR), read-only verification requires
``forensic_verify`` (ADMIN/OPERATOR), resolution/closure/reopening requires the
dedicated ``forensic_case_close`` capability (ADMIN), and export generation,
download, and verification require the dedicated ``forensic_export``
capability (ADMIN). Responses are sanitized and never expose absolute paths or
protected evidence bytes.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.app.auth.dependencies import (
    Principal,
    check_capability,
    require_capability_dep,
    require_read,
)
from backend.app.forensics.constants import CLOSE_STATUSES, CaseStatus
from backend.app.forensics.errors import (
    CaseVersionConflictError,
    CorrelationError,
    EvidenceReferenceError,
    ExportPolicyError,
    ExportTooLargeError,
    ForensicCaseNotFoundError,
    ForensicError,
    ForensicExportNotFoundError,
    ForensicNoteNotFoundError,
    InvalidCaseTransitionError,
    NoteVersionConflictError,
    ResolutionRequirementsError,
    UnresolvedCriticalFindingError,
)
from backend.app.forensics.service import ForensicService

router = APIRouter(
    prefix="/api/v1/forensics",
    tags=["forensics"],
    dependencies=[require_read],
)

MAX_PAGE_SIZE = 100


def get_forensic_service(request: Request) -> ForensicService:
    service = getattr(request.app.state, "forensic_service", None)
    if service is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "service_not_ready",
                "message": "Forensic investigation is not initialized.",
            },
        )
    return service


def _actor(principal: Principal) -> tuple[str | None, str]:
    user = getattr(principal, "user", None)
    actor_id = getattr(user, "email", None)
    role = getattr(user, "role", None)
    return actor_id, str(getattr(role, "value", role or "SYSTEM")).upper()


def _handle_error(exc: Exception) -> HTTPException:
    if isinstance(exc, (ForensicCaseNotFoundError, ForensicExportNotFoundError, ForensicNoteNotFoundError)):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(
        exc,
        (
            CaseVersionConflictError,
            NoteVersionConflictError,
            InvalidCaseTransitionError,
            ResolutionRequirementsError,
            UnresolvedCriticalFindingError,
        ),
    ):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(
        exc,
        (
            EvidenceReferenceError,
            ExportPolicyError,
            ExportTooLargeError,
            CorrelationError,
            ForensicError,
            ValueError,
        ),
    ):
        return HTTPException(status_code=422, detail=str(exc))
    return HTTPException(status_code=500, detail="Forensic operation failed.")


class EvidenceReferenceRequest(BaseModel):
    artifact_type: str = Field(min_length=1, max_length=32)
    artifact_id: str = Field(min_length=1, max_length=512)
    original_relative_path: str = Field(default="", max_length=2048)
    expected_sha256: str = Field(default="", max_length=71)
    source_audit_run_id: str | None = Field(default=None, max_length=128)
    source_finding_id: str | None = Field(default=None, max_length=64)


class CaseCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=8192)
    case_type: str = Field(default="FORENSIC_REVIEW", max_length=32)
    severity: str = Field(default="MEDIUM", max_length=16)
    priority: str | None = Field(default=None, max_length=8)
    originating_incident_id: str | None = Field(default=None, max_length=36)
    originating_audit_run_id: str | None = Field(default=None, max_length=128)
    assigned_to: str | None = Field(default=None, max_length=256)
    idempotency_key: str | None = Field(default=None, max_length=128)
    evidence_references: list[EvidenceReferenceRequest] = Field(default_factory=list, max_length=64)


class CorrelationRequest(BaseModel):
    finding_ids: list[str] = Field(default_factory=list, max_length=500)
    audit_run_id: str | None = Field(default=None, max_length=128)


class TransitionRequest(BaseModel):
    target_status: str = Field(min_length=1, max_length=32)
    reason: str = Field(min_length=1, max_length=1024)
    expected_version: int | None = Field(default=None, ge=1)
    resolution_summary: str | None = Field(default=None, max_length=8192)
    reopening: bool = False
    acknowledge_critical_findings: bool = False
    acknowledge_evidence_failures: bool = False
    allow_unverified_evidence: bool = False


class AssignRequest(BaseModel):
    assignee: str | None = Field(default=None, max_length=256)
    reason: str = Field(default="", max_length=1024)
    expected_version: int | None = Field(default=None, ge=1)


class NoteCreateRequest(BaseModel):
    note_type: str = Field(default="OBSERVATION", max_length=32)
    content: str = Field(min_length=1, max_length=16384)
    visibility: str = Field(default="INTERNAL", max_length=16)
    related_evidence_ids: list[str] = Field(default_factory=list, max_length=64)


class NoteUpdateRequest(BaseModel):
    content: str = Field(min_length=1, max_length=16384)
    expected_version: int | None = Field(default=None, ge=1)
    related_evidence_ids: list[str] | None = Field(default=None, max_length=64)


class ActionCreateRequest(BaseModel):
    action_type: str = Field(min_length=1, max_length=64)
    description: str = Field(min_length=1, max_length=8192)
    related_finding_ids: list[str] = Field(default_factory=list, max_length=128)
    result: str = Field(default="RECORDED", max_length=32)
    approval_reference: str | None = Field(default=None, max_length=256)


class IncidentLinkRequest(BaseModel):
    incident_id: str = Field(min_length=1, max_length=36)


class ExportCreateRequest(BaseModel):
    include_evidence_bytes: bool = False


@router.get("/status", summary="Forensic workspace status")
def forensic_status(service: ForensicService = Depends(get_forensic_service)) -> dict[str, Any]:
    try:
        return service.status()
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/summary", summary="Forensic case summary")
def forensic_summary(service: ForensicService = Depends(get_forensic_service)) -> dict[str, Any]:
    try:
        return service.summary()
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/cases", summary="List forensic cases")
def list_cases(
    status: list[str] | None = Query(default=None),
    severity: list[str] | None = Query(default=None),
    case_type: list[str] | None = Query(default=None),
    assigned_to: str | None = Query(default=None, max_length=256),
    source: str | None = Query(default=None, max_length=32),
    originating_incident_id: str | None = Query(default=None, max_length=36),
    search: str | None = Query(default=None, max_length=256),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    try:
        return service.list_cases(
            status=status,
            severity=severity,
            case_type=case_type,
            assigned_to=assigned_to,
            source=source,
            originating_incident_id=originating_incident_id,
            search=search,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/cases", summary="Open a forensic case", status_code=201)
def create_case(
    payload: CaseCreateRequest,
    principal: Principal = Depends(require_capability_dep("forensic_case_write")),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.create_case(
            title=payload.title,
            description=payload.description,
            case_type=payload.case_type,
            severity=payload.severity,
            priority=payload.priority,
            originating_incident_id=payload.originating_incident_id,
            originating_audit_run_id=payload.originating_audit_run_id,
            assigned_to=payload.assigned_to,
            idempotency_key=payload.idempotency_key,
            evidence_references=[item.model_dump() for item in payload.evidence_references],
            actor_id=actor_id,
            actor_role=actor_role,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/cases/{case_id}", summary="Get forensic case detail")
def get_case(
    case_id: str,
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    try:
        return service.get_case(case_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/cases/{case_id}/custody", summary="Read the custody ledger")
def get_custody(
    case_id: str,
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    try:
        return service.custody(case_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/cases/{case_id}/timeline", summary="Read the case timeline")
def get_timeline(
    case_id: str,
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    try:
        return service.timeline(case_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/cases/{case_id}/exports", summary="List forensic exports")
def list_exports(
    case_id: str,
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    try:
        return service.list_exports(case_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/correlate", summary="Correlate V33 findings into cases")
def correlate_findings(
    payload: CorrelationRequest,
    principal: Principal = Depends(require_capability_dep("forensic_case_write")),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.correlate_findings(
            finding_ids=payload.finding_ids,
            audit_run_id=payload.audit_run_id,
            actor_id=actor_id,
            actor_role=actor_role,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/cases/{case_id}/correlate", summary="Correlate findings into one case")
def correlate_case_findings(
    case_id: str,
    payload: CorrelationRequest,
    principal: Principal = Depends(require_capability_dep("forensic_case_write")),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.correlate_findings(
            finding_ids=payload.finding_ids,
            audit_run_id=payload.audit_run_id,
            case_id=case_id,
            actor_id=actor_id,
            actor_role=actor_role,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/cases/{case_id}/transition", summary="Apply an authorized case transition")
def transition_case(
    case_id: str,
    payload: TransitionRequest,
    principal: Principal = Depends(require_capability_dep("forensic_case_write")),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        target = CaseStatus(str(payload.target_status).upper())
    except ValueError:
        raise HTTPException(status_code=422, detail="unknown forensic case status") from None
    if payload.reopening or target in CLOSE_STATUSES:
        check_capability(principal, "forensic_case_close")
    try:
        return service.transition_case(
            case_id,
            target_status=payload.target_status,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=payload.expected_version,
            resolution_summary=payload.resolution_summary,
            reopening=payload.reopening,
            acknowledge_critical_findings=payload.acknowledge_critical_findings,
            acknowledge_evidence_failures=payload.acknowledge_evidence_failures,
            allow_unverified_evidence=payload.allow_unverified_evidence,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/cases/{case_id}/assign", summary="Assign or unassign a case")
def assign_case(
    case_id: str,
    payload: AssignRequest,
    principal: Principal = Depends(require_capability_dep("forensic_case_write")),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.assign_case(
            case_id,
            assignee=payload.assignee,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=payload.expected_version,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/cases/{case_id}/notes", summary="Add an investigation note", status_code=201)
def add_note(
    case_id: str,
    payload: NoteCreateRequest,
    principal: Principal = Depends(require_capability_dep("forensic_case_write")),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.add_note(
            case_id,
            note_type=payload.note_type,
            content=payload.content,
            visibility=payload.visibility,
            related_evidence_ids=payload.related_evidence_ids,
            author_id=actor_id,
            actor_role=actor_role,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get(
    "/cases/{case_id}/notes/{note_id}/revisions",
    summary="Read investigation-note edit history",
)
def get_note_revisions(
    case_id: str,
    note_id: str,
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    try:
        return service.note_revisions(case_id, note_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.patch("/cases/{case_id}/notes/{note_id}", summary="Edit an investigation note")
def update_note(
    case_id: str,
    note_id: str,
    payload: NoteUpdateRequest,
    principal: Principal = Depends(require_capability_dep("forensic_case_write")),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.update_note(
            case_id,
            note_id,
            content=payload.content,
            editor_id=actor_id,
            actor_role=actor_role,
            expected_version=payload.expected_version,
            related_evidence_ids=payload.related_evidence_ids,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/cases/{case_id}/actions", summary="Record an operator action", status_code=201)
def add_action(
    case_id: str,
    payload: ActionCreateRequest,
    principal: Principal = Depends(require_capability_dep("forensic_case_write")),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.add_action(
            case_id,
            action_type=payload.action_type,
            description=payload.description,
            related_finding_ids=payload.related_finding_ids,
            result=payload.result,
            approval_reference=payload.approval_reference,
            actor_id=actor_id,
            actor_role=actor_role,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/cases/{case_id}/evidence", summary="Reference supporting evidence", status_code=201)
def add_evidence_reference(
    case_id: str,
    payload: EvidenceReferenceRequest,
    principal: Principal = Depends(require_capability_dep("forensic_case_write")),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.add_evidence_reference(
            case_id,
            reference=payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/cases/{case_id}/incidents", summary="Link an existing V10 incident")
def link_incident(
    case_id: str,
    payload: IncidentLinkRequest,
    principal: Principal = Depends(require_capability_dep("forensic_case_write")),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.link_incident(
            case_id,
            incident_id=payload.incident_id,
            actor_id=actor_id,
            actor_role=actor_role,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/cases/{case_id}/verify", summary="Run read-only case verification")
def verify_case(
    case_id: str,
    principal: Principal = Depends(require_capability_dep("forensic_verify")),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.verify_case(case_id, actor_id=actor_id, actor_role=actor_role)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/cases/{case_id}/exports", summary="Build a deterministic forensic export", status_code=201)
def create_export(
    case_id: str,
    payload: ExportCreateRequest,
    principal: Principal = Depends(require_capability_dep("forensic_export")),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.create_export(
            case_id,
            include_evidence_bytes=payload.include_evidence_bytes,
            actor_id=actor_id,
            actor_role=actor_role,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/exports/{export_id}", summary="Download a forensic export")
def download_export(
    export_id: str,
    _principal: Principal = Depends(require_capability_dep("forensic_export")),
    service: ForensicService = Depends(get_forensic_service),
) -> FileResponse:
    try:
        path, filename = service.export_path(export_id)
    except Exception as exc:
        raise _handle_error(exc) from None
    return FileResponse(
        path,
        filename=filename,
        media_type="application/zip",
        headers={"Cache-Control": "no-store"},
    )


@router.post("/exports/{export_id}/verify", summary="Verify a forensic export")
def verify_export(
    export_id: str,
    principal: Principal = Depends(require_capability_dep("forensic_export")),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.verify_export(export_id, actor_id=actor_id, actor_role=actor_role)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/findings", summary="List V33 findings available for correlation")
def list_findings(
    audit_run_id: str | None = Query(default=None, max_length=128),
    severity: str | None = Query(default=None, max_length=16),
    reason_code: str | None = Query(default=None, max_length=64),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    service: ForensicService = Depends(get_forensic_service),
) -> dict[str, Any]:
    try:
        return service.list_source_findings(
            audit_run_id=audit_run_id,
            severity=severity,
            reason_code=reason_code,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


__all__ = ["get_forensic_service", "router"]
