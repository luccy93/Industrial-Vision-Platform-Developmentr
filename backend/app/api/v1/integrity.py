"""V33 continuous integrity monitoring API — read-first, audited.

Every route requires authentication (``read``). Starting or cancelling an
audit additionally requires the ``integrity_audit_run`` capability
(ADMIN/OPERATOR). The API is a thin orchestration layer: verification and
persistence live in :mod:`backend.app.integrity`. Responses are sanitized and
never expose absolute paths, credentials, or raw verifier internals.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from backend.app.auth.dependencies import (
    Principal,
    require_capability_dep,
    require_integrity_audit,
    require_read,
)
from backend.app.integrity.errors import (
    AuditRunNotCancellableError,
    AuditRunNotFoundError,
    DuplicateAuditRunError,
    InvalidAuditScopeError,
    MonitoringStoreError,
    MonitoringStoreUnavailable,
)
from backend.app.integrity.service import IntegrityService

router = APIRouter(
    prefix="/api/v1/integrity",
    tags=["integrity"],
    dependencies=[require_read],
)

MAX_PAGE_SIZE = 100


def get_integrity_service(request: Request) -> IntegrityService:
    service = getattr(request.app.state, "integrity_service", None)
    if service is None:
        raise HTTPException(
            status_code=503,
            detail={"code": "service_not_ready", "message": "Integrity monitoring is not initialized."},
        )
    return service


class AuditCreateRequest(BaseModel):
    """Bounded manual audit request; scopes are validated against V33."""

    scopes: list[str] = Field(default_factory=lambda: ["FULL"], max_length=16)
    idempotency_key: str | None = Field(default=None, max_length=128)


class AuditCancelResponse(BaseModel):
    cancelled: bool
    audit_run_id: str


def _handle_error(exc: Exception) -> HTTPException:
    if isinstance(exc, AuditRunNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, AuditRunNotCancellableError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, DuplicateAuditRunError):
        detail: dict[str, Any] = {
            "code": "audit_already_running",
            "message": str(exc),
        }
        if exc.existing_run_id:
            detail["existing_run_id"] = exc.existing_run_id
        return HTTPException(status_code=409, detail=detail)
    if isinstance(exc, InvalidAuditScopeError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, (MonitoringStoreUnavailable, MonitoringStoreError)):
        return HTTPException(
            status_code=503,
            detail={"code": "service_not_ready", "message": "Integrity monitoring store is unavailable."},
        )
    if isinstance(exc, ValueError):
        return HTTPException(status_code=422, detail=str(exc))
    return HTTPException(status_code=500, detail="Integrity operation failed.")


@router.get("/status", summary="Continuous integrity status")
def integrity_status(
    service: IntegrityService = Depends(get_integrity_service),
) -> dict[str, Any]:
    """Overview: latest run, last success/failure, findings, trust, scheduler."""
    try:
        return service.status()
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/summary", summary="Integrity operational summary")
def integrity_summary(
    service: IntegrityService = Depends(get_integrity_service),
) -> dict[str, Any]:
    """Aggregate counts, retention, assurance, and scheduler state."""
    try:
        return service.summary()
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/audits", summary="List audit runs")
def list_audits(
    status: str | None = Query(default=None, max_length=32),
    scope: str | None = Query(default=None, max_length=64),
    trigger: str | None = Query(default=None, max_length=32),
    started_from: str | None = Query(default=None, max_length=64),
    started_to: str | None = Query(default=None, max_length=64),
    page: int = Query(default=1, ge=1),
    page_size: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    service: IntegrityService = Depends(get_integrity_service),
) -> dict[str, Any]:
    """Paginated audit history with bounded filters."""
    try:
        return service.list_audits(
            status=status,
            scope=scope,
            trigger=trigger,
            started_from=started_from,
            started_to=started_to,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/history", summary="Audit history")
def audit_history(
    page: int = Query(default=1, ge=1),
    page_size: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    service: IntegrityService = Depends(get_integrity_service),
) -> dict[str, Any]:
    """Terminal audit history (alias of the audit listing, newest first)."""
    try:
        return service.history(page=page, page_size=page_size)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/audits/{audit_id}", summary="Get audit run detail")
def get_audit(
    audit_id: str,
    service: IntegrityService = Depends(get_integrity_service),
) -> dict[str, Any]:
    """Run summary plus per-scope results and persisted findings."""
    try:
        return service.get_audit(audit_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/findings", summary="List integrity findings")
def list_findings(
    severity: str | None = Query(default=None, max_length=32),
    reason_code: str | None = Query(default=None, max_length=64),
    scope: str | None = Query(default=None, max_length=64),
    audit_run_id: str | None = Query(default=None, max_length=128),
    artifact_id: str | None = Query(default=None, max_length=256),
    detected_from: str | None = Query(default=None, max_length=64),
    detected_to: str | None = Query(default=None, max_length=64),
    page: int = Query(default=1, ge=1),
    page_size: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    service: IntegrityService = Depends(get_integrity_service),
) -> dict[str, Any]:
    """Paginated, sanitized findings with bounded filters."""
    try:
        return service.list_findings(
            severity=severity,
            reason_code=reason_code,
            scope=scope,
            audit_run_id=audit_run_id,
            artifact_id=artifact_id,
            detected_from=detected_from,
            detected_to=detected_to,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post(
    "/audits",
    summary="Start a bounded integrity audit",
    status_code=201,
)
def start_audit(
    payload: AuditCreateRequest,
    principal: Principal = Depends(require_capability_dep("integrity_audit_run")),
    service: IntegrityService = Depends(get_integrity_service),
) -> dict[str, Any]:
    """Run an audit synchronously within the configured bounded timeout.

    The response is the terminal run summary. Protected V30-V32 inputs are
    read-only; only the isolated monitoring store is written. No external
    anchoring is performed or claimed.
    """
    user = getattr(principal, "user", None)
    requested_by = getattr(user, "email", None)
    try:
        return service.run_audit(
            scopes=payload.scopes or ["FULL"],
            requested_by=requested_by,
            idempotency_key=payload.idempotency_key,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post(
    "/audits/{audit_id}/cancel",
    summary="Cancel a running integrity audit",
    dependencies=[require_integrity_audit],
)
def cancel_audit(
    audit_id: str,
    service: IntegrityService = Depends(get_integrity_service),
) -> AuditCancelResponse:
    """Cancel an in-process run; cross-process cancellation is not claimed."""
    try:
        service.cancel_audit(audit_id)
    except Exception as exc:
        raise _handle_error(exc) from None
    return AuditCancelResponse(cancelled=True, audit_run_id=audit_id)


__all__ = ["get_integrity_service", "router"]
