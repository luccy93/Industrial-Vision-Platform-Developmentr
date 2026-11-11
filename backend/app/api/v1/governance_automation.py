"""V36 governance automation API.

The automation workspace is additive to the V35 ``/governance`` API. Reads need
``governance_automation_read`` or ``governance_snapshot_read``; schedule changes
need ``governance_automation_configure`` (ADMIN only); manual runs/retries need
``governance_automation_retry``; cancellation needs
``governance_automation_cancel``; snapshot generation needs
``governance_snapshot_generate``.

No route deletes jobs, events, snapshots, evidence, holds, dispositions, or
audit records. Reminders are review prompts and never approve or release a hold,
decide a disposition, or generate a forensic export.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from backend.app.auth.dependencies import (
    Principal,
    require_capability_dep,
    require_read,
)
from backend.app.core.logging import get_logger
from backend.app.governance.automation.errors import (
    AutomationDisabledError,
    AutomationError,
    JobNotFoundError,
    JobStateError,
    RetryExhaustedError,
    ScheduleNotFoundError,
    ScheduleVersionConflictError,
    SnapshotNotFoundError,
)
from backend.app.governance.automation.service import GovernanceAutomationService
from backend.app.governance.schemas import (
    AutomationActionRequest,
    AutomationRunRequest,
    AutomationScheduleUpdateRequest,
    AutomationSnapshotGenerateRequest,
)

router = APIRouter(
    prefix="/api/v1/governance/automation",
    tags=["governance-automation"],
    dependencies=[require_read],
)

MAX_PAGE_SIZE = 100

logger = get_logger(__name__)


def get_governance_automation_service(request: Request) -> GovernanceAutomationService:
    service = getattr(request.app.state, "governance_automation_service", None)
    if service is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "service_not_ready",
                "message": "Governance automation is not initialized.",
            },
        )
    return service


def _actor(principal: Principal) -> tuple[str | None, str]:
    user = getattr(principal, "user", None)
    actor_id = getattr(user, "email", None)
    role = getattr(user, "role", None)
    return actor_id, str(getattr(role, "value", role or "SYSTEM")).upper()


def _request_id(request: Request) -> str | None:
    value = getattr(request.state, "request_id", None)
    return str(value) if value else None


def _handle_error(exc: Exception) -> HTTPException:
    if isinstance(exc, (ScheduleNotFoundError, JobNotFoundError, SnapshotNotFoundError)):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(
        exc,
        (ScheduleVersionConflictError, JobStateError, RetryExhaustedError),
    ):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, AutomationDisabledError):
        return HTTPException(status_code=503, detail=str(exc))
    if isinstance(exc, (AutomationError, ValueError)):
        return HTTPException(status_code=422, detail=str(exc))
    logger.error("unhandled governance automation error", exc_info=True)
    return HTTPException(
        status_code=500,
        detail={"code": "internal_error", "message": "Governance automation request failed."},
    )


# ---------------------------------------------------------------------------
# Status and health
# ---------------------------------------------------------------------------
@router.get("/status", summary="Read governance automation status")
def automation_status(
    _principal: Principal = Depends(require_capability_dep("governance_automation_read")),
    service: GovernanceAutomationService = Depends(get_governance_automation_service),
) -> dict[str, Any]:
    try:
        return service.status()
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/health", summary="Read governance automation health")
def automation_health(
    _principal: Principal = Depends(require_capability_dep("governance_automation_read")),
    service: GovernanceAutomationService = Depends(get_governance_automation_service),
) -> dict[str, Any]:
    try:
        return service.health()
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Schedules
# ---------------------------------------------------------------------------
@router.get("/schedules", summary="List governance automation schedules")
def list_schedules(
    _principal: Principal = Depends(require_capability_dep("governance_automation_read")),
    service: GovernanceAutomationService = Depends(get_governance_automation_service),
) -> dict[str, Any]:
    try:
        return service.list_schedules()
    except Exception as exc:
        raise _handle_error(exc) from None


@router.put("/schedules/{job_type}", summary="Update one governance schedule")
def update_schedule(
    job_type: str,
    payload: AutomationScheduleUpdateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_automation_configure")),
    service: GovernanceAutomationService = Depends(get_governance_automation_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.update_schedule(
            job_type,
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------
@router.get("/jobs", summary="List governance automation jobs")
def list_jobs(
    job_type: str | None = Query(default=None, max_length=64),
    status: str | None = Query(default=None, max_length=16),
    trigger: str | None = Query(default=None, max_length=16),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_automation_read")),
    service: GovernanceAutomationService = Depends(get_governance_automation_service),
) -> dict[str, Any]:
    try:
        return service.list_jobs(
            job_type=job_type,
            status=status,
            trigger=trigger,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/jobs/{job_id}", summary="Read one governance automation job")
def job_detail(
    job_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_automation_read")),
    service: GovernanceAutomationService = Depends(get_governance_automation_service),
) -> dict[str, Any]:
    try:
        return service.job_detail(job_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/jobs/run", summary="Run a governance automation job now")
def run_job_now(
    payload: AutomationRunRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_automation_retry")),
    service: GovernanceAutomationService = Depends(get_governance_automation_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.run_now(
            job_type=payload.job_type,
            idempotency_key=payload.idempotency_key,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/jobs/{job_id}/retry", summary="Retry a terminal governance job")
def retry_job(
    job_id: str,
    payload: AutomationActionRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_automation_retry")),
    service: GovernanceAutomationService = Depends(get_governance_automation_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.retry_job(
            job_id,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/jobs/{job_id}/cancel", summary="Cancel a governance job")
def cancel_job(
    job_id: str,
    payload: AutomationActionRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_automation_cancel")),
    service: GovernanceAutomationService = Depends(get_governance_automation_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.cancel_job(
            job_id,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Compliance snapshots
# ---------------------------------------------------------------------------
@router.get("/snapshots", summary="List compliance snapshots")
def list_snapshots(
    snapshot_type: str | None = Query(default=None, max_length=32),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_snapshot_read")),
    service: GovernanceAutomationService = Depends(get_governance_automation_service),
) -> dict[str, Any]:
    try:
        return service.list_snapshots(snapshot_type=snapshot_type, page=page, page_size=page_size)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/snapshots", summary="Generate a compliance snapshot")
def generate_snapshot(
    payload: AutomationSnapshotGenerateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_snapshot_generate")),
    service: GovernanceAutomationService = Depends(get_governance_automation_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.generate_snapshot(
            idempotency_key=payload.idempotency_key,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/snapshots/{snapshot_id}", summary="Read one compliance snapshot")
def get_snapshot(
    snapshot_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_snapshot_read")),
    service: GovernanceAutomationService = Depends(get_governance_automation_service),
) -> dict[str, Any]:
    try:
        return service.get_snapshot(snapshot_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/snapshots/{snapshot_id}/csv", summary="Download a stored snapshot CSV")
def snapshot_csv(
    snapshot_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_snapshot_read")),
    service: GovernanceAutomationService = Depends(get_governance_automation_service),
) -> Response:
    try:
        payload = service.get_snapshot(snapshot_id)
        body = service.snapshot_csv(payload["snapshot"])
    except Exception as exc:
        raise _handle_error(exc) from None
    return Response(
        content=body,
        media_type="text/csv",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": 'attachment; filename="governance-compliance-snapshot.csv"',
        },
    )


# ---------------------------------------------------------------------------
# Reminder activity
# ---------------------------------------------------------------------------
@router.get("/reminders", summary="Read reminder queue and delivery state")
def reminder_activity(
    event_type: str | None = Query(default=None, max_length=64),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_automation_read")),
    service: GovernanceAutomationService = Depends(get_governance_automation_service),
) -> dict[str, Any]:
    try:
        return service.reminder_activity(event_type=event_type, page=page, page_size=page_size)
    except Exception as exc:
        raise _handle_error(exc) from None


__all__ = ["router"]
