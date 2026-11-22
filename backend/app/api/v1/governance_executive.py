"""V38 executive governance command center API.

Executive status, deterministic health, source-preserving KPIs, compatible
historical comparisons, bounded local reports, advisory strategic actions, and
operational configuration are additive to the V35 ``/governance`` API.

Summary reads need ``governance_executive_read`` (all roles). Detail, action,
and report reads need ``governance_executive_detail_read`` or
``governance_executive_action_read`` (ADMIN, OPERATOR). Report generation,
action assignment, and configuration writes are ADMIN-only. Action writes are
ADMIN/OPERATOR.

No route deletes evidence, cases, custody records, governance records,
automation records, intelligence records, snapshots, or audit history. Health
and KPI values are deterministic local aggregates, not regulatory certification
or a safety guarantee. Reports are never emailed, published, exported to a third
party, or rendered as PDF.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from backend.app.auth.dependencies import Principal, require_capability_dep, require_read
from backend.app.core.logging import get_logger
from backend.app.governance.executive.constants import (
    DEFAULT_WINDOW_DAYS,
    MAX_WINDOW_DAYS,
    MIN_WINDOW_DAYS,
)
from backend.app.governance.executive.errors import (
    ActionNotFoundError,
    ActionStateError,
    ActionVersionConflictError,
    ExecutiveConfigError,
    ExecutiveDisabledError,
    ExecutiveError,
    ExecutiveNotFoundError,
    ExecutiveValidationError,
    RecommendationNotActionableError,
    RecommendationNotFoundForActionError,
    ReportIncompatibleError,
    ReportIntegrityError,
    ReportNotFoundError,
    ReportUnavailableError,
)
from backend.app.governance.executive.schemas import (
    ExecutiveActionAssignRequest,
    ExecutiveActionCreateRequest,
    ExecutiveActionTransitionRequest,
    ExecutiveConfigUpdateRequest,
    ExecutiveReportGenerateRequest,
)
from backend.app.governance.executive.service import GovernanceExecutiveService

router = APIRouter(
    prefix="/api/v1/governance/executive",
    tags=["governance-executive"],
    dependencies=[require_read],
)

MAX_PAGE_SIZE = 100

logger = get_logger(__name__)


def get_governance_executive_service(request: Request) -> GovernanceExecutiveService:
    service = getattr(request.app.state, "governance_executive_service", None)
    if service is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "executive_not_ready",
                "message": "Executive governance is not initialized.",
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


def _http_error(status_code: int, code: str, message: str, **details: Any) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message, **details},
    )


def _handle_error(exc: Exception) -> HTTPException:
    """Map executive-domain failures to stable envelopes.

    Response codes are intentionally stable and bounded; raw SQL, paths, and
    exception internals never reach the response body.
    """
    if isinstance(
        exc,
        (
            ActionNotFoundError,
            ReportNotFoundError,
            RecommendationNotFoundForActionError,
            ExecutiveNotFoundError,
        ),
    ):
        return _http_error(404, "executive_not_found", str(exc))
    if isinstance(exc, RecommendationNotActionableError):
        return _http_error(
            409,
            "RECOMMENDATION_NOT_ACTIONABLE",
            "The linked recommendation is dismissed or resolved and cannot start a new action.",
        )
    if isinstance(
        exc,
        (
            ActionStateError,
            ActionVersionConflictError,
            ReportIncompatibleError,
            ReportIntegrityError,
        ),
    ):
        code = getattr(exc, "code", None) or "executive_conflict"
        return _http_error(409, str(code), str(exc))
    if isinstance(exc, ReportUnavailableError):
        return _http_error(503, "executive_unavailable", str(exc))
    if isinstance(exc, ExecutiveConfigError):
        return _http_error(503, "executive_config_unavailable", str(exc))
    if isinstance(exc, ExecutiveDisabledError):
        return _http_error(503, "executive_disabled", str(exc))
    if isinstance(exc, (ExecutiveValidationError, ExecutiveError, ValueError)):
        return _http_error(422, "executive_validation_error", str(exc))
    logger.error("unhandled executive governance error", exc_info=True)
    return _http_error(
        500,
        "internal_error",
        "Executive governance request failed.",
    )


def _window_days(value: int | None) -> int | None:
    if value is None:
        return None
    if value < MIN_WINDOW_DAYS or value > MAX_WINDOW_DAYS:
        raise _http_error(
            422,
            "executive_validation_error",
            f"window_days must be between {MIN_WINDOW_DAYS} and {MAX_WINDOW_DAYS}",
        )
    return value


# ---------------------------------------------------------------------------
# Status and health
# ---------------------------------------------------------------------------
@router.get("/status", summary="Read executive governance status")
def executive_status(
    _principal: Principal = Depends(require_capability_dep("governance_executive_read")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    try:
        return service.status()
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/health", summary="Read deterministic executive health")
def executive_health(
    window_days: int | None = Query(default=None, ge=MIN_WINDOW_DAYS, le=MAX_WINDOW_DAYS),
    _principal: Principal = Depends(require_capability_dep("governance_executive_read")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    try:
        return service.health(window_days=_window_days(window_days))
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# KPIs and source coverage
# ---------------------------------------------------------------------------
@router.get("/kpis", summary="Read source-preserving executive KPIs")
def executive_kpis(
    window_days: int | None = Query(default=None, ge=MIN_WINDOW_DAYS, le=MAX_WINDOW_DAYS),
    _principal: Principal = Depends(require_capability_dep("governance_executive_read")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    try:
        return service.kpis(window_days=_window_days(window_days))
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Strategic actions
# ---------------------------------------------------------------------------
@router.get("/actions", summary="List advisory strategic executive actions")
def executive_actions(
    status: str | None = Query(default=None, max_length=32),
    owner_id: str | None = Query(default=None, max_length=256),
    recommendation_id: str | None = Query(default=None, max_length=36),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_executive_action_read")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    try:
        return service.list_actions(
            status=status,
            owner_id=owner_id,
            recommendation_id=recommendation_id,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/actions", summary="Create a strategic action linked to a V37 recommendation")
def create_executive_action(
    payload: ExecutiveActionCreateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_executive_action_write")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.create_action(
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/actions/{action_id}", summary="Read one strategic action and its audit history")
def executive_action_detail(
    action_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_executive_action_read")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    try:
        return service.action_detail(action_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post(
    "/actions/{action_id}/transition",
    summary="Transition a strategic action through its validated lifecycle",
)
def transition_executive_action(
    action_id: str,
    payload: ExecutiveActionTransitionRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_executive_action_write")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.transition_action(
            action_id,
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/actions/{action_id}/assign", summary="Assign or reassign a strategic action owner")
def assign_executive_action(
    action_id: str,
    payload: ExecutiveActionAssignRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_executive_action_assign")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.assign_action(
            action_id,
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Executive reports
# ---------------------------------------------------------------------------
@router.get("/reports", summary="List bounded executive report metadata")
def executive_reports(
    report_type: str | None = Query(default=None, max_length=32),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_executive_detail_read")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    try:
        return service.list_reports(
            report_type=report_type,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/reports", summary="Generate a bounded local executive report")
def generate_executive_report(
    payload: ExecutiveReportGenerateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_executive_report_generate")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.generate_report(
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/reports/{report_id}", summary="Read one executive report and its stored payload")
def executive_report_detail(
    report_id: str,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_executive_detail_read")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.get_report(
            report_id,
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/reports/{report_id}/content", summary="Read report content in its stored format")
def executive_report_content(
    report_id: str,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_executive_detail_read")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> Response:
    actor_id, actor_role = _actor(principal)
    try:
        rendered = service.get_report_content(report_id)
        service.audit_report_view(
            report_id,
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
        report = rendered["report"]
        if str(report.get("format") or "json").lower() == "csv":
            filename = f"{report_id}.csv"
        else:
            filename = f"{report_id}.json"
        return Response(
            content=rendered["content"],
            media_type=rendered["media_type"],
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Compatible historical comparison
# ---------------------------------------------------------------------------
@router.get("/comparisons/{report_id}", summary="Compare a stored report with the current period")
def executive_comparison_current(
    report_id: str,
    request: Request,
    window_days: int | None = Query(default=None, ge=MIN_WINDOW_DAYS, le=MAX_WINDOW_DAYS),
    principal: Principal = Depends(require_capability_dep("governance_executive_detail_read")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.compare_reports(
            report_id,
            window_days=_window_days(window_days),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get(
    "/comparisons/{report_id}/vs/{other_report_id}",
    summary="Compare two stored executive reports for compatible periods",
)
def executive_comparison_pair(
    report_id: str,
    other_report_id: str,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_executive_detail_read")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.compare_reports(
            report_id,
            other_report_id=other_report_id,
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Configuration (append-only operational configuration)
# ---------------------------------------------------------------------------
@router.get("/config", summary="Read executive operational configuration")
def executive_config(
    _principal: Principal = Depends(require_capability_dep("governance_executive_detail_read")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    try:
        return service.config()
    except Exception as exc:
        raise _handle_error(exc) from None


@router.put("/config", summary="Append executive operational configuration")
def update_executive_config(
    payload: ExecutiveConfigUpdateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_executive_configure")),
    service: GovernanceExecutiveService = Depends(get_governance_executive_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.update_config(
            payload.config,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


__all__ = ["DEFAULT_WINDOW_DAYS", "router"]
