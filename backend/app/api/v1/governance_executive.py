"""V38 executive governance command center API (foundation reads).

Executive status, deterministic health, source-preserving KPIs, and
configuration reads are additive to the V35 ``/governance`` API. Summary reads
need ``governance_executive_read`` (all roles); configuration reads need
``governance_executive_detail_read`` (ADMIN, OPERATOR).

No route deletes evidence, cases, custody records, governance records,
automation records, intelligence records, snapshots, or audit history. Health
and KPI values are deterministic local aggregates, not regulatory certification
or a safety guarantee.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

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
# Configuration (read-only in the foundation layer)
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


__all__ = ["DEFAULT_WINDOW_DAYS", "router"]
