"""V37 governance intelligence API.

Deterministic risk scoring and versioned operational SLA reads are additive to
the V35 ``/governance`` API. Reads need ``governance_intelligence_read``,
``governance_risk_read``, or ``governance_sla_read``; configuration needs
``governance_intelligence_configure`` (ADMIN only).

No route deletes evidence, cases, custody records, governance records,
automation records, snapshots, or audit history. Risk scores and SLA states are
prioritization aids, not legal advice or automatic governance decisions.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from backend.app.auth.dependencies import (
    Principal,
    require_capability_dep,
    require_read,
)
from backend.app.core.logging import get_logger
from backend.app.governance.intelligence.errors import (
    IntelligenceDisabledError,
    IntelligenceError,
    IntelligenceValidationError,
    RiskCaseNotFoundError,
    RiskModelVersionConflictError,
    SlaTargetNotFoundError,
    SlaTargetVersionConflictError,
)
from backend.app.governance.intelligence.schemas import (
    RiskModelUpdateRequest,
    SlaTargetUpdateRequest,
)
from backend.app.governance.intelligence.service import GovernanceIntelligenceService

router = APIRouter(
    prefix="/api/v1/governance/intelligence",
    tags=["governance-intelligence"],
    dependencies=[require_read],
)

MAX_PAGE_SIZE = 100

logger = get_logger(__name__)


def get_governance_intelligence_service(request: Request) -> GovernanceIntelligenceService:
    service = getattr(request.app.state, "governance_intelligence_service", None)
    if service is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "service_not_ready",
                "message": "Governance intelligence is not initialized.",
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
    if isinstance(exc, (RiskCaseNotFoundError, SlaTargetNotFoundError)):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (RiskModelVersionConflictError, SlaTargetVersionConflictError)):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, IntelligenceDisabledError):
        return HTTPException(status_code=503, detail=str(exc))
    if isinstance(exc, (IntelligenceError, IntelligenceValidationError, ValueError)):
        return HTTPException(status_code=422, detail=str(exc))
    logger.error("unhandled governance intelligence error", exc_info=True)
    return HTTPException(
        status_code=500,
        detail={"code": "internal_error", "message": "Governance intelligence request failed."},
    )


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------
@router.get("/status", summary="Read governance intelligence status")
def intelligence_status(
    _principal: Principal = Depends(require_capability_dep("governance_intelligence_read")),
    service: GovernanceIntelligenceService = Depends(get_governance_intelligence_service),
) -> dict[str, Any]:
    try:
        return service.status()
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Risk model
# ---------------------------------------------------------------------------
@router.get("/risk/model", summary="Read the active governance risk model")
def risk_model(
    _principal: Principal = Depends(require_capability_dep("governance_risk_read")),
    service: GovernanceIntelligenceService = Depends(get_governance_intelligence_service),
) -> dict[str, Any]:
    try:
        return service.risk_model()
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/risk/model/versions", summary="List governance risk model versions")
def risk_model_versions(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_risk_read")),
    service: GovernanceIntelligenceService = Depends(get_governance_intelligence_service),
) -> dict[str, Any]:
    try:
        return service.list_risk_model_versions(page=page, page_size=page_size)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.put("/risk/model", summary="Append a new governance risk model version")
def update_risk_model(
    payload: RiskModelUpdateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_intelligence_configure")),
    service: GovernanceIntelligenceService = Depends(get_governance_intelligence_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.update_risk_model(
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Case risk
# ---------------------------------------------------------------------------
@router.get("/risk/cases", summary="List prioritized governance risk cases")
def risk_cases(
    risk_level: str | None = Query(default=None, pattern="^(LOW|MODERATE|HIGH|CRITICAL)$"),
    case_status: str | None = Query(default=None, max_length=32),
    case_severity: str | None = Query(default=None, max_length=16),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_risk_read")),
    service: GovernanceIntelligenceService = Depends(get_governance_intelligence_service),
) -> dict[str, Any]:
    try:
        return service.risk_cases(
            risk_level=risk_level,
            case_status=case_status,
            case_severity=case_severity,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/risk/cases/{case_id}", summary="Read one explainable case risk score")
def case_risk(
    case_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_risk_read")),
    service: GovernanceIntelligenceService = Depends(get_governance_intelligence_service),
) -> dict[str, Any]:
    try:
        return service.case_risk(case_id)
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Operational SLA
# ---------------------------------------------------------------------------
@router.get("/sla/targets", summary="List versioned operational SLA targets")
def sla_targets(
    target_key: str | None = Query(default=None, max_length=48),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_sla_read")),
    service: GovernanceIntelligenceService = Depends(get_governance_intelligence_service),
) -> dict[str, Any]:
    try:
        return service.list_sla_targets(target_key=target_key, page=page, page_size=page_size)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.put("/sla/targets/{target_key}", summary="Append a new operational SLA target version")
def update_sla_target(
    target_key: str,
    payload: SlaTargetUpdateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_intelligence_configure")),
    service: GovernanceIntelligenceService = Depends(get_governance_intelligence_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.update_sla_target(
            target_key,
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/sla/backlog", summary="Read the operational SLA backlog")
def sla_backlog(
    target_key: str | None = Query(default=None, max_length=48),
    state: str | None = Query(
        default=None,
        pattern="^(WITHIN_TARGET|AT_RISK|BREACHED|MET|MISSED|UNKNOWN|NOT_APPLICABLE)$",
    ),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_sla_read")),
    service: GovernanceIntelligenceService = Depends(get_governance_intelligence_service),
) -> dict[str, Any]:
    try:
        return service.sla_backlog(target_key=target_key, state=state, page=page, page_size=page_size)
    except Exception as exc:
        raise _handle_error(exc) from None


__all__ = ["router"]
