"""V35 forensic governance, retention, and compliance API.

Every route requires authentication. Read routes require ``governance_read``
(ADMIN/OPERATOR/VIEWER). Policy changes require ``governance_policy_write``;
retention evaluations require ``retention_evaluate``; legal-hold requests
require ``legal_hold_write`` while approvals/releases require
``legal_hold_approve``; disposition requests require ``disposition_request``
while decisions require ``disposition_review``; export requests require
``forensic_export_request`` while approval requires ``forensic_export_approve``
and generation/download still require the dedicated V34 ``forensic_export``
capability. Access audit and DETAIL readiness reports are ADMIN-only.

No route deletes evidence, cases, custody records, checkpoints, or audit
history. Approval and disposition states authorize review workflows only.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse

from backend.app.auth.dependencies import (
    Principal,
    check_capability,
    require_capability_dep,
    require_read,
)
from backend.app.core.logging import get_logger
from backend.app.forensics.errors import ForensicCaseNotFoundError
from backend.app.governance.errors import (
    DispositionBlockedError,
    DispositionNotFoundError,
    DispositionStateError,
    DispositionVersionConflictError,
    EvaluationNotFoundError,
    ExportApprovalNotFoundError,
    ExportApprovalStateError,
    ExportApprovalVersionConflictError,
    GovernanceAuditNotFoundError,
    GovernanceDisabledError,
    GovernanceError,
    GovernanceReportError,
    IdempotencyConflictError,
    LegalHoldNotFoundError,
    LegalHoldStateError,
    LegalHoldVersionConflictError,
    PolicyNotFoundError,
    PolicyValidationError,
    PolicyVersionConflictError,
    SeparationOfDutiesError,
)
from backend.app.governance.schemas import (
    DispositionCreateRequest,
    DispositionDecisionRequest,
    DispositionWithdrawRequest,
    ExportApprovalActionRequest,
    ExportApprovalCreateRequest,
    LegalHoldActionRequest,
    LegalHoldCreateRequest,
    PolicyCreateRequest,
    PolicyStateRequest,
    PolicyUpdateRequest,
    RetentionEvaluateRequest,
    RetentionReviewRequest,
)
from backend.app.governance.service import GovernanceService

router = APIRouter(
    prefix="/api/v1/governance",
    tags=["governance"],
    dependencies=[require_read],
)

MAX_PAGE_SIZE = 100

logger = get_logger(__name__)


def get_governance_service(request: Request) -> GovernanceService:
    service = getattr(request.app.state, "governance_service", None)
    if service is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "service_not_ready",
                "message": "Forensic governance is not initialized.",
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
    if isinstance(
        exc,
        (
            PolicyNotFoundError,
            EvaluationNotFoundError,
            LegalHoldNotFoundError,
            DispositionNotFoundError,
            ExportApprovalNotFoundError,
            GovernanceAuditNotFoundError,
            ForensicCaseNotFoundError,
        ),
    ):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(
        exc,
        (
            PolicyVersionConflictError,
            LegalHoldVersionConflictError,
            DispositionVersionConflictError,
            ExportApprovalVersionConflictError,
            LegalHoldStateError,
            DispositionStateError,
            ExportApprovalStateError,
            DispositionBlockedError,
            SeparationOfDutiesError,
            IdempotencyConflictError,
        ),
    ):
        detail: Any = str(exc)
        if isinstance(exc, DispositionBlockedError):
            detail = {"message": str(exc), "reason_codes": exc.reason_codes}
        return HTTPException(status_code=409, detail=detail)
    if isinstance(exc, GovernanceDisabledError):
        return HTTPException(status_code=503, detail=str(exc))
    if isinstance(exc, (PolicyValidationError, GovernanceReportError, GovernanceError, ValueError)):
        return HTTPException(status_code=422, detail=str(exc))
    logger.error("unexpected governance failure: %s", type(exc).__name__)
    return HTTPException(status_code=500, detail="Governance operation failed.")


# ---------------------------------------------------------------------------
# Status and policies
# ---------------------------------------------------------------------------
@router.get("/status", summary="Governance workspace status")
def governance_status(
    _principal: Principal = Depends(require_capability_dep("governance_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.status()
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/policies", summary="List governance policies")
def list_policies(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.list_policies(page=page, page_size=page_size)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/policies", summary="Create a governance policy", status_code=201)
def create_policy(
    payload: PolicyCreateRequest,
    principal: Principal = Depends(require_capability_dep("governance_policy_write")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.create_policy(payload.model_dump(), actor_id=actor_id, actor_role=actor_role)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/policies/{policy_id}", summary="Get a governance policy")
def get_policy(
    policy_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.get_policy(policy_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.patch("/policies/{policy_id}", summary="Append a governance policy version")
def update_policy(
    policy_id: str,
    payload: PolicyUpdateRequest,
    principal: Principal = Depends(require_capability_dep("governance_policy_write")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.update_policy(
            policy_id,
            payload.model_dump(exclude_unset=True),
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=payload.expected_version,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/policies/{policy_id}/state", summary="Change a policy state")
def set_policy_state(
    policy_id: str,
    payload: PolicyStateRequest,
    principal: Principal = Depends(require_capability_dep("governance_policy_write")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.set_policy_state(
            policy_id,
            state=payload.state,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=payload.expected_version,
            idempotency_key=payload.idempotency_key,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/policies/{policy_id}/versions", summary="List policy versions")
def list_policy_versions(
    policy_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.list_policy_versions(policy_id, page=page, page_size=page_size)
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------
@router.get("/retention/queue", summary="Read the latest retention evaluations")
def retention_queue(
    state: str | None = Query(default=None, max_length=32),
    as_of: date | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.retention_queue(state=state, page=page, page_size=page_size, as_of=as_of)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/retention/cases/{case_id}", summary="Read a case retention state")
def retention_case(
    case_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.retention_case(case_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/retention/evaluate", summary="Evaluate retention (non-destructive)")
def evaluate_retention(
    payload: RetentionEvaluateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("retention_evaluate")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        if payload.case_id:
            return service.evaluate_case(
                payload.case_id,
                actor_id=actor_id,
                actor_role=actor_role,
                as_of=payload.as_of,
                request_id=_request_id(request),
            )
        if not payload.case_ids:
            raise PolicyValidationError("case_id or case_ids is required")
        return service.evaluate_batch(
            payload.case_ids,
            actor_id=actor_id,
            actor_role=actor_role,
            as_of=payload.as_of,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/retention/cases/{case_id}/review", summary="Complete a retention review")
def review_retention(
    case_id: str,
    payload: RetentionReviewRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("retention_evaluate")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.review_retention(
            case_id,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            as_of=payload.as_of,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Legal holds
# ---------------------------------------------------------------------------
@router.get("/holds", summary="List legal holds")
def list_holds(
    case_id: str | None = Query(default=None, max_length=36),
    status: list[str] | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.list_legal_holds(case_id=case_id, statuses=status, page=page, page_size=page_size)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/holds", summary="Request a legal hold", status_code=201)
def create_hold(
    payload: LegalHoldCreateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("legal_hold_write")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.create_legal_hold(
            payload.case_id,
            evidence_reference_id=payload.evidence_reference_id,
            scope=payload.scope,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            idempotency_key=payload.idempotency_key,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/holds/{hold_id}", summary="Get a legal hold and its events")
def get_hold(
    hold_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.get_legal_hold(hold_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/holds/{hold_id}/approve", summary="Approve a pending legal hold")
def approve_hold(
    hold_id: str,
    payload: LegalHoldActionRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("legal_hold_approve")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.approve_legal_hold(
            hold_id,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=payload.expected_version,
            idempotency_key=payload.idempotency_key,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/holds/{hold_id}/reject", summary="Reject a pending legal hold")
def reject_hold(
    hold_id: str,
    payload: LegalHoldActionRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("legal_hold_approve")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.reject_legal_hold(
            hold_id,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=payload.expected_version,
            idempotency_key=payload.idempotency_key,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/holds/{hold_id}/release", summary="Release an active legal hold")
def release_hold(
    hold_id: str,
    payload: LegalHoldActionRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("legal_hold_approve")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.release_legal_hold(
            hold_id,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=payload.expected_version,
            idempotency_key=payload.idempotency_key,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/holds/{hold_id}/withdraw", summary="Withdraw a legal-hold request")
def withdraw_hold(
    hold_id: str,
    payload: LegalHoldActionRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("legal_hold_write")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.withdraw_legal_hold(
            hold_id,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=payload.expected_version,
            idempotency_key=payload.idempotency_key,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Disposition review
# ---------------------------------------------------------------------------
@router.get("/dispositions", summary="List disposition reviews")
def list_dispositions(
    case_id: str | None = Query(default=None, max_length=36),
    status: list[str] | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.list_dispositions(case_id=case_id, statuses=status, page=page, page_size=page_size)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/dispositions", summary="Request disposition review", status_code=201)
def request_disposition(
    payload: DispositionCreateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("disposition_request")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.request_disposition(
            payload.case_id,
            justification=payload.justification,
            actor_id=actor_id,
            actor_role=actor_role,
            idempotency_key=payload.idempotency_key,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/dispositions/{disposition_id}", summary="Get a disposition review")
def get_disposition(
    disposition_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.get_disposition(disposition_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/dispositions/{disposition_id}/decide", summary="Decide a disposition review")
def decide_disposition(
    disposition_id: str,
    payload: DispositionDecisionRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("disposition_review")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.decide_disposition(
            disposition_id,
            decision=payload.decision,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=payload.expected_version,
            idempotency_key=payload.idempotency_key,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/dispositions/{disposition_id}/withdraw", summary="Withdraw a disposition request")
def withdraw_disposition(
    disposition_id: str,
    payload: DispositionWithdrawRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("disposition_request")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.decide_disposition(
            disposition_id,
            decision="WITHDRAW",
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=payload.expected_version,
            idempotency_key=payload.idempotency_key,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Export approvals
# ---------------------------------------------------------------------------
@router.get("/exports", summary="List governance export approvals")
def list_exports(
    case_id: str | None = Query(default=None, max_length=36),
    status: list[str] | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.list_export_approvals(case_id=case_id, statuses=status, page=page, page_size=page_size)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/exports", summary="Request export approval", status_code=201)
def request_export(
    payload: ExportApprovalCreateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("forensic_export_request")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.request_export(
            payload.case_id,
            include_evidence_bytes=payload.include_evidence_bytes,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            idempotency_key=payload.idempotency_key,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/exports/{approval_id}", summary="Get a governance export approval")
def get_export(
    approval_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.get_export_approval(approval_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/exports/{approval_id}/approve", summary="Approve an export request")
def approve_export(
    approval_id: str,
    payload: ExportApprovalActionRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("forensic_export_approve")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.approve_export(
            approval_id,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=payload.expected_version,
            idempotency_key=payload.idempotency_key,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/exports/{approval_id}/reject", summary="Reject an export request")
def reject_export(
    approval_id: str,
    payload: ExportApprovalActionRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("forensic_export_approve")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.reject_export(
            approval_id,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=payload.expected_version,
            idempotency_key=payload.idempotency_key,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/exports/{approval_id}/withdraw", summary="Withdraw an export request")
def withdraw_export(
    approval_id: str,
    payload: ExportApprovalActionRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("forensic_export_request")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.withdraw_export(
            approval_id,
            reason=payload.reason,
            actor_id=actor_id,
            actor_role=actor_role,
            expected_version=payload.expected_version,
            idempotency_key=payload.idempotency_key,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/exports/{approval_id}/generate", summary="Generate an approved export")
def generate_export(
    approval_id: str,
    request: Request,
    principal: Principal = Depends(require_capability_dep("forensic_export")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.generate_export(
            approval_id,
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/exports/{approval_id}/verify", summary="Verify a generated export")
def verify_export(
    approval_id: str,
    request: Request,
    principal: Principal = Depends(require_capability_dep("forensic_export")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.verify_governance_export(
            approval_id,
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/exports/{approval_id}/download", summary="Download a generated export")
def download_export(
    approval_id: str,
    request: Request,
    principal: Principal = Depends(require_capability_dep("forensic_export")),
    service: GovernanceService = Depends(get_governance_service),
) -> FileResponse:
    actor_id, actor_role = _actor(principal)
    try:
        path, filename, _row = service.export_download(
            approval_id,
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None
    return FileResponse(
        path,
        filename=filename,
        media_type="application/zip",
        headers={"Cache-Control": "no-store"},
    )


# ---------------------------------------------------------------------------
# Access audit and compliance readiness
# ---------------------------------------------------------------------------
@router.get("/audit", summary="List append-only governance access audit events")
def list_audit(
    event_type: str | None = Query(default=None, max_length=64),
    actor_id: str | None = Query(default=None, max_length=256),
    case_id: str | None = Query(default=None, max_length=36),
    outcome: str | None = Query(default=None, max_length=16),
    target_type: str | None = Query(default=None, max_length=32),
    target_id: str | None = Query(default=None, max_length=128),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_audit_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.list_audit(
            event_type=event_type,
            actor_id=actor_id,
            case_id=case_id,
            outcome=outcome,
            target_type=target_type,
            target_id=target_id,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/audit/summary", summary="Summarize governance access audit")
def audit_summary(
    _principal: Principal = Depends(require_capability_dep("governance_audit_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.audit_summary()
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/audit/{event_id}", summary="Get one governance audit event")
def get_audit(
    event_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_audit_read")),
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    try:
        return service.get_audit(event_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/reports/compliance", summary="Generate a compliance-readiness report")
def compliance_report(
    request: Request,
    scope: str = Query(default="SUMMARY", max_length=16),
    case_id: str | None = Query(default=None, max_length=36),
    format: str = Query(default="json", max_length=16),
    as_of: date | None = Query(default=None),
    principal: Principal = require_read,
    service: GovernanceService = Depends(get_governance_service),
) -> dict[str, Any]:
    normalized = str(scope or "SUMMARY").upper()
    try:
        if normalized == "DETAIL" or case_id:
            check_capability(principal, "governance_report_generate")
        else:
            check_capability(principal, "governance_read")
        actor_id, actor_role = _actor(principal)
        return service.compliance_report(
            scope=normalized,
            case_id=case_id,
            format=format,
            actor_id=actor_id,
            actor_role=actor_role,
            as_of=as_of,
            request_id=_request_id(request),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/reports/compliance.csv", summary="Generate a compliance-readiness CSV")
def compliance_report_csv(
    request: Request,
    scope: str = Query(default="SUMMARY", max_length=16),
    case_id: str | None = Query(default=None, max_length=36),
    as_of: date | None = Query(default=None),
    principal: Principal = require_read,
    service: GovernanceService = Depends(get_governance_service),
) -> Response:
    normalized = str(scope or "SUMMARY").upper()
    try:
        if normalized == "DETAIL" or case_id:
            check_capability(principal, "governance_report_generate")
        else:
            check_capability(principal, "governance_read")
        actor_id, actor_role = _actor(principal)
        report = service.compliance_report(
            scope=normalized,
            case_id=case_id,
            format="csv",
            actor_id=actor_id,
            actor_role=actor_role,
            as_of=as_of,
            request_id=_request_id(request),
        )
        body = service.report_csv(report)
    except HTTPException:
        raise
    except Exception as exc:
        raise _handle_error(exc) from None
    return Response(
        content=body,
        media_type="text/csv",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": 'attachment; filename="governance-compliance.csv"',
        },
    )


__all__ = ["router"]
