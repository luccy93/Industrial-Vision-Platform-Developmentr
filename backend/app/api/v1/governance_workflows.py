"""V39 enterprise governance workflow orchestration API.

Versioned templates, workflow instances, task dependencies, ownership,
read-only cross-domain references, SLA indicators, escalations, and append-only
event history are additive to the V35 ``/governance`` and V38
``/governance/executive`` APIs.

Overview reads need ``governance_workflow_read`` (all roles). Detail reads need
``governance_workflow_detail_read`` (ADMIN, OPERATOR). Creation, transitions,
assignment, task writes, escalation, and audit reads need their dedicated
ADMIN/OPERATOR capabilities. Template management is ADMIN-only.

No route deletes evidence, cases, custody records, governance records,
automation records, intelligence records, executive actions, snapshots, or
audit history. Workflows never approve or release a hold, approve or reject a
disposition, delete or modify evidence, approve or generate an export, alter
custody, resolve a recommendation, or complete an executive action.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from backend.app.auth.dependencies import Principal, require_capability_dep, require_read
from backend.app.core.logging import get_logger
from backend.app.governance.workflows.constants import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
)
from backend.app.governance.workflows.errors import (
    DependencyError,
    EscalationNotEligibleError,
    EscalationNotFoundError,
    EscalationStateError,
    EscalationVersionConflictError,
    OwnerValidationError,
    ReferenceDeletedError,
    ReferenceNotFoundError,
    ReferenceUnauthorizedError,
    ReferenceUnavailableError,
    SourceCaseMismatchError,
    TaskNotFoundError,
    TaskStateError,
    TaskVersionConflictError,
    TemplateNotFoundError,
    TemplateValidationError,
    WorkflowConfigError,
    WorkflowDisabledError,
    WorkflowError,
    WorkflowNotFoundError,
    WorkflowStateError,
    WorkflowValidationError,
    WorkflowVersionConflictError,
)
from backend.app.governance.workflows.schemas import (
    WorkflowAssignRequest,
    WorkflowCreateRequest,
    WorkflowEscalationAcknowledgeRequest,
    WorkflowEscalationCreateRequest,
    WorkflowEscalationResolveRequest,
    WorkflowReferenceCreateRequest,
    WorkflowTaskAssignRequest,
    WorkflowTaskTransitionRequest,
    WorkflowTemplateCreateRequest,
    WorkflowTemplateDisableRequest,
    WorkflowTemplateVersionRequest,
    WorkflowTransitionRequest,
)
from backend.app.governance.workflows.service import GovernanceWorkflowService

router = APIRouter(
    prefix="/api/v1/governance/workflows",
    tags=["governance-workflows"],
    dependencies=[require_read],
)

logger = get_logger(__name__)


def get_governance_workflow_service(request: Request) -> GovernanceWorkflowService:
    service = getattr(request.app.state, "governance_workflow_service", None)
    if service is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "workflow_not_ready",
                "message": "Governance workflow orchestration is not initialized.",
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
    """Map workflow-domain failures to stable, bounded envelopes."""
    if isinstance(
        exc,
        (
            WorkflowNotFoundError,
            TemplateNotFoundError,
            TaskNotFoundError,
            EscalationNotFoundError,
            ReferenceNotFoundError,
        ),
    ):
        return _http_error(404, "workflow_not_found", str(exc))
    if isinstance(exc, ReferenceUnauthorizedError):
        return _http_error(403, "REFERENCE_UNAUTHORIZED", str(exc))
    if isinstance(
        exc,
        (
            WorkflowStateError,
            TaskStateError,
            EscalationStateError,
            WorkflowVersionConflictError,
            TaskVersionConflictError,
            EscalationVersionConflictError,
            EscalationNotEligibleError,
            SourceCaseMismatchError,
            ReferenceDeletedError,
        ),
    ):
        code = getattr(exc, "code", None) or "workflow_conflict"
        return _http_error(409, str(code), str(exc))
    if isinstance(exc, ReferenceUnavailableError):
        return _http_error(503, "REFERENCE_UNAVAILABLE", str(exc))
    if isinstance(exc, WorkflowConfigError):
        return _http_error(503, "workflow_config_unavailable", str(exc))
    if isinstance(exc, WorkflowDisabledError):
        return _http_error(503, "workflow_disabled", str(exc))
    if isinstance(
        exc,
        (
            WorkflowValidationError,
            TemplateValidationError,
            OwnerValidationError,
            DependencyError,
            WorkflowError,
            ValueError,
        ),
    ):
        return _http_error(422, "workflow_validation_error", str(exc))
    logger.error("unhandled governance workflow error", exc_info=True)
    return _http_error(
        500,
        "internal_error",
        "Governance workflow request failed.",
    )


# ---------------------------------------------------------------------------
# Status and ownership reporting
# ---------------------------------------------------------------------------
@router.get("/status", summary="Read governance workflow orchestration status")
def workflow_status(
    _principal: Principal = Depends(require_capability_dep("governance_workflow_read")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    try:
        return service.status()
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/ownership", summary="Read unassigned and overdue workflow ownership")
def workflow_ownership(
    _principal: Principal = Depends(require_capability_dep("governance_workflow_read")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    try:
        return service.ownership_report()
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
@router.get("/templates", summary="List versioned workflow templates")
def list_templates(
    template_key: str | None = Query(default=None, max_length=64),
    status: str | None = Query(default=None, max_length=16),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_workflow_read")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    try:
        return service.list_templates(
            template_key=template_key,
            status=status,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/templates", summary="Create a versioned workflow template")
def create_template(
    payload: WorkflowTemplateCreateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_workflow_template_manage")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.create_template(
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post(
    "/templates/{template_key}/versions",
    summary="Create a new version of a workflow template",
)
def create_template_version(
    template_key: str,
    payload: WorkflowTemplateVersionRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_workflow_template_manage")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.create_template_version(
            template_key,
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/templates/{template_id}", summary="Read one workflow template")
def template_detail(
    template_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_workflow_detail_read")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    try:
        return service.template_detail(template_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post(
    "/templates/{template_id}/disable",
    summary="Disable a workflow template without affecting existing workflows",
)
def disable_template(
    template_id: str,
    payload: WorkflowTemplateDisableRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_workflow_template_manage")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.disable_template(
            template_id,
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Workflows
# ---------------------------------------------------------------------------
@router.get("/workflows", summary="List governance workflow instances")
def list_workflows(
    status: str | None = Query(default=None, max_length=16),
    owner_id: str | None = Query(default=None, max_length=256),
    case_id: str | None = Query(default=None, max_length=36),
    unassigned: bool = Query(default=False),
    overdue: bool = Query(default=False),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_workflow_read")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    try:
        return service.list_workflows(
            status=status,
            owner_id=owner_id,
            case_id=case_id,
            unassigned=unassigned,
            overdue=overdue,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post("/workflows", summary="Instantiate a workflow from a template version")
def create_workflow(
    payload: WorkflowCreateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_workflow_create")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.create_workflow(
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/workflows/{workflow_id}", summary="Read one workflow with tasks and history")
def workflow_detail(
    workflow_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_workflow_detail_read")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    try:
        return service.workflow_detail(workflow_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post(
    "/workflows/{workflow_id}/transitions",
    summary="Apply a strict workflow lifecycle transition",
)
def transition_workflow(
    workflow_id: str,
    payload: WorkflowTransitionRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_workflow_transition")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.transition_workflow(
            workflow_id,
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post(
    "/workflows/{workflow_id}/assignments",
    summary="Assign or reassign a workflow owner with a mandatory reason",
)
def assign_workflow(
    workflow_id: str,
    payload: WorkflowAssignRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_workflow_assign")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.assign_workflow(
            workflow_id,
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/workflows/{workflow_id}/events", summary="Read append-only workflow events")
def workflow_events(
    workflow_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_workflow_audit_read")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    try:
        detail = service.workflow_detail(workflow_id)
        return {
            "workflow_id": workflow_id,
            "events": detail["events"],
            "non_claims": detail["non_claims"],
        }
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------
@router.get("/tasks", summary="List workflow tasks across workflows")
def list_tasks(
    workflow_id: str | None = Query(default=None, max_length=36),
    status: str | None = Query(default=None, max_length=16),
    owner_id: str | None = Query(default=None, max_length=256),
    unassigned: bool = Query(default=False),
    overdue: bool = Query(default=False),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_workflow_read")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    try:
        return service.list_tasks(
            workflow_id=workflow_id,
            status=status,
            owner_id=owner_id,
            unassigned=unassigned,
            overdue=overdue,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get("/workflows/{workflow_id}/tasks", summary="List tasks for one workflow")
def workflow_tasks(
    workflow_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_workflow_detail_read")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    try:
        detail = service.workflow_detail(workflow_id)
        return {
            "workflow_id": workflow_id,
            "items": detail["tasks"],
            "dependencies": detail["dependencies"],
            "non_claims": detail["non_claims"],
        }
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post(
    "/workflows/{workflow_id}/tasks/{task_id}/transitions",
    summary="Apply a strict task lifecycle transition",
)
def transition_task(
    workflow_id: str,
    task_id: str,
    payload: WorkflowTaskTransitionRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_workflow_task_write")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.transition_task(
            workflow_id,
            task_id,
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post(
    "/workflows/{workflow_id}/tasks/{task_id}/assignments",
    summary="Assign or reassign a task owner with a mandatory reason",
)
def assign_task(
    workflow_id: str,
    task_id: str,
    payload: WorkflowTaskAssignRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_workflow_assign")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.assign_task(
            workflow_id,
            task_id,
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Cross-domain references
# ---------------------------------------------------------------------------
@router.get(
    "/workflows/{workflow_id}/references",
    summary="List read-only cross-domain workflow references",
)
def list_references(
    workflow_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_workflow_detail_read")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    try:
        return service.list_references(workflow_id)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post(
    "/workflows/{workflow_id}/references",
    summary="Attach a validated read-only cross-domain reference",
)
def add_reference(
    workflow_id: str,
    payload: WorkflowReferenceCreateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_workflow_task_write")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.add_reference(
            workflow_id,
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# Escalations
# ---------------------------------------------------------------------------
@router.get("/escalations", summary="List workflow escalations")
def list_escalations(
    workflow_id: str | None = Query(default=None, max_length=36),
    status: str | None = Query(default=None, max_length=16),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    _principal: Principal = Depends(require_capability_dep("governance_workflow_detail_read")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    try:
        return service.list_escalations(
            workflow_id=workflow_id,
            status=status,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.get(
    "/workflows/{workflow_id}/escalations",
    summary="List escalations for one workflow",
)
def workflow_escalations(
    workflow_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_workflow_detail_read")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    try:
        return service.list_escalations(workflow_id=workflow_id, page=1, page_size=100)
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post(
    "/workflows/{workflow_id}/escalations",
    summary="Create a reasoned, idempotent workflow escalation",
)
def create_escalation(
    workflow_id: str,
    payload: WorkflowEscalationCreateRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_workflow_escalate")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.create_escalation(
            workflow_id,
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post(
    "/escalations/{escalation_id}/acknowledge",
    summary="Acknowledge a workflow escalation",
)
def acknowledge_escalation(
    escalation_id: str,
    payload: WorkflowEscalationAcknowledgeRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_workflow_escalate")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.acknowledge_escalation(
            escalation_id,
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


@router.post(
    "/escalations/{escalation_id}/resolve",
    summary="Resolve a workflow escalation with a resolution",
)
def resolve_escalation(
    escalation_id: str,
    payload: WorkflowEscalationResolveRequest,
    request: Request,
    principal: Principal = Depends(require_capability_dep("governance_workflow_escalate")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    actor_id, actor_role = _actor(principal)
    try:
        return service.resolve_escalation(
            escalation_id,
            payload.model_dump(),
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=_request_id(request),
        )
    except Exception as exc:
        raise _handle_error(exc) from None


# ---------------------------------------------------------------------------
# SLA
# ---------------------------------------------------------------------------
@router.get(
    "/workflows/{workflow_id}/sla",
    summary="Read deterministic workflow and task SLA indicators",
)
def workflow_sla(
    workflow_id: str,
    _principal: Principal = Depends(require_capability_dep("governance_workflow_read")),
    service: GovernanceWorkflowService = Depends(get_governance_workflow_service),
) -> dict[str, Any]:
    try:
        return service.workflow_sla(workflow_id)
    except Exception as exc:
        raise _handle_error(exc) from None
