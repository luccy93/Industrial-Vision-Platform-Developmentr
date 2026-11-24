"""V39 enterprise governance workflow foundation tests.

Synthetic, deterministic, local-only. These tests exercise template validation
and version preservation, strict lifecycle transitions, deterministic
dependency evaluation, ownership, escalations, read-only cross-domain
references, pagination, concurrency, idempotency, redaction, metrics, RBAC, and
the forbidden delete-route surface. No live PostgreSQL, Redis, Docker, SMTP,
webhook, or external service is contacted.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.core.metrics import (
    metrics_payload,
    record_governance_workflow_escalation,
    record_governance_workflow_transition,
    set_governance_workflow_counts,
    set_governance_workflow_overdue,
    set_governance_workflow_sla,
)
from backend.app.forensics.repository import ForensicRepository
from backend.app.governance.workflows.constants import (
    REQUIRED_WORKFLOW_EVENT_TYPES,
    WORKFLOW_SLA_STATE_VALUES,
)
from backend.app.governance.workflows.dependencies import validate_template_definition
from backend.app.governance.workflows.errors import (
    DependencyError,
    EscalationNotEligibleError,
    EscalationStateError,
    OwnerValidationError,
    ReferenceDeletedError,
    ReferenceNotFoundError,
    ReferenceUnauthorizedError,
    ReferenceUnavailableError,
    SourceCaseMismatchError,
    TaskStateError,
    TemplateValidationError,
    WorkflowStateError,
    WorkflowValidationError,
    WorkflowVersionConflictError,
)
from backend.app.governance.workflows.repository import GovernanceWorkflowRepository
from backend.app.governance.workflows.service import GovernanceWorkflowService
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.tests.auth_helpers import create_test_user

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
_SECRET_TOKEN = "ghp_" + "A" * 36


class _AuditSink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record_access(self, **kwargs: Any) -> None:
        self.events.append(dict(kwargs))


class _Source:
    """Small deterministic source-domain stub for read-only references."""

    def __init__(self, records: dict[str, Any] | None = None, *, error: Exception | None = None) -> None:
        self.records = records or {}
        self.error = error

    def _read(self, key: str) -> Any:
        if self.error is not None:
            raise self.error
        return self.records.get(key)


class _ExecutiveSource(_Source):
    def get_action(self, action_id: str) -> Any:
        return self._read(action_id)


class _IntelligenceSource(_Source):
    def get_recommendation(self, recommendation_id: str) -> Any:
        return self._read(recommendation_id)


class _AutomationSource(_Source):
    def get_job(self, job_id: str) -> Any:
        return self._read(job_id)


class _GovernanceSource(_Source):
    def get_evaluation(self, evaluation_id: str) -> Any:
        return self._read(evaluation_id)

    def get_hold(self, hold_id: str) -> Any:
        return self._read(hold_id)

    def get_disposition(self, disposition_id: str) -> Any:
        return self._read(disposition_id)

    def get_export_approval(self, approval_id: str) -> Any:
        return self._read(approval_id)


class _IntegritySource(_Source):
    def get_finding(self, finding_id: str) -> Any:
        return self._read(finding_id)


def _settings() -> Any:
    return SimpleNamespace(
        governance_enabled=True,
        governance_workflow_enabled=True,
        governance_workflow_page_size=20,
        governance_workflow_max_active_sample=500,
        governance_workflow_default_warning_hours=24,
    )


def _build_service(
    tmp_path: Any,
    *,
    executive: Any = None,
    intelligence: Any = None,
    automation: Any = None,
    governance: Any = None,
    integrity: Any = None,
    notifier: Any = None,
) -> tuple[
    GovernanceWorkflowService, GovernanceWorkflowRepository, ForensicRepository, AuthRepository, _AuditSink
]:
    Path(tmp_path).mkdir(parents=True, exist_ok=True)
    url = f"sqlite:///{tmp_path}/v39-foundation.db"
    init_db(url)
    factory = get_session_factory(url)
    auth = AuthRepository(factory)
    create_test_user(auth, "admin@example.com", role=Role.ADMIN)
    create_test_user(auth, "operator@example.com", role=Role.OPERATOR)
    create_test_user(auth, "viewer@example.com", role=Role.VIEWER)
    audit = _AuditSink()
    forensic = ForensicRepository(factory)
    repository = GovernanceWorkflowRepository(factory)
    service = GovernanceWorkflowService(
        settings=_settings(),
        repository=repository,
        governance_service=audit,
        forensic_repository=forensic,
        integrity_store=integrity,
        governance_repository=governance,
        automation_repository=automation,
        intelligence_repository=intelligence,
        executive_repository=executive,
        auth_repository=auth,
        notifier=notifier,
        clock=lambda: NOW,
    )
    return service, repository, forensic, auth, audit


def _template_payload(
    *,
    key: str,
    idempotency_key: str,
    tasks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "template_key": key,
        "name": f"Template {key}",
        "description": "Synthetic workflow template.",
        "tasks": tasks
        or [
            {"task_key": "intake", "title": "Intake", "depends_on": []},
            {"task_key": "review", "title": "Review", "depends_on": ["intake"]},
        ],
        "reason": "Synthetic template for deterministic tests.",
        "idempotency_key": idempotency_key,
    }


def _create_template(service: GovernanceWorkflowService, *, key: str = "CASE_REVIEW") -> dict[str, Any]:
    return service.create_template(
        _template_payload(key=key, idempotency_key=f"template-{key}-v1"),
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )["template"]


def _create_workflow(
    service: GovernanceWorkflowService,
    template_id: str,
    *,
    key: str,
    case_id: str | None = None,
    owner_type: str | None = None,
    owner_id: str | None = None,
    due_at: str | None = None,
    description: str = "Synthetic workflow.",
) -> dict[str, Any]:
    return service.create_workflow(
        {
            "template_id": template_id,
            "case_id": case_id,
            "title": "Synthetic case review",
            "description": description,
            "priority": "HIGH",
            "due_at": due_at,
            "owner_type": owner_type,
            "owner_id": owner_id,
            "idempotency_key": key,
            "reason": "Synthetic workflow creation.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )


def _transition(
    service: GovernanceWorkflowService,
    workflow_id: str,
    target: str,
    version: int,
    **extra: Any,
) -> dict[str, Any]:
    return service.transition_workflow(
        workflow_id,
        {"target_status": target, "expected_version": version, **extra},
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )


def _task(service: GovernanceWorkflowService, workflow_id: str, task_key: str) -> dict[str, Any]:
    detail = service.workflow_detail(workflow_id)
    return next(item for item in detail["tasks"] if item["task_key"] == task_key)


def _assign_task(
    service: GovernanceWorkflowService,
    workflow_id: str,
    task: dict[str, Any],
    *,
    owner_type: str = "USER",
    owner_id: str = "operator@example.com",
    reason: str = "Assign the task owner.",
) -> dict[str, Any]:
    return service.assign_task(
        workflow_id,
        task["task_id"],
        {
            "owner_type": owner_type,
            "owner_id": owner_id,
            "expected_version": task["version"],
            "reason": reason,
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )


def _start_and_complete(
    service: GovernanceWorkflowService,
    workflow_id: str,
    task_key: str,
    *,
    outcome: str = "Task completed with recorded evidence.",
) -> dict[str, Any]:
    task = _task(service, workflow_id, task_key)
    if task["owner_id"] is None:
        _assign_task(service, workflow_id, task)
        task = _task(service, workflow_id, task_key)
    if task["status"] == "READY":
        task = service.transition_task(
            workflow_id,
            task["task_id"],
            {
                "target_status": "IN_PROGRESS",
                "expected_version": task["version"],
                "reason": "Start the task.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )["task"]
    return service.transition_task(
        workflow_id,
        task["task_id"],
        {
            "target_status": "COMPLETED",
            "expected_version": task["version"],
            "reason": "Complete the task.",
            "outcome_summary": outcome,
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )["task"]


# ---------------------------------------------------------------------------
# Template validation and version preservation
# ---------------------------------------------------------------------------
def test_template_validation_rejects_cycles_unknown_dependencies_and_duplicates() -> None:
    with pytest.raises(TemplateValidationError):
        validate_template_definition(
            {
                "tasks": [
                    {"task_key": "alpha", "title": "Alpha", "depends_on": ["beta"]},
                    {"task_key": "beta", "title": "Beta", "depends_on": ["alpha"]},
                ]
            }
        )
    with pytest.raises(DependencyError):
        validate_template_definition(
            {"tasks": [{"task_key": "alpha", "title": "Alpha", "depends_on": ["missing"]}]}
        )
    with pytest.raises(TemplateValidationError):
        validate_template_definition(
            {
                "tasks": [
                    {"task_key": "alpha", "title": "Alpha"},
                    {"task_key": "alpha", "title": "Alpha again"},
                ]
            }
        )


def test_template_versions_preserve_prior_definitions_and_workflow_snapshots(tmp_path: Any) -> None:
    service, repository, _, _, _ = _build_service(tmp_path)
    v1 = _create_template(service)
    original_definition = dict(v1["definition"])
    original_digest = v1["definition_digest"]

    v2 = service.create_template_version(
        "CASE_REVIEW",
        {
            "name": "Template CASE_REVIEW v2",
            "tasks": [
                {"task_key": "intake", "title": "Intake"},
                {"task_key": "review", "title": "Review", "depends_on": ["intake"]},
                {"task_key": "approve", "title": "Approve", "depends_on": ["review"]},
            ],
            "reason": "Add an explicit review step.",
            "idempotency_key": "template-CASE_REVIEW-v2",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )["template"]

    assert v2["version"] == 2
    assert v2["status"] == "ACTIVE"
    assert v2["task_count"] == 3
    assert repository.get_template(v1["template_id"])["status"] == "SUPERSEDED"
    assert repository.get_template(v1["template_id"])["definition"] == original_definition
    assert repository.get_template(v1["template_id"])["definition_digest"] == original_digest

    workflow = _create_workflow(service, v1["template_id"], key="pinned-v1")
    assert workflow["workflow"]["template_version"] == 1
    assert workflow["workflow"]["template_digest"] == original_digest
    assert workflow["workflow"]["template_snapshot"]["definition_digest"] == original_digest


def test_template_disable_is_terminal_and_does_not_change_existing_workflows(tmp_path: Any) -> None:
    service, _, _, _, _ = _build_service(tmp_path)
    template = _create_template(service)
    workflow = _create_workflow(service, template["template_id"], key="before-disable")

    disabled = service.disable_template(
        template["template_id"],
        {"reason": "Retire the synthetic template."},
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert disabled["template"]["status"] == "DISABLED"
    assert disabled["changed"] is True
    assert service.workflow_detail(workflow["workflow"]["workflow_id"])["workflow"]["template_version"] == 1
    with pytest.raises(WorkflowValidationError):
        service.create_workflow(
            {
                "template_id": template["template_id"],
                "title": "Disabled template workflow",
                "idempotency_key": "disabled-template",
                "reason": "This must fail.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


# ---------------------------------------------------------------------------
# Lifecycle, dependencies, completion, blocking, cancellation
# ---------------------------------------------------------------------------
def test_workflow_and_task_lifecycle_is_strict_and_dependency_driven(tmp_path: Any) -> None:
    service, _, _, _, _ = _build_service(tmp_path)
    template = _create_template(service)
    created = _create_workflow(service, template["template_id"], key="lifecycle")
    workflow_id = created["workflow"]["workflow_id"]

    assert created["workflow"]["status"] == "DRAFT"
    assert {task["status"] for task in created["tasks"]} == {"PENDING"}

    _transition(service, workflow_id, "READY", 1)
    started = _transition(service, workflow_id, "IN_PROGRESS", 2)
    by_key = {task["task_key"]: task for task in started["tasks"]}
    assert by_key["intake"]["status"] == "READY"
    assert by_key["review"]["status"] == "PENDING"

    with pytest.raises(WorkflowStateError):
        _transition(service, workflow_id, "UNDER_REVIEW", 3, reason="Too early.")

    _start_and_complete(service, workflow_id, "intake")
    assert _task(service, workflow_id, "review")["status"] == "READY"
    _start_and_complete(service, workflow_id, "review")

    review = _transition(service, workflow_id, "UNDER_REVIEW", 3)
    assert review["workflow"]["status"] == "UNDER_REVIEW"
    with pytest.raises(WorkflowValidationError):
        _transition(service, workflow_id, "COMPLETED", 4)
    completed = _transition(
        service,
        workflow_id,
        "COMPLETED",
        4,
        outcome_summary="All mandatory review tasks completed.",
    )
    assert completed["workflow"]["status"] == "COMPLETED"
    assert completed["workflow"]["terminal"] is True
    with pytest.raises(WorkflowStateError):
        _transition(service, workflow_id, "IN_PROGRESS", 5)
    with pytest.raises(TaskStateError):
        service.transition_task(
            workflow_id,
            _task(service, workflow_id, "intake")["task_id"],
            {
                "target_status": "IN_PROGRESS",
                "expected_version": _task(service, workflow_id, "intake")["version"],
                "reason": "Reopening is not supported.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


def test_blocking_requires_reason_and_pauses_sla_and_cancellation_is_terminal(tmp_path: Any) -> None:
    service, _, _, _, _ = _build_service(tmp_path)
    template = _create_template(service)
    workflow_id = _create_workflow(service, template["template_id"], key="block-cancel")["workflow"][
        "workflow_id"
    ]
    _transition(service, workflow_id, "READY", 1)
    _transition(service, workflow_id, "IN_PROGRESS", 2)

    with pytest.raises(WorkflowValidationError):
        _transition(service, workflow_id, "BLOCKED", 3)
    blocked = _transition(service, workflow_id, "BLOCKED", 3, reason="Awaiting external legal review.")
    assert blocked["workflow"]["status"] == "BLOCKED"
    assert blocked["sla"]["state"] == "PAUSED"
    with pytest.raises(TaskStateError):
        service.transition_task(
            workflow_id,
            _task(service, workflow_id, "intake")["task_id"],
            {
                "target_status": "IN_PROGRESS",
                "expected_version": _task(service, workflow_id, "intake")["version"],
                "reason": "Blocked workflow writes are rejected.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    _transition(service, workflow_id, "IN_PROGRESS", 4, reason="External review returned.")
    with pytest.raises(WorkflowValidationError):
        _transition(service, workflow_id, "CANCELLED", 5)
    cancelled = _transition(
        service, workflow_id, "CANCELLED", 5, reason="Workflow superseded by a new case plan."
    )
    assert cancelled["workflow"]["status"] == "CANCELLED"
    assert cancelled["sla"]["state"] == "NOT_APPLICABLE"
    assert {task["status"] for task in cancelled["tasks"]} == {"CANCELLED"}


def test_completion_requires_all_mandatory_tasks_even_when_optional_tasks_remain(tmp_path: Any) -> None:
    service, _, _, _, _ = _build_service(tmp_path)
    template = service.create_template(
        _template_payload(
            key="MANDATORY_ONLY",
            idempotency_key="template-mandatory-only",
            tasks=[
                {"task_key": "required", "title": "Required", "required": True},
                {"task_key": "optional", "title": "Optional", "required": False},
            ],
        ),
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )["template"]
    workflow_id = _create_workflow(service, template["template_id"], key="mandatory-only")["workflow"][
        "workflow_id"
    ]
    _transition(service, workflow_id, "READY", 1)
    _transition(service, workflow_id, "IN_PROGRESS", 2)
    _start_and_complete(service, workflow_id, "required")
    _transition(service, workflow_id, "UNDER_REVIEW", 3)
    completed = _transition(
        service,
        workflow_id,
        "COMPLETED",
        4,
        outcome_summary="Mandatory work is complete; optional follow-up remains advisory.",
    )
    optional = next(task for task in completed["tasks"] if task["task_key"] == "optional")
    assert optional["status"] == "READY"
    assert completed["workflow"]["status"] == "COMPLETED"


# ---------------------------------------------------------------------------
# Ownership and reassignment
# ---------------------------------------------------------------------------
def test_ownership_assignment_reassignment_and_history(tmp_path: Any) -> None:
    service, _, _, _, _ = _build_service(tmp_path)
    template = _create_template(service)
    workflow_id = _create_workflow(service, template["template_id"], key="ownership")["workflow"][
        "workflow_id"
    ]

    assigned = service.assign_workflow(
        workflow_id,
        {
            "owner_type": "ROLE",
            "owner_id": "OPERATOR",
            "expected_version": 1,
            "reason": "Route to the operations queue.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert assigned["workflow"]["owner_type"] == "ROLE"
    assert assigned["workflow"]["owner_id"] == "OPERATOR"

    reassigned = service.assign_workflow(
        workflow_id,
        {
            "owner_type": "USER",
            "owner_id": "operator@example.com",
            "expected_version": 2,
            "reason": "Assign a named accountable operator.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert reassigned["workflow"]["owner_id"] == "operator@example.com"
    detail = service.workflow_detail(workflow_id)
    assert [event["event_type"] for event in detail["ownership_history"]] == [
        "WORKFLOW_ASSIGNED",
        "WORKFLOW_REASSIGNED",
    ]

    with pytest.raises(OwnerValidationError):
        service.assign_workflow(
            workflow_id,
            {
                "owner_type": "USER",
                "owner_id": "missing@example.com",
                "expected_version": 3,
                "reason": "This owner does not exist.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    with pytest.raises(OwnerValidationError):
        service.assign_workflow(
            workflow_id,
            {
                "owner_type": "ROLE",
                "owner_id": "SUPERUSER",
                "expected_version": 3,
                "reason": "This role does not exist.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


def test_task_assignment_requires_reason_and_is_rejected_after_terminal_state(tmp_path: Any) -> None:
    service, _, _, _, _ = _build_service(tmp_path)
    template = _create_template(service)
    workflow_id = _create_workflow(service, template["template_id"], key="task-ownership")["workflow"][
        "workflow_id"
    ]
    task = _task(service, workflow_id, "intake")
    with pytest.raises(WorkflowValidationError):
        service.assign_task(
            workflow_id,
            task["task_id"],
            {
                "owner_type": "USER",
                "owner_id": "operator@example.com",
                "expected_version": task["version"],
                "reason": "",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    _transition(service, workflow_id, "READY", 1)
    _transition(service, workflow_id, "IN_PROGRESS", 2)
    _assign_task(service, workflow_id, _task(service, workflow_id, "intake"))
    _start_and_complete(service, workflow_id, "intake")
    _start_and_complete(service, workflow_id, "review")
    _transition(service, workflow_id, "UNDER_REVIEW", 3)
    _transition(
        service,
        workflow_id,
        "COMPLETED",
        4,
        outcome_summary="Completed before the terminal assignment check.",
    )
    terminal_task = _task(service, workflow_id, "intake")
    with pytest.raises(TaskStateError):
        service.assign_task(
            workflow_id,
            terminal_task["task_id"],
            {
                "owner_type": "USER",
                "owner_id": "operator@example.com",
                "expected_version": terminal_task["version"],
                "reason": "Terminal tasks cannot be reassigned.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


# ---------------------------------------------------------------------------
# Escalations
# ---------------------------------------------------------------------------
def test_escalations_are_reasoned_idempotent_eligible_and_transition_strictly(tmp_path: Any) -> None:
    service, _, _, _, _ = _build_service(tmp_path)
    template = _create_template(service)
    workflow_id = _create_workflow(
        service,
        template["template_id"],
        key="escalation",
        owner_type="ROLE",
        owner_id="OPERATOR",
    )["workflow"]["workflow_id"]
    _transition(service, workflow_id, "READY", 1)
    _transition(service, workflow_id, "IN_PROGRESS", 2)

    with pytest.raises(EscalationNotEligibleError):
        service.create_escalation(
            workflow_id,
            {
                "escalation_type": "UNASSIGNED",
                "severity": "MEDIUM",
                "reason": "The workflow is assigned.",
                "idempotency_key": "escalation-unassigned",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    with pytest.raises(EscalationNotEligibleError):
        service.create_escalation(
            workflow_id,
            {
                "escalation_type": "SLA_OVERDUE",
                "severity": "HIGH",
                "reason": "The workflow has no due date.",
                "idempotency_key": "escalation-overdue",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )

    created = service.create_escalation(
        workflow_id,
        {
            "escalation_type": "MANUAL",
            "severity": "HIGH",
            "reason": "Operations requested a review of the evidence backlog.",
            "idempotency_key": "escalation-manual",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    escalation_id = created["escalation"]["escalation_id"]
    assert created["escalation"]["status"] == "OPEN"
    replay = service.create_escalation(
        workflow_id,
        {
            "escalation_type": "MANUAL",
            "severity": "HIGH",
            "reason": "Operations requested a review of the evidence backlog.",
            "idempotency_key": "escalation-manual",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert replay["replayed"] is True
    assert replay["escalation"]["escalation_id"] == escalation_id

    acknowledged = service.acknowledge_escalation(
        escalation_id,
        {"expected_version": 1, "reason": "Operations acknowledged the review."},
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert acknowledged["escalation"]["status"] == "ACKNOWLEDGED"
    resolved = service.resolve_escalation(
        escalation_id,
        {
            "expected_version": 2,
            "reason": "The review completed.",
            "resolution": "Backlog was triaged without changing any source record.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert resolved["escalation"]["status"] == "RESOLVED"
    with pytest.raises(EscalationStateError):
        service.resolve_escalation(
            escalation_id,
            {
                "expected_version": 3,
                "reason": "This must fail.",
                "resolution": "No second resolution is allowed.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )

    blocked = _transition(service, workflow_id, "BLOCKED", 3, reason="Awaiting source-domain clarification.")
    assert blocked["workflow"]["status"] == "BLOCKED"
    eligible = service.create_escalation(
        workflow_id,
        {
            "escalation_type": "BLOCKED",
            "severity": "HIGH",
            "reason": "The workflow is blocked.",
            "idempotency_key": "escalation-blocked",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert eligible["escalation"]["escalation_type"] == "BLOCKED"


# ---------------------------------------------------------------------------
# Cross-domain references
# ---------------------------------------------------------------------------
def _case(forensic: ForensicRepository, title: str) -> str:
    case, _ = forensic.create_case(title=title, description="Synthetic V39 reference case.")
    return str(case["case_id"])


def test_cross_domain_references_are_validated_read_only_and_case_bounded(tmp_path: Any) -> None:
    executive = _ExecutiveSource(
        {
            "action-v39": {
                "action_id": "action-v39",
                "status": "IN_PROGRESS",
                "title": "Executive follow-up",
                "version": 2,
            }
        }
    )
    governance = _GovernanceSource(
        {
            "review-other": {
                "evaluation_id": "review-other",
                "case_id": "other-case",
                "status": "COMPLETED",
                "governance_state": "REVIEW_COMPLETE",
            }
        }
    )
    service, _, forensic, _, _ = _build_service(tmp_path, executive=executive, governance=governance)
    case_id = _case(forensic, "V39 reference case")
    template = _create_template(service)
    workflow_id = _create_workflow(service, template["template_id"], key="references", case_id=case_id)[
        "workflow"
    ]["workflow_id"]

    added = service.add_reference(
        workflow_id,
        {
            "domain": "FORENSIC_CASE",
            "source_id": case_id,
            "reason": "Link the workflow to its forensic case.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert added["reference"]["availability"] == "AVAILABLE"
    assert added["reference"]["source_case_id"] == case_id
    assert added["source_mutated"] is False
    assert forensic.get_case(case_id)["title"] == "V39 reference case"

    replay = service.add_reference(
        workflow_id,
        {
            "domain": "FORENSIC_CASE",
            "source_id": case_id,
            "reason": "Replay the same reference.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert replay["replayed"] is True
    assert len(service.list_references(workflow_id)["items"]) == 1

    action_reference = service.add_reference(
        workflow_id,
        {
            "domain": "EXECUTIVE_ACTION",
            "source_id": "action-v39",
            "reason": "Link the advisory executive follow-up.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert action_reference["reference"]["source_status"] == "IN_PROGRESS"

    with pytest.raises(ReferenceNotFoundError):
        service.add_reference(
            workflow_id,
            {
                "domain": "EXECUTIVE_ACTION",
                "source_id": "missing-action",
                "reason": "This source does not exist.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    with pytest.raises(ReferenceUnauthorizedError):
        service.add_reference(
            workflow_id,
            {
                "domain": "EXECUTIVE_ACTION",
                "source_id": "action-v39",
                "reason": "A viewer lacks the executive action capability.",
            },
            actor_id="viewer@example.com",
            actor_role="VIEWER",
        )
    with pytest.raises(SourceCaseMismatchError):
        service.add_reference(
            workflow_id,
            {
                "domain": "RETENTION_REVIEW",
                "source_id": "review-other",
                "reason": "This source belongs to another case.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


def test_reference_states_distinguish_missing_unavailable_deleted_and_terminal(tmp_path: Any) -> None:
    service, _, forensic, _, _ = _build_service(
        tmp_path,
        executive=_ExecutiveSource(error=RuntimeError("synthetic source outage")),
    )
    case_id = _case(forensic, "V39 state case")
    template = _create_template(service)
    workflow_id = _create_workflow(service, template["template_id"], key="reference-states", case_id=case_id)[
        "workflow"
    ]["workflow_id"]
    with pytest.raises(ReferenceUnavailableError):
        service.add_reference(
            workflow_id,
            {
                "domain": "EXECUTIVE_ACTION",
                "source_id": "action-v39",
                "reason": "The source is unavailable.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )

    deleted_service, _, deleted_forensic, _, _ = _build_service(
        tmp_path / "deleted",
        executive=_ExecutiveSource({"action-deleted": {"action_id": "action-deleted", "status": "DELETED"}}),
    )
    deleted_case = _case(deleted_forensic, "V39 deleted case")
    deleted_template = _create_template(deleted_service, key="DELETED_CASE")
    deleted_workflow = _create_workflow(
        deleted_service,
        deleted_template["template_id"],
        key="deleted-reference",
        case_id=deleted_case,
    )["workflow"]["workflow_id"]
    with pytest.raises(ReferenceDeletedError):
        deleted_service.add_reference(
            deleted_workflow,
            {
                "domain": "EXECUTIVE_ACTION",
                "source_id": "action-deleted",
                "reason": "The source is explicitly deleted.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )

    _transition(deleted_service, deleted_workflow, "READY", 1)
    _transition(deleted_service, deleted_workflow, "IN_PROGRESS", 2)
    _transition(deleted_service, deleted_workflow, "CANCELLED", 3, reason="Terminal test.")
    with pytest.raises(WorkflowValidationError):
        deleted_service.add_reference(
            deleted_workflow,
            {
                "domain": "FORENSIC_CASE",
                "source_id": deleted_case,
                "reason": "Terminal workflows cannot receive references.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


# ---------------------------------------------------------------------------
# Pagination, bounds, status, and SLA honesty
# ---------------------------------------------------------------------------
def test_pagination_bounds_and_invalid_filters(tmp_path: Any) -> None:
    service, _, _, _, _ = _build_service(tmp_path)
    template = _create_template(service)
    for index in range(3):
        _create_workflow(service, template["template_id"], key=f"page-{index}")
    page = service.list_workflows(page=1, page_size=2)
    assert len(page["items"]) == 2
    assert page["total"] == 3
    assert page["page_size"] == 2
    assert service.list_workflows(page=1, page_size=1000)["page_size"] == 100
    with pytest.raises(WorkflowValidationError):
        service.list_workflows(status="HOSTILE")


def test_missing_due_date_is_not_applicable_never_zero(tmp_path: Any) -> None:
    service, _, _, _, _ = _build_service(tmp_path)
    template = _create_template(service)
    no_due = _create_workflow(service, template["template_id"], key="no-due")
    with_due = _create_workflow(
        service,
        template["template_id"],
        key="with-due",
        due_at=(NOW + timedelta(hours=48)).isoformat(),
    )
    no_due_sla = no_due["sla"]
    with_due_sla = with_due["sla"]
    assert no_due_sla["state"] == "NOT_APPLICABLE"
    assert no_due_sla["target_hours"] is None
    assert no_due_sla["elapsed_hours"] is None
    assert with_due_sla["state"] == "NOT_APPLICABLE"  # DRAFT has no operational clock yet
    assert with_due_sla["due_at"] is not None

    _transition(service, no_due["workflow"]["workflow_id"], "READY", 1)
    ready_sla = service.workflow_sla(no_due["workflow"]["workflow_id"])
    assert ready_sla["workflow"]["state"] == "NOT_APPLICABLE"
    assert set(ready_sla["counts"]) == set(WORKFLOW_SLA_STATE_VALUES) | {"UNKNOWN"}
    status = service.status()
    assert status["sla_counts"]["NOT_APPLICABLE"] >= 1
    assert status["overdue"]["workflows"] == 0


def test_status_reports_counts_unassigned_and_overdue(tmp_path: Any) -> None:
    service, _, _, _, _ = _build_service(tmp_path)
    template = _create_template(service)
    _create_workflow(service, template["template_id"], key="unassigned")
    overdue = _create_workflow(
        service,
        template["template_id"],
        key="overdue",
        due_at=(NOW - timedelta(hours=1)).isoformat(),
    )
    _transition(service, overdue["workflow"]["workflow_id"], "READY", 1)
    status = service.status()
    assert status["workflow_counts"]["DRAFT"] >= 1
    assert status["workflow_counts"]["READY"] >= 1
    assert status["unassigned"]["workflows"] >= 2
    assert status["overdue"]["workflows"] >= 1
    assert status["task_total"] >= 4
    assert status["scheduled_workflows"] is False


# ---------------------------------------------------------------------------
# Idempotency and concurrency
# ---------------------------------------------------------------------------
def test_concurrent_workflow_creation_is_idempotent_and_audited_once(tmp_path: Any) -> None:
    service, repository, _, _, audit = _build_service(tmp_path)
    template = _create_template(service)

    def create() -> dict[str, Any]:
        return _create_workflow(service, template["template_id"], key="concurrent-create")

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = [future.result() for future in [pool.submit(create) for _ in range(4)]]

    ids = {result["workflow"]["workflow_id"] for result in results}
    assert len(ids) == 1
    assert repository.count_workflows() == 1
    events = repository.workflow_events(ids.pop())
    assert [event["event_type"] for event in events].count("WORKFLOW_CREATED") == 1
    assert len([event for event in audit.events if event["event_type"] == "WORKFLOW_CREATED"]) == 1


def test_concurrent_transition_applies_once_and_conflicts_once(tmp_path: Any) -> None:
    service, _, _, _, _ = _build_service(tmp_path)
    template = _create_template(service)
    workflow_id = _create_workflow(service, template["template_id"], key="concurrent-transition")["workflow"][
        "workflow_id"
    ]

    def transition() -> str:
        try:
            _transition(service, workflow_id, "READY", 1)
            return "APPLIED"
        except WorkflowVersionConflictError:
            return "CONFLICT"

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = [future.result() for future in [pool.submit(transition) for _ in range(4)]]

    assert outcomes.count("APPLIED") == 1
    assert outcomes.count("CONFLICT") == 3
    assert service.workflow_detail(workflow_id)["workflow"]["status"] == "READY"


# ---------------------------------------------------------------------------
# Redaction and event contract
# ---------------------------------------------------------------------------
def test_workflow_text_and_events_redact_credentials(tmp_path: Any) -> None:
    service, repository, _, _, _ = _build_service(tmp_path)
    template = _create_template(service)
    created = _create_workflow(
        service,
        template["template_id"],
        key="redaction",
        description=f"Workflow notes containing {_SECRET_TOKEN} must be redacted.",
    )
    workflow_id = created["workflow"]["workflow_id"]
    stored = repository.get_workflow(workflow_id)
    assert _SECRET_TOKEN not in stored["description"]
    assert "[REDACTED]" in stored["description"]

    _transition(
        service,
        workflow_id,
        "READY",
        1,
        reason=f"Approved using token {_SECRET_TOKEN}.",
    )
    detail = service.workflow_detail(workflow_id)
    assert _SECRET_TOKEN not in str(detail["events"])
    assert all(_SECRET_TOKEN not in str(event.get("detail")) for event in detail["events"])


def test_required_event_contract_is_exposed() -> None:
    from backend.app.governance.workflows.constants import WORKFLOW_EVENT_VALUES

    assert REQUIRED_WORKFLOW_EVENT_TYPES <= set(WORKFLOW_EVENT_VALUES)


# ---------------------------------------------------------------------------
# Bounded metrics
# ---------------------------------------------------------------------------
def test_workflow_metrics_labels_are_bounded() -> None:
    hostile = "V39/SENTINEL/UNBOUNDED"
    set_governance_workflow_counts({hostile: 999, "DRAFT": 1}, {hostile: 999})
    set_governance_workflow_overdue({hostile: 999, "workflow": 2})
    set_governance_workflow_sla({hostile: 999, "ON_TRACK": 1})
    record_governance_workflow_transition(hostile, hostile, hostile, hostile)
    record_governance_workflow_escalation(hostile, hostile, hostile)

    payload = metrics_payload().decode("utf-8")
    assert "SENTINEL" not in payload
    assert 'status="UNKNOWN"' in payload
    assert 'entity="UNKNOWN"' in payload
    assert 'from_status="UNKNOWN"' in payload
    assert 'to_status="UNKNOWN"' in payload
    assert 'outcome="UNKNOWN"' in payload
    assert 'escalation_type="UNKNOWN"' in payload


# ---------------------------------------------------------------------------
# API RBAC and route surface
# ---------------------------------------------------------------------------
def _role_client(client: Any, email: str, role: Role) -> Any:
    from fastapi.testclient import TestClient

    repo = AuthRepository(get_session_factory(str(client.app.state.settings.database_url)))
    create_test_user(repo, email, role=role)
    plain = TestClient(client.app)
    login = plain.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "Fixture-Auth-9-Voltage-Battery!"},
    )
    assert login.status_code == 200, login.text
    plain.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    return plain


def test_api_has_no_delete_route_for_workflow_history(client: Any) -> None:
    from backend.app.api.v1.governance_workflows import router

    routes = list(router.routes)
    assert routes
    assert not [route for route in routes if "DELETE" in set(getattr(route, "methods", set()))]
    assert client.delete("/api/v1/governance/workflows/workflows/any").status_code == 405
    assert client.delete("/api/v1/governance/workflows/templates/any").status_code == 405


def test_api_rbac_viewer_can_read_overview_but_not_write(client: Any) -> None:
    assert client.app.state.governance_workflow_service is not None
    viewer = _role_client(client, "viewer-v39-api@example.com", Role.VIEWER)
    status = viewer.get("/api/v1/governance/workflows/status")
    assert status.status_code == 200, status.text
    assert status.json()["scheduled_workflows"] is False
    assert viewer.get("/api/v1/governance/workflows/workflows").status_code == 200
    assert (
        viewer.post(
            "/api/v1/governance/workflows/templates",
            json=_template_payload(key="VIEWER_TEMPLATE", idempotency_key="viewer-template"),
        ).status_code
        == 403
    )
    assert viewer.get("/api/v1/governance/workflows/workflows/any").status_code == 403

    operator = _role_client(client, "operator-v39-api@example.com", Role.OPERATOR)
    assert (
        operator.post(
            "/api/v1/governance/workflows/templates",
            json=_template_payload(key="OPERATOR_TEMPLATE", idempotency_key="operator-template"),
        ).status_code
        == 403
    )
    assert operator.get("/api/v1/governance/workflows/ownership").status_code == 200


def test_api_template_and_workflow_roundtrip_with_bounded_query_validation(client: Any) -> None:
    created = client.post(
        "/api/v1/governance/workflows/templates",
        json=_template_payload(key="API_TEMPLATE", idempotency_key="api-template-v1"),
    )
    assert created.status_code == 200, created.text
    template_id = created.json()["template"]["template_id"]

    workflow = client.post(
        "/api/v1/governance/workflows/workflows",
        json={
            "template_id": template_id,
            "title": "API synthetic workflow",
            "priority": "MEDIUM",
            "idempotency_key": "api-workflow-v1",
            "reason": "Synthetic API workflow creation.",
        },
    )
    assert workflow.status_code == 200, workflow.text
    workflow_id = workflow.json()["workflow"]["workflow_id"]
    detail = client.get(f"/api/v1/governance/workflows/workflows/{workflow_id}")
    assert detail.status_code == 200
    assert detail.json()["workflow"]["status"] == "DRAFT"

    assert client.get("/api/v1/governance/workflows/workflows", params={"page_size": 1000}).status_code == 422
    assert (
        client.get("/api/v1/governance/workflows/workflows", params={"status": "HOSTILE"}).status_code == 422
    )
    assert (
        client.get("/api/v1/governance/workflows/workflows", params={"page_size": 1}).json()["page_size"] == 1
    )


def test_api_reference_unauthorized_and_missing_use_stable_envelopes(client: Any) -> None:
    created = client.post(
        "/api/v1/governance/workflows/templates",
        json=_template_payload(key="API_REFERENCE", idempotency_key="api-reference-template"),
    )
    assert created.status_code == 200, created.text
    template_id = created.json()["template"]["template_id"]
    workflow = client.post(
        "/api/v1/governance/workflows/workflows",
        json={
            "template_id": template_id,
            "title": "API reference workflow",
            "idempotency_key": "api-reference-workflow",
            "reason": "Synthetic API reference workflow.",
        },
    )
    assert workflow.status_code == 200, workflow.text
    workflow_id = workflow.json()["workflow"]["workflow_id"]

    missing = client.post(
        f"/api/v1/governance/workflows/workflows/{workflow_id}/references",
        json={
            "domain": "EXECUTIVE_ACTION",
            "source_id": "missing-action",
            "reason": "Synthetic missing source.",
        },
    )
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "not_found"
    assert missing.json()["error"]["details"]["code"] == "workflow_not_found"

    viewer = _role_client(client, "viewer-v39-reference@example.com", Role.VIEWER)
    unauthorized = viewer.post(
        f"/api/v1/governance/workflows/workflows/{workflow_id}/references",
        json={
            "domain": "EXECUTIVE_ACTION",
            "source_id": "missing-action",
            "reason": "Synthetic unauthorized source.",
        },
    )
    assert unauthorized.status_code == 403
    # The route-level capability gate rejects the viewer before the service
    # resolves the source. The source-level REFERENCE_UNAUTHORIZED state is
    # exercised by the service tests and remains defense-in-depth.
    assert unauthorized.json()["error"]["code"] == "http_error"
