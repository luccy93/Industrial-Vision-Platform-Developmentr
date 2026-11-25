"""V39 enterprise governance workflow hardening tests.

Synthetic, deterministic, local-only adversarial coverage that complements the
foundation suite: diamond and cancelled dependency graphs, task/workflow
blocking, SLA state boundaries, escalation eligibility and notification gating,
identity-aware ownership, template digest/version pinning, concurrent task and
escalation races, the complete event contract, redaction and sequence ordering,
case isolation, API request bounds and stable conflict envelopes, all supported
cross-domain reference readers, bounded metrics, and honest disabled behavior.

No live PostgreSQL, Redis, Docker, SMTP, webhook, or external service is
contacted. V39 never approves or releases a hold, approves or rejects a
disposition, deletes or modifies evidence, approves or generates an export,
alters custody, resolves a recommendation, or completes a V38 action.
"""

from __future__ import annotations

import copy
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
    record_governance_workflow_creation,
    record_governance_workflow_dependency,
    record_governance_workflow_operation,
)
from backend.app.forensics.repository import ForensicRepository
from backend.app.governance.workflows.constants import (
    MAX_TEMPLATE_TASKS,
    REQUIRED_WORKFLOW_EVENT_TYPES,
)
from backend.app.governance.workflows.dependencies import validate_template_definition
from backend.app.governance.workflows.errors import (
    EscalationNotEligibleError,
    OwnerValidationError,
    TaskNotFoundError,
    TaskStateError,
    TaskVersionConflictError,
    TemplateValidationError,
    WorkflowStateError,
    WorkflowValidationError,
)
from backend.app.governance.workflows.repository import GovernanceWorkflowRepository
from backend.app.governance.workflows.service import GovernanceWorkflowService
from backend.app.governance.workflows.sla import evaluate_sla
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.tests.auth_helpers import create_test_user

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
_SECRET_TOKEN = "ghp_" + "C" * 36


class _AuditSink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record_access(self, **kwargs: Any) -> None:
        self.events.append(dict(kwargs))


class _Source:
    def __init__(self, records: dict[str, Any] | None = None) -> None:
        self.records = records or {}

    def _read(self, key: str) -> Any:
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


class _Notifier:
    enabled = True

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[dict[str, Any]] = []

    def notify_event(self, **kwargs: Any) -> dict[str, int]:
        self.calls.append(dict(kwargs))
        if self.fail:
            raise RuntimeError("synthetic notification outage")
        return {
            "considered": 1,
            "queued": 1,
            "duplicate": 0,
            "suppressed": 0,
            "no_rule": 0,
            "failed": 0,
        }


class _Clock:
    def __init__(self, moment: datetime) -> None:
        self.moment = moment

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, **kwargs: Any) -> None:
        self.moment += timedelta(**kwargs)


def _settings(*, notifications: bool = False) -> Any:
    return SimpleNamespace(
        governance_enabled=True,
        governance_workflow_enabled=True,
        governance_workflow_page_size=20,
        governance_workflow_max_active_sample=500,
        governance_workflow_default_warning_hours=24,
        governance_workflow_escalation_notifications_enabled=notifications,
    )


def _build_service(
    tmp_path: Any,
    *,
    name: str = "v39-hardening",
    settings: Any = None,
    auth_enabled: bool = True,
    notifier: Any = None,
    executive: Any = None,
    intelligence: Any = None,
    automation: Any = None,
    governance: Any = None,
    integrity: Any = None,
    clock: Any = None,
) -> tuple[
    GovernanceWorkflowService,
    GovernanceWorkflowRepository,
    ForensicRepository,
    AuthRepository | None,
    _AuditSink,
]:
    directory = Path(tmp_path)
    directory.mkdir(parents=True, exist_ok=True)
    url = f"sqlite:///{directory / name}.db"
    init_db(url)
    factory = get_session_factory(url)
    auth = AuthRepository(factory) if auth_enabled else None
    if auth is not None:
        create_test_user(auth, "admin@example.com", role=Role.ADMIN)
        create_test_user(auth, "operator@example.com", role=Role.OPERATOR)
        create_test_user(auth, "viewer@example.com", role=Role.VIEWER)
    audit = _AuditSink()
    forensic = ForensicRepository(factory)
    repository = GovernanceWorkflowRepository(factory)
    service = GovernanceWorkflowService(
        settings=settings or _settings(),
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
        clock=clock or (lambda: NOW),
    )
    return service, repository, forensic, auth, audit


def _template_payload(
    key: str,
    idempotency_key: str,
    tasks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "template_key": key,
        "name": f"Template {key}",
        "description": "Synthetic hardening template.",
        "tasks": tasks
        or [
            {"task_key": "intake", "title": "Intake"},
            {"task_key": "review", "title": "Review", "depends_on": ["intake"]},
        ],
        "reason": "Synthetic template for hardening tests.",
        "idempotency_key": idempotency_key,
    }


def _create_template(
    service: GovernanceWorkflowService,
    *,
    key: str = "HARDENING",
    tasks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return service.create_template(
        _template_payload(key, f"template-{key}-v1", tasks),
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )["template"]


def _create_workflow(
    service: GovernanceWorkflowService,
    *,
    key: str,
    template_id: str | None = None,
    template_key: str | None = None,
    template_version: int | None = None,
    case_id: str | None = None,
    due_at: str | None = None,
    title: str = "Hardening workflow",
    description: str = "Synthetic hardening workflow.",
    owner_type: str | None = None,
    owner_id: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "title": title,
        "description": description,
        "priority": "HIGH",
        "due_at": due_at,
        "case_id": case_id,
        "owner_type": owner_type,
        "owner_id": owner_id,
        "idempotency_key": key,
        "reason": "Synthetic hardening workflow creation.",
    }
    if template_id is not None:
        payload["template_id"] = template_id
    else:
        payload["template_key"] = template_key
        if template_version is not None:
            payload["template_version"] = template_version
    return service.create_workflow(
        payload,
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )


def _workflow(service: GovernanceWorkflowService, workflow_id: str) -> dict[str, Any]:
    return service.workflow_detail(workflow_id)["workflow"]


def _task(service: GovernanceWorkflowService, workflow_id: str, task_key: str) -> dict[str, Any]:
    detail = service.workflow_detail(workflow_id)
    return next(item for item in detail["tasks"] if item["task_key"] == task_key)


def _move_workflow(
    service: GovernanceWorkflowService,
    workflow_id: str,
    target: str,
    **extra: Any,
) -> dict[str, Any]:
    return service.transition_workflow(
        workflow_id,
        {"target_status": target, "expected_version": _workflow(service, workflow_id)["version"], **extra},
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )


def _move_task(
    service: GovernanceWorkflowService,
    workflow_id: str,
    task_key: str,
    target: str,
    **extra: Any,
) -> dict[str, Any]:
    task = _task(service, workflow_id, task_key)
    return service.transition_task(
        workflow_id,
        task["task_id"],
        {"target_status": target, "expected_version": task["version"], **extra},
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )


def _assign_workflow(
    service: GovernanceWorkflowService,
    workflow_id: str,
    owner_type: str,
    owner_id: str,
    *,
    reason: str = "Assign an accountable owner.",
) -> dict[str, Any]:
    return service.assign_workflow(
        workflow_id,
        {
            "owner_type": owner_type,
            "owner_id": owner_id,
            "expected_version": _workflow(service, workflow_id)["version"],
            "reason": reason,
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )


def _assign_task(
    service: GovernanceWorkflowService,
    workflow_id: str,
    task_key: str,
    *,
    owner_type: str = "USER",
    owner_id: str = "operator@example.com",
    reason: str = "Assign the task owner.",
) -> dict[str, Any]:
    task = _task(service, workflow_id, task_key)
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
        _assign_task(service, workflow_id, task_key)
        task = _task(service, workflow_id, task_key)
    if task["status"] == "READY":
        _move_task(service, workflow_id, task_key, "IN_PROGRESS", reason="Start the task.")
    return _move_task(
        service,
        workflow_id,
        task_key,
        "COMPLETED",
        reason="Complete the task.",
        outcome_summary=outcome,
    )["task"]


def _case(forensic: ForensicRepository, title: str) -> str:
    case, _ = forensic.create_case(title=title, description="Synthetic V39 hardening case.")
    return str(case["case_id"])


# ---------------------------------------------------------------------------
# Dependency graphs and completion honesty
# ---------------------------------------------------------------------------
def test_diamond_dependency_graph_advances_only_when_every_predecessor_completes(
    tmp_path: Any,
) -> None:
    service, _, _, _, _ = _build_service(tmp_path)
    template = _create_template(
        service,
        key="DIAMOND",
        tasks=[
            {"task_key": "start", "title": "Start"},
            {"task_key": "left", "title": "Left", "depends_on": ["start"]},
            {"task_key": "right", "title": "Right", "depends_on": ["start"]},
            {"task_key": "join", "title": "Join", "depends_on": ["right", "left"]},
        ],
    )
    workflow_id = _create_workflow(service, template_id=template["template_id"], key="diamond")["workflow"][
        "workflow_id"
    ]
    _move_workflow(service, workflow_id, "READY")
    _move_workflow(service, workflow_id, "IN_PROGRESS")

    statuses = {task["task_key"]: task["status"] for task in service.workflow_detail(workflow_id)["tasks"]}
    assert statuses == {
        "start": "READY",
        "left": "PENDING",
        "right": "PENDING",
        "join": "PENDING",
    }
    join = _task(service, workflow_id, "join")
    assert set(join["dependencies"]) == {"left", "right"}
    assert join["dependency_state"] == "PENDING"

    _start_and_complete(service, workflow_id, "start")
    assert _task(service, workflow_id, "left")["status"] == "READY"
    assert _task(service, workflow_id, "right")["status"] == "READY"
    assert _task(service, workflow_id, "join")["status"] == "PENDING"

    with pytest.raises(TaskStateError):
        _move_task(
            service,
            workflow_id,
            "join",
            "READY",
            reason="The join still has an incomplete predecessor.",
        )

    _start_and_complete(service, workflow_id, "left")
    assert _task(service, workflow_id, "join")["status"] == "PENDING"
    assert _task(service, workflow_id, "join")["dependency_state"] == "PENDING"

    _start_and_complete(service, workflow_id, "right")
    join = _task(service, workflow_id, "join")
    assert join["status"] == "READY"
    assert join["dependency_state"] == "READY"

    _start_and_complete(service, workflow_id, "join")
    _move_workflow(service, workflow_id, "UNDER_REVIEW", reason="All mandatory tasks are complete.")
    completed = _move_workflow(
        service,
        workflow_id,
        "COMPLETED",
        outcome_summary="Diamond dependency graph completed in deterministic order.",
    )
    assert completed["workflow"]["status"] == "COMPLETED"


def test_cancelled_dependency_blocks_the_dependent_and_never_completes_the_workflow(
    tmp_path: Any,
) -> None:
    service, _, _, _, _ = _build_service(tmp_path)
    template = _create_template(
        service,
        key="CANCELLED_DEPENDENCY",
        tasks=[
            {"task_key": "intake", "title": "Intake"},
            {"task_key": "review", "title": "Review", "depends_on": ["intake"]},
        ],
    )
    workflow_id = _create_workflow(service, template_id=template["template_id"], key="cancel-dependency")[
        "workflow"
    ]["workflow_id"]
    _move_workflow(service, workflow_id, "READY")
    _move_workflow(service, workflow_id, "IN_PROGRESS")

    _move_task(
        service,
        workflow_id,
        "intake",
        "CANCELLED",
        cancel_reason="The intake task was explicitly cancelled.",
    )
    review = _task(service, workflow_id, "review")
    assert review["status"] == "BLOCKED"
    assert review["dependency_state"] == "BLOCKED"
    assert "dependency was cancelled" in str(review["block_reason"])

    with pytest.raises(TaskStateError):
        _move_task(service, workflow_id, "review", "COMPLETED", outcome_summary="This must not complete.")

    with pytest.raises(WorkflowStateError):
        _move_workflow(service, workflow_id, "UNDER_REVIEW", reason="A required task is blocked.")

    assert _workflow(service, workflow_id)["status"] == "IN_PROGRESS"
    _move_workflow(service, workflow_id, "CANCELLED", cancel_reason="The workflow plan was cancelled.")
    assert _task(service, workflow_id, "review")["status"] == "CANCELLED"


# ---------------------------------------------------------------------------
# Task and workflow blocking
# ---------------------------------------------------------------------------
def test_task_blocking_requires_reason_pauses_sla_and_terminal_tasks_never_reopen(
    tmp_path: Any,
) -> None:
    clock = _Clock(NOW)
    service, _, _, _, _ = _build_service(tmp_path, clock=clock)
    template = _create_template(
        service,
        key="TASK_BLOCKING",
        tasks=[{"task_key": "intake", "title": "Intake", "due_in_hours": 2}],
    )
    workflow_id = _create_workflow(service, template_id=template["template_id"], key="task-blocking")[
        "workflow"
    ]["workflow_id"]
    _move_workflow(service, workflow_id, "READY")
    _move_workflow(service, workflow_id, "IN_PROGRESS")
    _assign_task(service, workflow_id, "intake")
    clock.advance(minutes=90)

    ready = _task(service, workflow_id, "intake")
    assert ready["status"] == "READY"
    assert ready["sla"]["state"] == "AT_RISK"

    _move_task(service, workflow_id, "intake", "IN_PROGRESS", reason="Start the task.")
    with pytest.raises(WorkflowValidationError):
        _move_task(service, workflow_id, "intake", "BLOCKED")

    blocked = _move_task(
        service,
        workflow_id,
        "intake",
        "BLOCKED",
        block_reason="Awaiting a source-domain clarification.",
    )
    assert blocked["task"]["status"] == "BLOCKED"
    assert blocked["sla"]["state"] == "PAUSED"
    assert "TASK_BLOCKED" in {event["event_type"] for event in blocked["events"]}

    _move_task(service, workflow_id, "intake", "IN_PROGRESS", reason="The clarification arrived.")
    completed = _move_task(
        service,
        workflow_id,
        "intake",
        "COMPLETED",
        reason="The task is complete.",
        outcome_summary="The task completed with recorded evidence.",
    )
    assert completed["task"]["status"] == "COMPLETED"

    with pytest.raises(TaskStateError):
        _move_task(service, workflow_id, "intake", "IN_PROGRESS", reason="Reopening is not supported.")
    with pytest.raises(TaskStateError):
        _move_task(service, workflow_id, "intake", "CANCELLED", cancel_reason="Terminal tasks stay final.")


def test_workflow_blocking_unblocking_and_incomplete_completion_are_rejected_without_mutation(
    tmp_path: Any,
) -> None:
    service, _, _, _, _ = _build_service(tmp_path)
    template = _create_template(service, key="WORKFLOW_BLOCKING")
    workflow_id = _create_workflow(service, template_id=template["template_id"], key="workflow-blocking")[
        "workflow"
    ]["workflow_id"]
    _move_workflow(service, workflow_id, "READY")
    _move_workflow(service, workflow_id, "IN_PROGRESS")

    with pytest.raises(WorkflowValidationError):
        _move_workflow(service, workflow_id, "BLOCKED")

    blocked = _move_workflow(
        service,
        workflow_id,
        "BLOCKED",
        block_reason="Awaiting an external legal review.",
    )
    assert blocked["workflow"]["status"] == "BLOCKED"
    assert blocked["sla"]["state"] == "PAUSED"

    with pytest.raises(TaskStateError):
        _move_task(
            service, workflow_id, "intake", "IN_PROGRESS", reason="Blocked workflows reject task writes."
        )

    unblocked = _move_workflow(service, workflow_id, "IN_PROGRESS", reason="The external review returned.")
    event_types = {event["event_type"] for event in unblocked["events"]}
    assert {"WORKFLOW_BLOCKED", "WORKFLOW_UNBLOCKED"} <= event_types

    before = _workflow(service, workflow_id)
    with pytest.raises(WorkflowStateError):
        _move_workflow(
            service,
            workflow_id,
            "COMPLETED",
            outcome_summary="Completion is not allowed directly from in-progress.",
        )
    after = _workflow(service, workflow_id)
    assert after["status"] == before["status"]
    assert after["version"] == before["version"]

    with pytest.raises(WorkflowStateError):
        _move_workflow(
            service,
            workflow_id,
            "UNDER_REVIEW",
            reason="Mandatory tasks are still incomplete.",
        )
    assert _workflow(service, workflow_id)["version"] == before["version"]


# ---------------------------------------------------------------------------
# SLA states
# ---------------------------------------------------------------------------
def test_sla_states_cover_on_track_at_risk_overdue_paused_unavailable_and_not_applicable(
    tmp_path: Any,
) -> None:
    clock = _Clock(NOW)
    service, _, _, _, _ = _build_service(tmp_path, clock=clock)
    template = _create_template(
        service,
        key="SLA_STATES",
        tasks=[{"task_key": "intake", "title": "Intake", "due_in_hours": 48}],
    )
    template_id = template["template_id"]

    def ready_workflow(key: str, due_at: str | None) -> str:
        workflow_id = _create_workflow(
            service,
            template_id=template_id,
            key=key,
            due_at=due_at,
        )["workflow"]["workflow_id"]
        _move_workflow(service, workflow_id, "READY")
        return workflow_id

    on_track = ready_workflow("sla-on-track", (NOW + timedelta(hours=48)).isoformat())
    at_risk = ready_workflow("sla-at-risk", (NOW + timedelta(hours=2)).isoformat())
    overdue = ready_workflow("sla-overdue", (NOW - timedelta(hours=1)).isoformat())
    no_due = ready_workflow("sla-no-due", None)
    _move_workflow(service, on_track, "IN_PROGRESS")

    blocked_id = _create_workflow(
        service,
        template_id=template_id,
        key="sla-blocked",
        due_at=(NOW + timedelta(hours=48)).isoformat(),
    )["workflow"]["workflow_id"]
    _move_workflow(service, blocked_id, "READY")
    _move_workflow(service, blocked_id, "IN_PROGRESS")
    _move_workflow(service, blocked_id, "BLOCKED", block_reason="The SLA clock must pause.")

    at_risk_template = _create_template(
        service,
        key="SLA_TASK_RISK",
        tasks=[{"task_key": "intake", "title": "Intake", "due_in_hours": 2}],
    )
    at_risk_task_workflow = _create_workflow(
        service,
        template_id=at_risk_template["template_id"],
        key="sla-task-risk",
    )["workflow"]["workflow_id"]
    _move_workflow(service, at_risk_task_workflow, "READY")
    _move_workflow(service, at_risk_task_workflow, "IN_PROGRESS")

    clock.advance(minutes=90)

    assert service.workflow_sla(on_track)["workflow"]["state"] == "ON_TRACK"
    assert service.workflow_sla(at_risk)["workflow"]["state"] == "AT_RISK"
    assert service.workflow_sla(overdue)["workflow"]["state"] == "OVERDUE"
    assert service.workflow_sla(no_due)["workflow"]["state"] == "NOT_APPLICABLE"
    assert service.workflow_sla(blocked_id)["workflow"]["state"] == "PAUSED"

    on_track_tasks = {
        task["task_key"]: task["sla"]["state"] for task in service.workflow_detail(on_track)["tasks"]
    }
    assert on_track_tasks == {"intake": "ON_TRACK"}
    assert _task(service, at_risk_task_workflow, "intake")["sla"]["state"] == "AT_RISK"

    unavailable = evaluate_sla(
        entity_type="WORKFLOW",
        entity_id="synthetic-unavailable",
        status="READY",
        due_at=(NOW + timedelta(hours=48)).isoformat(),
        start_at=None,
        resolved_at=None,
        now=NOW,
    )
    assert unavailable["state"] == "UNAVAILABLE"

    status = service.status()
    assert status["overdue"]["workflows"] >= 1
    assert status["sla_counts"]["ON_TRACK"] >= 1
    assert status["sla_counts"]["AT_RISK"] >= 1
    assert status["sla_counts"]["PAUSED"] >= 1
    assert status["sla_counts"]["NOT_APPLICABLE"] >= 1


# ---------------------------------------------------------------------------
# Escalations and notification gating
# ---------------------------------------------------------------------------
def test_escalation_eligibility_is_state_driven_and_task_scoped(
    tmp_path: Any,
) -> None:
    clock = _Clock(NOW)
    service, _, _, _, _ = _build_service(tmp_path, clock=clock)
    template = _create_template(service, key="ESCALATION_ELIGIBILITY")

    def workflow_with_due(key: str, due_at: str | None) -> str:
        workflow_id = _create_workflow(
            service,
            template_id=template["template_id"],
            key=key,
            due_at=due_at,
        )["workflow"]["workflow_id"]
        _move_workflow(service, workflow_id, "READY")
        return workflow_id

    overdue = workflow_with_due("escalation-overdue", (NOW - timedelta(hours=1)).isoformat())
    at_risk = workflow_with_due("escalation-at-risk", (NOW + timedelta(hours=2)).isoformat())
    on_track = workflow_with_due("escalation-on-track", (NOW + timedelta(hours=48)).isoformat())

    task_template = _create_template(
        service,
        key="ESCALATION_TASK",
        tasks=[{"task_key": "intake", "title": "Intake", "due_in_hours": 2}],
    )
    task_workflow = _create_workflow(
        service,
        template_id=task_template["template_id"],
        key="escalation-task",
    )["workflow"]["workflow_id"]
    _move_workflow(service, task_workflow, "READY")
    _move_workflow(service, task_workflow, "IN_PROGRESS")

    clock.advance(minutes=90)

    created = service.create_escalation(
        overdue,
        {
            "escalation_type": "SLA_OVERDUE",
            "severity": "HIGH",
            "reason": "The operational target is overdue.",
            "idempotency_key": "escalation-overdue",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert created["escalation"]["escalation_type"] == "SLA_OVERDUE"
    assert created["escalation"]["status"] == "OPEN"

    at_risk_created = service.create_escalation(
        at_risk,
        {
            "escalation_type": "SLA_AT_RISK",
            "severity": "MEDIUM",
            "reason": "The operational warning window is active.",
            "idempotency_key": "escalation-at-risk",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert at_risk_created["escalation"]["escalation_type"] == "SLA_AT_RISK"

    with pytest.raises(EscalationNotEligibleError):
        service.create_escalation(
            on_track,
            {
                "escalation_type": "SLA_AT_RISK",
                "severity": "LOW",
                "reason": "This workflow is not inside the warning window.",
                "idempotency_key": "escalation-on-track",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )

    task = _task(service, task_workflow, "intake")
    task_escalation = service.create_escalation(
        task_workflow,
        {
            "escalation_type": "SLA_AT_RISK",
            "severity": "MEDIUM",
            "task_id": task["task_id"],
            "reason": "The task is inside its warning window.",
            "idempotency_key": "escalation-task",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert task_escalation["escalation"]["task_id"] == task["task_id"]

    other_task = _task(service, overdue, "intake")
    with pytest.raises(TaskNotFoundError):
        service.create_escalation(
            task_workflow,
            {
                "escalation_type": "MANUAL",
                "severity": "LOW",
                "task_id": other_task["task_id"],
                "reason": "A task from another workflow must not be accepted.",
                "idempotency_key": "escalation-cross-workflow-task",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )

    _move_workflow(service, on_track, "CANCELLED", cancel_reason="The workflow is no longer needed.")
    with pytest.raises(WorkflowValidationError):
        service.create_escalation(
            on_track,
            {
                "escalation_type": "MANUAL",
                "severity": "LOW",
                "reason": "Terminal workflows cannot be escalated.",
                "idempotency_key": "escalation-terminal",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


def test_escalation_notifications_are_opt_in_idempotent_and_failures_are_contained(
    tmp_path: Any,
) -> None:
    off_notifier = _Notifier()
    off_service, _, _, _, _ = _build_service(
        tmp_path / "off",
        settings=_settings(notifications=False),
        notifier=off_notifier,
    )
    off_template = _create_template(off_service, key="NOTIFY_OFF")
    off_workflow = _create_workflow(
        off_service,
        template_id=off_template["template_id"],
        key="notify-off",
    )["workflow"]["workflow_id"]
    off = off_service.create_escalation(
        off_workflow,
        {
            "escalation_type": "MANUAL",
            "severity": "HIGH",
            "reason": "Notification gating is disabled by configuration.",
            "idempotency_key": "notify-off",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert off_notifier.calls == []
    assert off["notifications"]["enabled"] is False

    notifier = _Notifier()
    service, _, _, _, _ = _build_service(
        tmp_path / "on",
        settings=_settings(notifications=True),
        notifier=notifier,
    )
    template = _create_template(service, key="NOTIFY_ON")
    workflow_id = _create_workflow(
        service,
        template_id=template["template_id"],
        key="notify-on",
    )["workflow"]["workflow_id"]
    payload = {
        "escalation_type": "MANUAL",
        "severity": "HIGH",
        "reason": "Notify the operations queue without changing any source record.",
        "idempotency_key": "notify-on",
    }
    created = service.create_escalation(
        workflow_id,
        payload,
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert created["notifications"]["enabled"] is True
    assert created["notifications"]["queued"] == 1
    assert len(notifier.calls) == 1
    call = notifier.calls[0]
    assert call["event_type"] == "GOVERNANCE_WORKFLOW_ESCALATION"
    assert call["target_id"] == workflow_id
    assert call["severity"] == "HIGH"
    assert call["dedup_version"] == 1

    replay = service.create_escalation(
        workflow_id,
        payload,
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert replay["replayed"] is True
    assert len(notifier.calls) == 1

    failing = _Notifier(fail=True)
    failing_service, _, _, _, _ = _build_service(
        tmp_path / "failing",
        settings=_settings(notifications=True),
        notifier=failing,
    )
    failing_template = _create_template(failing_service, key="NOTIFY_FAILING")
    failing_workflow = _create_workflow(
        failing_service,
        template_id=failing_template["template_id"],
        key="notify-failing",
    )["workflow"]["workflow_id"]
    failed = failing_service.create_escalation(
        failing_workflow,
        {
            "escalation_type": "MANUAL",
            "severity": "MEDIUM",
            "reason": "A delivery failure must not roll back the escalation.",
            "idempotency_key": "notify-failing",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert failed["escalation"]["status"] == "OPEN"
    assert failed["notifications"]["failed"] == 1


# ---------------------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------------------
def test_ownership_rejects_inactive_users_and_works_without_an_identity_store_for_roles(
    tmp_path: Any,
) -> None:
    service, _, _, auth, _ = _build_service(tmp_path)
    assert auth is not None
    template = _create_template(service, key="OWNER_IDENTITY")
    workflow_id = _create_workflow(
        service,
        template_id=template["template_id"],
        key="owner-identity",
    )["workflow"]["workflow_id"]

    operator = auth.get_user_by_email("operator@example.com")
    assert operator is not None
    auth.set_user_active(user_id=operator.id, is_active=False)
    with pytest.raises(OwnerValidationError):
        _assign_workflow(service, workflow_id, "USER", "operator@example.com")

    role_assignment = _assign_workflow(service, workflow_id, "role", "operator")
    assert role_assignment["workflow"]["owner_type"] == "ROLE"
    assert role_assignment["workflow"]["owner_id"] == "OPERATOR"

    no_auth_service, _, _, no_auth, _ = _build_service(tmp_path / "no-identity", auth_enabled=False)
    assert no_auth is None
    no_auth_template = _create_template(no_auth_service, key="OWNER_NO_IDENTITY")
    no_auth_workflow = _create_workflow(
        no_auth_service,
        template_id=no_auth_template["template_id"],
        key="owner-no-identity",
    )["workflow"]["workflow_id"]
    with pytest.raises(OwnerValidationError):
        _assign_workflow(no_auth_service, no_auth_workflow, "USER", "operator@example.com")
    role_only = _assign_workflow(no_auth_service, no_auth_workflow, "ROLE", "OPERATOR")
    assert role_only["workflow"]["owner_id"] == "OPERATOR"


# ---------------------------------------------------------------------------
# Template canonicalization and version pinning
# ---------------------------------------------------------------------------
def test_template_digest_is_stable_for_equivalent_inputs_and_versions_are_pinned(
    tmp_path: Any,
) -> None:
    first = validate_template_definition(
        {
            "tasks": [
                {"task_key": "alpha", "title": "Alpha", "order_index": 0},
                {
                    "task_key": "beta",
                    "title": "Beta",
                    "order_index": 1,
                    "depends_on": ["alpha"],
                },
            ]
        }
    )
    second = validate_template_definition(
        {
            "tasks": [
                {
                    "task_key": "beta",
                    "title": "Beta",
                    "order_index": 1,
                    "depends_on": ["alpha", "alpha"],
                },
                {"task_key": "alpha", "title": "Alpha", "order_index": 0},
            ]
        }
    )
    assert first["definition_digest"] == second["definition_digest"]
    assert first["definition"] == second["definition"]
    assert first["topological_order"] == ["alpha", "beta"]

    service, repository, _, _, _ = _build_service(tmp_path)
    v1 = service.create_template(
        _template_payload(
            "PINNED",
            "template-pinned-v1",
            tasks=[{"task_key": "intake", "title": "Intake"}],
        ),
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )["template"]
    v2 = service.create_template_version(
        "PINNED",
        {
            "name": "Template PINNED v2",
            "tasks": [
                {"task_key": "intake", "title": "Intake"},
                {"task_key": "review", "title": "Review", "depends_on": ["intake"]},
            ],
            "reason": "Add the review step in a new immutable version.",
            "idempotency_key": "template-pinned-v2",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )["template"]
    assert v2["version"] == 2
    assert repository.get_template(v1["template_id"])["status"] == "SUPERSEDED"

    pinned = _create_workflow(
        service,
        template_key="PINNED",
        template_version=1,
        key="pinned-version-1",
    )
    latest = _create_workflow(service, template_key="PINNED", key="pinned-version-latest")
    assert pinned["workflow"]["template_version"] == 1
    assert len(pinned["tasks"]) == 1
    assert latest["workflow"]["template_version"] == 2
    assert len(latest["tasks"]) == 2

    disabled = service.disable_template(
        v2["template_id"],
        {"reason": "Retire the hardening template."},
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert disabled["changed"] is True
    assert (
        service.disable_template(
            v2["template_id"],
            {"reason": "Disabling an already disabled template is idempotent."},
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )["changed"]
        is False
    )
    with pytest.raises(WorkflowValidationError):
        service.create_template_version(
            "PINNED",
            {
                "tasks": [{"task_key": "intake", "title": "Intake"}],
                "reason": "A disabled template cannot receive a new version.",
                "idempotency_key": "template-pinned-v3",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


def test_template_bounds_reject_self_dependencies_and_excess_tasks() -> None:
    with pytest.raises(TemplateValidationError):
        validate_template_definition(
            {"tasks": [{"task_key": "alpha", "title": "Alpha", "depends_on": ["alpha"]}]}
        )
    with pytest.raises(TemplateValidationError):
        validate_template_definition({"tasks": []})
    too_many = [{"task_key": f"task{i}", "title": f"Task {i}"} for i in range(MAX_TEMPLATE_TASKS + 1)]
    with pytest.raises(TemplateValidationError):
        validate_template_definition({"tasks": too_many})

    normalized = validate_template_definition(
        {
            "tasks": [
                {"task_key": "alpha", "title": "Alpha"},
                {"task_key": "beta", "title": "Beta", "depends_on": ["alpha", "alpha"]},
            ]
        }
    )
    assert normalized["dependency_count"] == 1
    assert normalized["definition"]["tasks"][1]["depends_on"] == ["alpha"]


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------
def test_concurrent_task_completion_applies_once_and_conflicts_deterministically(
    tmp_path: Any,
) -> None:
    service, repository, _, _, _ = _build_service(tmp_path)
    template = _create_template(
        service,
        key="TASK_RACE",
        tasks=[{"task_key": "intake", "title": "Intake"}],
    )
    workflow_id = _create_workflow(service, template_id=template["template_id"], key="task-race")["workflow"][
        "workflow_id"
    ]
    _move_workflow(service, workflow_id, "READY")
    _move_workflow(service, workflow_id, "IN_PROGRESS")
    _assign_task(service, workflow_id, "intake")
    _move_task(service, workflow_id, "intake", "IN_PROGRESS", reason="Start the task.")
    task = _task(service, workflow_id, "intake")
    expected_version = task["version"]

    def complete() -> str:
        try:
            service.transition_task(
                workflow_id,
                task["task_id"],
                {
                    "target_status": "COMPLETED",
                    "expected_version": expected_version,
                    "reason": "Complete the task once.",
                    "outcome_summary": "Concurrent completion applied exactly once.",
                },
                actor_id="admin@example.com",
                actor_role="ADMIN",
            )
            return "APPLIED"
        except TaskVersionConflictError:
            return "CONFLICT"

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = [future.result() for future in [pool.submit(complete) for _ in range(4)]]

    assert outcomes.count("APPLIED") == 1
    assert outcomes.count("CONFLICT") == 3
    events = repository.task_events(task["task_id"])
    assert [event["event_type"] for event in events].count("TASK_COMPLETED") == 1
    assert _task(service, workflow_id, "intake")["status"] == "COMPLETED"


def test_concurrent_escalation_creation_is_idempotent_and_emits_one_event(
    tmp_path: Any,
) -> None:
    service, repository, _, _, _ = _build_service(tmp_path)
    template = _create_template(service, key="ESCALATION_RACE")
    workflow_id = _create_workflow(
        service,
        template_id=template["template_id"],
        key="escalation-race",
    )["workflow"]["workflow_id"]

    def create() -> bool:
        return bool(
            service.create_escalation(
                workflow_id,
                {
                    "escalation_type": "MANUAL",
                    "severity": "HIGH",
                    "reason": "Concurrent escalation creation must be idempotent.",
                    "idempotency_key": "escalation-race",
                },
                actor_id="admin@example.com",
                actor_role="ADMIN",
            )["replayed"]
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        replayed = [future.result() for future in [pool.submit(create) for _ in range(4)]]

    assert replayed.count(False) == 1
    assert replayed.count(True) == 3
    assert repository.count_escalations(workflow_id) == 1
    events = repository.workflow_events(workflow_id)
    assert [event["event_type"] for event in events].count("ESCALATION_CREATED") == 1


# ---------------------------------------------------------------------------
# Event contract, ordering, redaction, append-only surface
# ---------------------------------------------------------------------------
def test_required_event_contract_is_emitted_across_real_lifecycles(tmp_path: Any) -> None:
    service, repository, _, _, _ = _build_service(tmp_path)
    template = service.create_template(
        _template_payload("CONTRACT", "template-contract-v1"),
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )["template"]
    template_id = template["template_id"]

    first = _create_workflow(service, template_id=template_id, key="contract-first")
    first_id = first["workflow"]["workflow_id"]
    _assign_workflow(service, first_id, "ROLE", "OPERATOR")
    _assign_workflow(service, first_id, "USER", "operator@example.com")
    _move_workflow(service, first_id, "READY")
    _move_workflow(service, first_id, "IN_PROGRESS")

    _assign_task(service, first_id, "intake")
    _move_task(service, first_id, "intake", "IN_PROGRESS", reason="Start intake.")
    _move_task(
        service,
        first_id,
        "intake",
        "BLOCKED",
        block_reason="Intake waits for a synthetic clarification.",
    )
    _move_task(service, first_id, "intake", "IN_PROGRESS", reason="The clarification arrived.")
    _move_task(
        service,
        first_id,
        "intake",
        "COMPLETED",
        reason="Complete intake.",
        outcome_summary="Intake completed with recorded evidence.",
    )
    assert _task(service, first_id, "review")["status"] == "READY"
    _assign_task(service, first_id, "review")
    _move_task(service, first_id, "review", "IN_PROGRESS", reason="Start review.")
    _move_task(
        service,
        first_id,
        "review",
        "COMPLETED",
        reason="Complete review.",
        outcome_summary="Review completed with recorded evidence.",
    )

    _move_workflow(service, first_id, "BLOCKED", block_reason="A synthetic workflow-level pause.")
    _move_workflow(service, first_id, "IN_PROGRESS", reason="The pause was lifted.")

    escalation = service.create_escalation(
        first_id,
        {
            "escalation_type": "MANUAL",
            "severity": "HIGH",
            "reason": "Operations requested a documented review.",
            "idempotency_key": "contract-escalation",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )["escalation"]
    service.acknowledge_escalation(
        escalation["escalation_id"],
        {"expected_version": 1, "reason": "Operations acknowledged the review."},
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    service.resolve_escalation(
        escalation["escalation_id"],
        {
            "expected_version": 2,
            "reason": "The review completed.",
            "resolution": "The review was triaged without changing any source record.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )

    _move_workflow(service, first_id, "UNDER_REVIEW", reason="All mandatory tasks are complete.")
    _move_workflow(
        service,
        first_id,
        "COMPLETED",
        outcome_summary="The synthetic contract workflow completed.",
    )

    second = _create_workflow(service, template_id=template_id, key="contract-second")
    second_id = second["workflow"]["workflow_id"]
    _move_workflow(service, second_id, "READY")
    _move_workflow(service, second_id, "IN_PROGRESS")
    _move_workflow(
        service,
        second_id,
        "CANCELLED",
        cancel_reason="The second workflow was superseded.",
    )

    second_version = service.create_template_version(
        "CONTRACT",
        {
            "name": "Template CONTRACT v2",
            "tasks": [
                {"task_key": "intake", "title": "Intake"},
                {"task_key": "review", "title": "Review", "depends_on": ["intake"]},
                {"task_key": "close", "title": "Close", "depends_on": ["review"]},
            ],
            "reason": "Add the close step in a new immutable version.",
            "idempotency_key": "template-contract-v2",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )["template"]
    service.disable_template(
        second_version["template_id"],
        {"reason": "Retire the contract template."},
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )

    groups = [
        repository.workflow_events(first_id),
        repository.workflow_events(second_id),
        repository.template_events(template_id),
        repository.template_events(second_version["template_id"]),
    ]
    event_types = {event["event_type"] for group in groups for event in group}
    assert REQUIRED_WORKFLOW_EVENT_TYPES <= event_types
    for group in groups:
        sequences = [event["sequence"] for event in group]
        assert sequences == sorted(sequences)
        assert len(set(sequences)) == len(sequences)


def test_events_and_workflow_text_redact_credentials_and_stay_append_only(tmp_path: Any) -> None:
    service, repository, forensic, _, _ = _build_service(tmp_path)
    case_id = _case(forensic, "V39 redaction case")
    template = _create_template(service, key="REDACTION")
    workflow_id = _create_workflow(
        service,
        template_id=template["template_id"],
        key="redaction",
        case_id=case_id,
        description=f"Workflow notes containing {_SECRET_TOKEN} must be redacted.",
    )["workflow"]["workflow_id"]

    _move_workflow(service, workflow_id, "READY", reason=f"Ready using token {_SECRET_TOKEN}.")
    _move_workflow(service, workflow_id, "IN_PROGRESS")
    _move_workflow(
        service,
        workflow_id,
        "BLOCKED",
        block_reason=f"Blocked using token {_SECRET_TOKEN}.",
    )
    _move_workflow(service, workflow_id, "IN_PROGRESS", reason=f"Unblocked using token {_SECRET_TOKEN}.")

    escalation = service.create_escalation(
        workflow_id,
        {
            "escalation_type": "MANUAL",
            "severity": "HIGH",
            "reason": f"Escalation notes containing {_SECRET_TOKEN} must be redacted.",
            "idempotency_key": "redaction-escalation",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )["escalation"]
    reference = service.add_reference(
        workflow_id,
        {
            "domain": "FORENSIC_CASE",
            "source_id": case_id,
            "reason": f"Reference notes containing {_SECRET_TOKEN} must be redacted.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )["reference"]

    stored = repository.get_workflow(workflow_id)
    assert _SECRET_TOKEN not in str(stored["description"])
    assert "[REDACTED]" in str(stored["description"])
    assert _SECRET_TOKEN not in str(escalation["reason"])
    assert _SECRET_TOKEN not in str(reference["reason"])
    detail = service.workflow_detail(workflow_id)
    assert _SECRET_TOKEN not in str(detail)
    assert _SECRET_TOKEN not in str(detail["events"])

    sequences = [event["sequence"] for event in detail["events"]]
    assert sequences == sorted(sequences)
    assert len(set(sequences)) == len(sequences)

    assert not [name for name in dir(repository) if name.startswith("delete")]
    assert not [name for name in dir(service) if name.startswith("delete")]


# ---------------------------------------------------------------------------
# Cross-domain references
# ---------------------------------------------------------------------------
def test_reference_resolution_covers_every_source_domain_read_only(tmp_path: Any) -> None:
    executive = _ExecutiveSource(
        {
            "action-hardening": {
                "action_id": "action-hardening",
                "status": "IN_PROGRESS",
                "title": "Executive follow-up",
                "version": 2,
            }
        }
    )
    intelligence = _IntelligenceSource(
        {
            "recommendation-hardening": {
                "recommendation_id": "recommendation-hardening",
                "status": "OPEN",
                "title": "Retention recommendation",
            }
        }
    )
    automation = _AutomationSource(
        {
            "job-hardening": {
                "job_id": "job-hardening",
                "status": "COMPLETED",
                "job_type": "RETENTION_EVALUATION",
            }
        }
    )
    directory = Path(tmp_path)
    directory.mkdir(parents=True, exist_ok=True)
    url = f"sqlite:///{directory / 'v39-hardening'}.db"
    init_db(url)
    case_id = _case(ForensicRepository(get_session_factory(url)), "V39 all-domain reference case")
    governance = _GovernanceSource(
        {
            "review-hardening": {
                "evaluation_id": "review-hardening",
                "case_id": case_id,
                "status": "COMPLETED",
                "governance_state": "REVIEW_COMPLETE",
            },
            "hold-hardening": {
                "hold_id": "hold-hardening",
                "case_id": case_id,
                "status": "ACTIVE",
                "hold_number": "HOLD-39",
            },
            "disposition-hardening": {
                "disposition_id": "disposition-hardening",
                "case_id": case_id,
                "status": "PENDING",
            },
            "approval-hardening": {
                "approval_id": "approval-hardening",
                "case_id": case_id,
                "status": "APPROVED",
            },
        }
    )
    integrity = _IntegritySource(
        {
            "finding-hardening": {
                "finding_id": "finding-hardening",
                "case_id": case_id,
                "status": "OPEN",
                "severity": "HIGH",
            }
        }
    )
    service, _, _, _, _ = _build_service(
        tmp_path,
        executive=executive,
        intelligence=intelligence,
        automation=automation,
        governance=governance,
        integrity=integrity,
    )
    template = _create_template(service, key="ALL_REFERENCE_DOMAINS")
    workflow_id = _create_workflow(
        service,
        template_id=template["template_id"],
        key="all-reference-domains",
        case_id=case_id,
    )["workflow"]["workflow_id"]

    originals = {
        "executive": copy.deepcopy(executive.records),
        "intelligence": copy.deepcopy(intelligence.records),
        "automation": copy.deepcopy(automation.records),
        "governance": copy.deepcopy(governance.records),
        "integrity": copy.deepcopy(integrity.records),
    }
    domains = [
        ("FORENSIC_CASE", case_id),
        ("FORENSIC_FINDING", "finding-hardening"),
        ("RETENTION_REVIEW", "review-hardening"),
        ("LEGAL_HOLD", "hold-hardening"),
        ("DISPOSITION", "disposition-hardening"),
        ("EXPORT_APPROVAL", "approval-hardening"),
        ("AUTOMATION_JOB", "job-hardening"),
        ("RECOMMENDATION", "recommendation-hardening"),
        ("EXECUTIVE_ACTION", "action-hardening"),
    ]
    for domain, source_id in domains:
        added = service.add_reference(
            workflow_id,
            {
                "domain": domain,
                "source_id": source_id,
                "reason": f"Attach the read-only {domain} source.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
        assert added["reference"]["availability"] == "AVAILABLE"
        assert added["reference"]["domain"] == domain
        assert added["source_mutated"] is False

    references = service.list_references(workflow_id)
    assert len(references["items"]) == len(domains)
    assert references["source_mutated"] is False
    assert {item["domain"] for item in references["items"]} == {domain for domain, _ in domains}

    assert executive.records == originals["executive"]
    assert intelligence.records == originals["intelligence"]
    assert automation.records == originals["automation"]
    assert governance.records == originals["governance"]
    assert integrity.records == originals["integrity"]


# ---------------------------------------------------------------------------
# API RBAC, bounds, and stable envelopes
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


def test_api_conflict_envelopes_bounds_and_role_boundaries(client: Any) -> None:
    template = client.post(
        "/api/v1/governance/workflows/templates",
        json=_template_payload("API_HARDENING", "api-hardening-template"),
    )
    assert template.status_code == 200, template.text
    template_id = template.json()["template"]["template_id"]

    workflow = client.post(
        "/api/v1/governance/workflows/workflows",
        json={
            "template_id": template_id,
            "title": "API hardening workflow",
            "idempotency_key": "api-hardening-workflow",
            "reason": "Synthetic API hardening workflow.",
        },
    )
    assert workflow.status_code == 200, workflow.text
    workflow_id = workflow.json()["workflow"]["workflow_id"]

    invalid = client.post(
        f"/api/v1/governance/workflows/workflows/{workflow_id}/transitions",
        json={
            "target_status": "COMPLETED",
            "expected_version": 1,
            "outcome_summary": "This transition is not allowed from draft.",
        },
    )
    assert invalid.status_code == 409
    assert invalid.json()["error"]["code"] == "WORKFLOW_TRANSITION_INVALID"

    ready = client.post(
        f"/api/v1/governance/workflows/workflows/{workflow_id}/transitions",
        json={
            "target_status": "READY",
            "expected_version": 1,
            "reason": "The workflow is ready.",
        },
    )
    assert ready.status_code == 200, ready.text

    stale = client.post(
        f"/api/v1/governance/workflows/workflows/{workflow_id}/transitions",
        json={
            "target_status": "IN_PROGRESS",
            "expected_version": 1,
            "reason": "This version is stale.",
        },
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "WORKFLOW_VERSION_CONFLICT"

    missing_reason = client.post(
        f"/api/v1/governance/workflows/workflows/{workflow_id}/transitions",
        json={"target_status": "BLOCKED", "expected_version": 2},
    )
    assert missing_reason.status_code == 422
    assert missing_reason.json()["error"]["code"] == "workflow_validation_error"

    assert client.get("/api/v1/governance/workflows/workflows", params={"page_size": 0}).status_code == 422
    assert client.get("/api/v1/governance/workflows/workflows", params={"page_size": 101}).status_code == 422
    assert client.get("/api/v1/governance/workflows/workflows", params={"page": 0}).status_code == 422
    assert (
        client.get("/api/v1/governance/workflows/workflows", params={"status": "HOSTILE"}).status_code == 422
    )
    assert (
        client.post(
            "/api/v1/governance/workflows/templates",
            json={
                **_template_payload("API_TOO_LONG", "api-too-long-template"),
                "name": "N" * 201,
            },
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/governance/workflows/workflows",
            json={
                "template_version": 1,
                "title": "Version without a key",
                "idempotency_key": "api-version-without-key",
                "reason": "The schema requires a template key for a version.",
            },
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"/api/v1/governance/workflows/workflows/{workflow_id}/references",
            json={
                "domain": "FORENSIC_CASE",
                "source_id": "S" * 129,
                "reason": "The source id exceeds the bounded request limit.",
            },
        ).status_code
        == 422
    )

    viewer = _role_client(client, "viewer-v39-hardening@example.com", Role.VIEWER)
    assert viewer.get("/api/v1/governance/workflows/status").status_code == 200
    assert viewer.get("/api/v1/governance/workflows/workflows").status_code == 200
    assert viewer.get("/api/v1/governance/workflows/templates").status_code == 200
    assert viewer.get(f"/api/v1/governance/workflows/workflows/{workflow_id}").status_code == 403
    assert viewer.get(f"/api/v1/governance/workflows/workflows/{workflow_id}/events").status_code == 403
    assert viewer.get(f"/api/v1/governance/workflows/templates/{template_id}").status_code == 403
    assert (
        viewer.post(
            "/api/v1/governance/workflows/templates",
            json=_template_payload("VIEWER_HARDENING", "viewer-hardening-template"),
        ).status_code
        == 403
    )

    operator = _role_client(client, "operator-v39-hardening@example.com", Role.OPERATOR)
    assert (
        operator.post(
            "/api/v1/governance/workflows/templates",
            json=_template_payload("OPERATOR_HARDENING", "operator-hardening-template"),
        ).status_code
        == 403
    )
    operator_workflow = operator.post(
        "/api/v1/governance/workflows/workflows",
        json={
            "template_id": template_id,
            "title": "Operator hardening workflow",
            "idempotency_key": "operator-hardening-workflow",
            "reason": "An operator may instantiate a workflow.",
        },
    )
    assert operator_workflow.status_code == 200, operator_workflow.text
    operator_workflow_id = operator_workflow.json()["workflow"]["workflow_id"]
    assert (
        operator.get(f"/api/v1/governance/workflows/workflows/{operator_workflow_id}/events").status_code
        == 200
    )
    assert (
        operator.post(
            f"/api/v1/governance/workflows/workflows/{operator_workflow_id}/transitions",
            json={
                "target_status": "READY",
                "expected_version": 1,
                "reason": "An operator may transition a workflow.",
            },
        ).status_code
        == 200
    )

    for path in (
        f"/api/v1/governance/workflows/workflows/{workflow_id}",
        f"/api/v1/governance/workflows/templates/{template_id}",
        f"/api/v1/governance/workflows/workflows/{workflow_id}/escalations",
        f"/api/v1/governance/workflows/workflows/{workflow_id}/tasks",
        f"/api/v1/governance/workflows/workflows/{workflow_id}/references",
    ):
        assert client.delete(path).status_code == 405


def test_api_case_filters_and_cross_workflow_task_isolation(client: Any) -> None:
    forensic = ForensicRepository(get_session_factory(str(client.app.state.settings.database_url)))
    case_a, _ = forensic.create_case(title="V39 API case A", description="Synthetic API case A.")
    case_b, _ = forensic.create_case(title="V39 API case B", description="Synthetic API case B.")
    case_a_id = str(case_a["case_id"])
    case_b_id = str(case_b["case_id"])

    template = client.post(
        "/api/v1/governance/workflows/templates",
        json=_template_payload("API_CASE_ISOLATION", "api-case-isolation-template"),
    )
    assert template.status_code == 200, template.text
    template_id = template.json()["template"]["template_id"]

    def create(key: str, case_id: str) -> str:
        response = client.post(
            "/api/v1/governance/workflows/workflows",
            json={
                "template_id": template_id,
                "case_id": case_id,
                "title": f"Case workflow {key}",
                "idempotency_key": key,
                "reason": "Synthetic case-scoped workflow.",
            },
        )
        assert response.status_code == 200, response.text
        return response.json()["workflow"]["workflow_id"]

    workflow_a = create("api-case-a", case_a_id)
    workflow_b = create("api-case-b", case_b_id)

    filtered = client.get(
        "/api/v1/governance/workflows/workflows",
        params={"case_id": case_a_id},
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1
    assert filtered.json()["items"][0]["workflow_id"] == workflow_a

    assert (
        client.get(
            "/api/v1/governance/workflows/workflows",
            params={"case_id": case_a_id, "status": "READY"},
        ).json()["total"]
        == 0
    )

    tasks_b = client.get(
        "/api/v1/governance/workflows/tasks",
        params={"workflow_id": workflow_b},
    )
    assert tasks_b.status_code == 200
    assert tasks_b.json()["total"] == 2
    assert {item["workflow_id"] for item in tasks_b.json()["items"]} == {workflow_b}

    detail_b = client.get(f"/api/v1/governance/workflows/workflows/{workflow_b}")
    assert detail_b.status_code == 200
    task_b = detail_b.json()["tasks"][0]
    cross_workflow = client.post(
        f"/api/v1/governance/workflows/workflows/{workflow_a}/tasks/{task_b['task_id']}/transitions",
        json={
            "target_status": "IN_PROGRESS",
            "expected_version": task_b["version"],
            "reason": "A task from another workflow must not be addressable.",
        },
    )
    assert cross_workflow.status_code == 404
    assert cross_workflow.json()["error"]["code"] == "not_found"
    assert cross_workflow.json()["error"]["details"]["code"] == "workflow_not_found"


def test_disabled_workflow_service_returns_a_stable_503(client: Any) -> None:
    settings = client.app.state.settings
    original = bool(settings.governance_workflow_enabled)
    settings.governance_workflow_enabled = False
    try:
        status = client.get("/api/v1/governance/workflows/status")
        assert status.status_code == 503
        assert status.json()["error"]["code"] == "workflow_disabled"
        assert client.get("/api/v1/governance/workflows/workflows").status_code == 503
    finally:
        settings.governance_workflow_enabled = original


# ---------------------------------------------------------------------------
# Bounded metrics
# ---------------------------------------------------------------------------
def test_operation_creation_and_dependency_metrics_normalize_hostile_labels() -> None:
    hostile = "V39/HARDENING/SENTINEL"
    record_governance_workflow_operation(hostile, hostile, 0.05)
    record_governance_workflow_creation(hostile)
    record_governance_workflow_dependency(hostile)

    payload = metrics_payload().decode("utf-8")
    assert "HARDENING/SENTINEL" not in payload
    assert 'operation="UNKNOWN"' in payload
    assert 'outcome="UNKNOWN"' in payload
