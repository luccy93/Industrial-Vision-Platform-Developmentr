"""Validated request schemas for the V39 enterprise workflow API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, model_validator

from backend.app.governance.workflows.constants import (
    MAX_REFERENCE_KEY_LENGTH,
    MAX_REFERENCE_SOURCE_ID_LENGTH,
    MAX_TASKS_PER_WORKFLOW,
    MAX_TEMPLATE_TASKS,
    MAX_WORKFLOW_DESCRIPTION_LENGTH,
    MAX_WORKFLOW_IDEMPOTENCY_LENGTH,
    MAX_WORKFLOW_OUTCOME_LENGTH,
    MAX_WORKFLOW_OWNER_LENGTH,
    MAX_WORKFLOW_REASON_LENGTH,
    MAX_WORKFLOW_TITLE_LENGTH,
    MIN_OUTCOME_LENGTH,
    MIN_REASON_LENGTH,
    MIN_TITLE_LENGTH,
    TASK_KEY_PATTERN,
    TEMPLATE_KEY_PATTERN,
)


class WorkflowTemplateTaskRequest(BaseModel):
    task_key: str = Field(min_length=1, max_length=64, pattern=TASK_KEY_PATTERN)
    title: str = Field(min_length=MIN_TITLE_LENGTH, max_length=MAX_WORKFLOW_TITLE_LENGTH)
    description: str = Field(default="", max_length=MAX_WORKFLOW_DESCRIPTION_LENGTH)
    required: bool = True
    depends_on: list[str] = Field(default_factory=list, max_length=MAX_TASKS_PER_WORKFLOW)
    order_index: int | None = Field(default=None, ge=0, le=10_000)
    due_in_hours: int | None = Field(default=None, ge=1, le=24 * 3650)


class WorkflowTemplateCreateRequest(BaseModel):
    template_key: str = Field(min_length=1, max_length=64, pattern=TEMPLATE_KEY_PATTERN)
    name: str = Field(min_length=MIN_TITLE_LENGTH, max_length=MAX_WORKFLOW_TITLE_LENGTH)
    description: str = Field(default="", max_length=MAX_WORKFLOW_DESCRIPTION_LENGTH)
    tasks: list[WorkflowTemplateTaskRequest] = Field(min_length=1, max_length=MAX_TEMPLATE_TASKS)
    reason: str = Field(min_length=MIN_REASON_LENGTH, max_length=MAX_WORKFLOW_REASON_LENGTH)
    idempotency_key: str = Field(min_length=1, max_length=MAX_WORKFLOW_IDEMPOTENCY_LENGTH)


class WorkflowTemplateVersionRequest(BaseModel):
    name: str | None = Field(default=None, min_length=MIN_TITLE_LENGTH, max_length=MAX_WORKFLOW_TITLE_LENGTH)
    description: str | None = Field(default=None, max_length=MAX_WORKFLOW_DESCRIPTION_LENGTH)
    tasks: list[WorkflowTemplateTaskRequest] = Field(min_length=1, max_length=MAX_TEMPLATE_TASKS)
    reason: str = Field(min_length=MIN_REASON_LENGTH, max_length=MAX_WORKFLOW_REASON_LENGTH)
    idempotency_key: str = Field(min_length=1, max_length=MAX_WORKFLOW_IDEMPOTENCY_LENGTH)


class WorkflowTemplateDisableRequest(BaseModel):
    reason: str = Field(min_length=MIN_REASON_LENGTH, max_length=MAX_WORKFLOW_REASON_LENGTH)


class WorkflowCreateRequest(BaseModel):
    template_id: str | None = Field(default=None, min_length=1, max_length=36)
    template_key: str | None = Field(default=None, min_length=1, max_length=64, pattern=TEMPLATE_KEY_PATTERN)
    template_version: int | None = Field(default=None, ge=1)
    case_id: str | None = Field(default=None, min_length=1, max_length=36)
    title: str = Field(min_length=MIN_TITLE_LENGTH, max_length=MAX_WORKFLOW_TITLE_LENGTH)
    description: str = Field(default="", max_length=MAX_WORKFLOW_DESCRIPTION_LENGTH)
    priority: str = Field(default="MEDIUM", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    due_at: datetime | None = None
    owner_type: str | None = Field(default=None, pattern="^(USER|ROLE)$")
    owner_id: str | None = Field(default=None, min_length=1, max_length=MAX_WORKFLOW_OWNER_LENGTH)
    idempotency_key: str = Field(min_length=1, max_length=MAX_WORKFLOW_IDEMPOTENCY_LENGTH)
    reason: str = Field(min_length=MIN_REASON_LENGTH, max_length=MAX_WORKFLOW_REASON_LENGTH)

    @model_validator(mode="after")
    def _require_template_reference(self) -> WorkflowCreateRequest:
        if not self.template_id and not self.template_key:
            raise ValueError("template_id or template_key is required")
        if self.template_version is not None and not self.template_key:
            raise ValueError("template_version requires template_key")
        if self.owner_type is None and self.owner_id is not None:
            raise ValueError("owner_type is required when owner_id is provided")
        if self.owner_type is not None and not self.owner_id:
            raise ValueError("owner_id is required when owner_type is provided")
        return self


class WorkflowTransitionRequest(BaseModel):
    target_status: str = Field(pattern="^(READY|IN_PROGRESS|BLOCKED|UNDER_REVIEW|COMPLETED|CANCELLED)$")
    expected_version: int = Field(ge=1)
    reason: str = Field(default="", max_length=MAX_WORKFLOW_REASON_LENGTH)
    outcome_summary: str = Field(default="", max_length=MAX_WORKFLOW_OUTCOME_LENGTH)
    block_reason: str = Field(default="", max_length=MAX_WORKFLOW_REASON_LENGTH)
    cancel_reason: str = Field(default="", max_length=MAX_WORKFLOW_REASON_LENGTH)


class WorkflowAssignRequest(BaseModel):
    owner_type: str = Field(pattern="^(USER|ROLE)$")
    owner_id: str = Field(min_length=1, max_length=MAX_WORKFLOW_OWNER_LENGTH)
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=MIN_REASON_LENGTH, max_length=MAX_WORKFLOW_REASON_LENGTH)


class WorkflowTaskTransitionRequest(BaseModel):
    target_status: str = Field(pattern="^(READY|IN_PROGRESS|BLOCKED|COMPLETED|CANCELLED)$")
    expected_version: int = Field(ge=1)
    reason: str = Field(default="", max_length=MAX_WORKFLOW_REASON_LENGTH)
    outcome_summary: str = Field(default="", max_length=MAX_WORKFLOW_OUTCOME_LENGTH)
    block_reason: str = Field(default="", max_length=MAX_WORKFLOW_REASON_LENGTH)
    cancel_reason: str = Field(default="", max_length=MAX_WORKFLOW_REASON_LENGTH)


class WorkflowTaskAssignRequest(BaseModel):
    owner_type: str = Field(pattern="^(USER|ROLE)$")
    owner_id: str = Field(min_length=1, max_length=MAX_WORKFLOW_OWNER_LENGTH)
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=MIN_REASON_LENGTH, max_length=MAX_WORKFLOW_REASON_LENGTH)


class WorkflowReferenceCreateRequest(BaseModel):
    domain: str = Field(
        pattern=(
            "^(FORENSIC_CASE|FORENSIC_FINDING|RETENTION_REVIEW|LEGAL_HOLD|"
            "DISPOSITION|EXPORT_APPROVAL|AUTOMATION_JOB|RECOMMENDATION|EXECUTIVE_ACTION)$"
        )
    )
    source_id: str = Field(min_length=1, max_length=MAX_REFERENCE_SOURCE_ID_LENGTH)
    task_id: str | None = Field(default=None, min_length=1, max_length=36)
    reference_key: str | None = Field(default=None, min_length=1, max_length=MAX_REFERENCE_KEY_LENGTH)
    reason: str = Field(min_length=MIN_REASON_LENGTH, max_length=MAX_WORKFLOW_REASON_LENGTH)


class WorkflowEscalationCreateRequest(BaseModel):
    escalation_type: str = Field(pattern="^(SLA_OVERDUE|SLA_AT_RISK|BLOCKED|UNASSIGNED|MANUAL)$")
    severity: str = Field(default="MEDIUM", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    task_id: str | None = Field(default=None, min_length=1, max_length=36)
    reason: str = Field(min_length=MIN_REASON_LENGTH, max_length=MAX_WORKFLOW_REASON_LENGTH)
    idempotency_key: str = Field(min_length=1, max_length=MAX_WORKFLOW_IDEMPOTENCY_LENGTH)


class WorkflowEscalationAcknowledgeRequest(BaseModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=MIN_REASON_LENGTH, max_length=MAX_WORKFLOW_REASON_LENGTH)


class WorkflowEscalationResolveRequest(BaseModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=MIN_REASON_LENGTH, max_length=MAX_WORKFLOW_REASON_LENGTH)
    resolution: str = Field(min_length=MIN_OUTCOME_LENGTH, max_length=MAX_WORKFLOW_REASON_LENGTH)


__all__ = [
    "WorkflowAssignRequest",
    "WorkflowCreateRequest",
    "WorkflowEscalationAcknowledgeRequest",
    "WorkflowEscalationCreateRequest",
    "WorkflowEscalationResolveRequest",
    "WorkflowReferenceCreateRequest",
    "WorkflowTaskAssignRequest",
    "WorkflowTaskTransitionRequest",
    "WorkflowTemplateCreateRequest",
    "WorkflowTemplateDisableRequest",
    "WorkflowTemplateTaskRequest",
    "WorkflowTemplateVersionRequest",
    "WorkflowTransitionRequest",
]
