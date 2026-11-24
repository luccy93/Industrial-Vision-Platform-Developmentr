"""V39 enterprise workflow domain errors with stable response codes."""

from __future__ import annotations


class WorkflowError(ValueError):
    """Base class for sanitized workflow-domain failures."""


class WorkflowDisabledError(WorkflowError):
    """Workflow orchestration is disabled or not initialized."""


class WorkflowValidationError(WorkflowError):
    """A request value, template definition, or query is invalid."""


class TemplateValidationError(WorkflowValidationError):
    """A versioned template definition is invalid."""

    code = "TEMPLATE_INVALID"


class WorkflowNotFoundError(WorkflowError):
    """A requested workflow record does not exist."""

    def __init__(self, workflow_id: str) -> None:
        super().__init__(f"workflow not found: {workflow_id}")
        self.workflow_id = workflow_id


class TemplateNotFoundError(WorkflowError):
    """A requested workflow template does not exist."""

    def __init__(self, template_id: str) -> None:
        super().__init__(f"workflow template not found: {template_id}")
        self.template_id = template_id


class TaskNotFoundError(WorkflowError):
    """A requested workflow task does not exist in the workflow."""

    def __init__(self, task_id: str) -> None:
        super().__init__(f"workflow task not found: {task_id}")
        self.task_id = task_id


class EscalationNotFoundError(WorkflowError):
    """A requested workflow escalation does not exist."""

    def __init__(self, escalation_id: str) -> None:
        super().__init__(f"workflow escalation not found: {escalation_id}")
        self.escalation_id = escalation_id


class ReferenceNotFoundError(WorkflowError):
    """A referenced source record does not exist."""

    def __init__(self, domain: str, source_id: str) -> None:
        super().__init__(f"referenced {domain} record not found: {source_id}")
        self.domain = domain
        self.source_id = source_id


class ReferenceUnauthorizedError(WorkflowError):
    """The caller lacks the source domain's own read capability."""

    code = "REFERENCE_UNAUTHORIZED"


class ReferenceUnavailableError(WorkflowError):
    """A source domain could not be read for a reference operation."""

    code = "REFERENCE_UNAVAILABLE"


class ReferenceDeletedError(WorkflowError):
    """A source record reports an explicit deleted tombstone."""

    code = "REFERENCE_DELETED"


class SourceCaseMismatchError(WorkflowError):
    """A case-scoped source does not match the workflow case boundary."""

    code = "REFERENCE_CASE_MISMATCH"


class WorkflowVersionConflictError(WorkflowError):
    """A workflow update lost an optimistic-concurrency race."""

    code = "WORKFLOW_VERSION_CONFLICT"

    def __init__(self, workflow_id: str, expected: int, actual: int) -> None:
        super().__init__(
            f"workflow {workflow_id} was updated concurrently (expected version {expected}, actual {actual})"
        )
        self.workflow_id = workflow_id
        self.expected = expected
        self.actual = actual


class TaskVersionConflictError(WorkflowError):
    """A task update lost an optimistic-concurrency race."""

    code = "TASK_VERSION_CONFLICT"

    def __init__(self, task_id: str, expected: int, actual: int) -> None:
        super().__init__(
            f"workflow task {task_id} was updated concurrently (expected version {expected}, actual {actual})"
        )
        self.task_id = task_id
        self.expected = expected
        self.actual = actual


class EscalationVersionConflictError(WorkflowError):
    """An escalation update lost an optimistic-concurrency race."""

    code = "ESCALATION_VERSION_CONFLICT"

    def __init__(self, escalation_id: str, expected: int, actual: int) -> None:
        super().__init__(
            f"workflow escalation {escalation_id} was updated concurrently "
            f"(expected version {expected}, actual {actual})"
        )
        self.escalation_id = escalation_id
        self.expected = expected
        self.actual = actual


class WorkflowStateError(WorkflowError):
    """A workflow lifecycle transition is not allowed."""

    code = "WORKFLOW_TRANSITION_INVALID"


class TaskStateError(WorkflowError):
    """A task lifecycle transition is not allowed."""

    code = "TASK_TRANSITION_INVALID"


class EscalationStateError(WorkflowError):
    """An escalation lifecycle transition is not allowed."""

    code = "ESCALATION_TRANSITION_INVALID"


class DependencyError(WorkflowError):
    """A task dependency graph is invalid or unsatisfied."""

    code = "DEPENDENCY_INVALID"


class EscalationNotEligibleError(WorkflowError):
    """An escalation type does not match the current deterministic state."""

    code = "ESCALATION_NOT_ELIGIBLE"


class OwnerValidationError(WorkflowError):
    """An owner reference is not an existing active user or known role."""

    code = "OWNER_INVALID"


class WorkflowConfigError(WorkflowError):
    """Stored workflow configuration or a required dependency is unavailable."""


__all__ = [
    "DependencyError",
    "EscalationNotEligibleError",
    "EscalationNotFoundError",
    "EscalationStateError",
    "EscalationVersionConflictError",
    "OwnerValidationError",
    "ReferenceDeletedError",
    "ReferenceNotFoundError",
    "ReferenceUnauthorizedError",
    "ReferenceUnavailableError",
    "SourceCaseMismatchError",
    "TaskNotFoundError",
    "TaskStateError",
    "TaskVersionConflictError",
    "TemplateNotFoundError",
    "TemplateValidationError",
    "WorkflowConfigError",
    "WorkflowDisabledError",
    "WorkflowError",
    "WorkflowNotFoundError",
    "WorkflowStateError",
    "WorkflowValidationError",
    "WorkflowVersionConflictError",
]
