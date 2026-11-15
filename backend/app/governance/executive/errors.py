"""V38 executive-governance domain errors."""

from __future__ import annotations


class ExecutiveError(ValueError):
    """Base class for sanitized executive-domain failures."""


class ExecutiveDisabledError(ExecutiveError):
    """Executive governance is disabled or not initialized."""


class ExecutiveValidationError(ExecutiveError):
    """A request or configuration value is invalid."""


class ExecutiveNotFoundError(ExecutiveError):
    """A requested executive record does not exist."""


class ActionNotFoundError(ExecutiveNotFoundError):
    def __init__(self, action_id: str) -> None:
        super().__init__(f"executive action not found: {action_id}")
        self.action_id = action_id


class ActionVersionConflictError(ExecutiveError):
    def __init__(self, action_id: str, expected: int, actual: int) -> None:
        super().__init__(
            f"executive action {action_id} was updated concurrently "
            f"(expected version {expected}, actual {actual})"
        )
        self.action_id = action_id
        self.expected = expected
        self.actual = actual


class ActionStateError(ExecutiveError):
    """An executive action transition is not allowed from the current state."""


class RecommendationNotActionableError(ExecutiveError):
    """A V37 recommendation cannot be linked to a new strategic action."""

    code = "RECOMMENDATION_NOT_ACTIONABLE"


class RecommendationNotFoundForActionError(ExecutiveNotFoundError):
    def __init__(self, recommendation_id: str) -> None:
        super().__init__(f"governance recommendation not found: {recommendation_id}")
        self.recommendation_id = recommendation_id


class ReportNotFoundError(ExecutiveNotFoundError):
    def __init__(self, report_id: str) -> None:
        super().__init__(f"executive report not found: {report_id}")
        self.report_id = report_id


class ReportIntegrityError(ExecutiveError):
    """A stored report or its source snapshot failed self-digest validation."""

    code = "REPORT_INTEGRITY_FAILED"


class ReportIncompatibleError(ExecutiveError):
    """Two reports cannot be compared because their type or schema differs."""

    code = "REPORT_INCOMPATIBLE"


class ReportUnavailableError(ExecutiveError):
    """A report source or stored payload is unavailable."""


class ExecutiveConfigError(ExecutiveError):
    """The stored executive configuration is invalid or failed integrity."""


__all__ = [
    "ActionNotFoundError",
    "ActionStateError",
    "ActionVersionConflictError",
    "ExecutiveConfigError",
    "ExecutiveDisabledError",
    "ExecutiveError",
    "ExecutiveNotFoundError",
    "ExecutiveValidationError",
    "RecommendationNotActionableError",
    "RecommendationNotFoundForActionError",
    "ReportIncompatibleError",
    "ReportIntegrityError",
    "ReportNotFoundError",
    "ReportUnavailableError",
]
