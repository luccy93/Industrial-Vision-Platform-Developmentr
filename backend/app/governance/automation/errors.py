"""V36 governance-automation domain errors (mapped to HTTP codes by the API)."""

from __future__ import annotations


class AutomationError(ValueError):
    """Base class for sanitized automation-domain failures."""


class AutomationDisabledError(AutomationError):
    """Automation is disabled by configuration or not initialized."""


class ScheduleNotFoundError(AutomationError):
    def __init__(self, job_type: str) -> None:
        super().__init__(f"governance automation schedule not found: {job_type}")
        self.job_type = job_type


class ScheduleVersionConflictError(AutomationError):
    def __init__(self, job_type: str, expected: int, actual: int) -> None:
        super().__init__(
            f"governance automation schedule {job_type} was updated concurrently "
            f"(expected version {expected}, actual {actual})"
        )
        self.job_type = job_type
        self.expected = expected
        self.actual = actual


class ScheduleValidationError(AutomationError):
    """A schedule configuration is invalid or outside its bounds."""


class JobNotFoundError(AutomationError):
    def __init__(self, job_id: str) -> None:
        super().__init__(f"governance automation job not found: {job_id}")
        self.job_id = job_id


class JobStateError(AutomationError):
    """A job is not in a state that permits the requested transition."""


class RetryExhaustedError(AutomationError):
    """The job has reached its bounded retry limit."""


class UnsupportedJobTypeError(AutomationError):
    """The job type is not implemented by this deployment."""


class SnapshotNotFoundError(AutomationError):
    def __init__(self, snapshot_id: str) -> None:
        super().__init__(f"governance compliance snapshot not found: {snapshot_id}")
        self.snapshot_id = snapshot_id


class AutomationValidationError(AutomationError):
    """A request or configuration value is invalid."""


class AutomationExecutionError(AutomationError):
    """A job ran but completed no useful work."""


class JobCancelled(AutomationError):
    """Cooperative cancellation was observed while a job was running."""


class JobTimeout(AutomationError):
    """A job exceeded its configured execution deadline."""


class LeaseLost(AutomationError):
    """The executor no longer owns the job lease."""


__all__ = [
    "AutomationDisabledError",
    "AutomationError",
    "AutomationExecutionError",
    "AutomationValidationError",
    "JobCancelled",
    "JobNotFoundError",
    "JobStateError",
    "JobTimeout",
    "LeaseLost",
    "RetryExhaustedError",
    "ScheduleNotFoundError",
    "ScheduleValidationError",
    "ScheduleVersionConflictError",
    "SnapshotNotFoundError",
    "UnsupportedJobTypeError",
]
