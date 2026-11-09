"""V35 governance domain errors (mapped to HTTP codes by the API layer)."""

from __future__ import annotations


class GovernanceError(ValueError):
    """Base class for sanitized governance-domain failures."""


class GovernanceDisabledError(GovernanceError):
    """Governance is disabled or not initialized."""


class PolicyNotFoundError(GovernanceError):
    def __init__(self, policy_id: str) -> None:
        super().__init__(f"governance policy not found: {policy_id}")
        self.policy_id = policy_id


class PolicyVersionConflictError(GovernanceError):
    def __init__(self, policy_id: str, expected: int, actual: int) -> None:
        super().__init__(
            f"governance policy {policy_id} was updated concurrently "
            f"(expected version {expected}, actual {actual})"
        )
        self.policy_id = policy_id
        self.expected = expected
        self.actual = actual


class PolicyValidationError(GovernanceError):
    """A policy definition is invalid or an unsafe transition was requested."""


class EvaluationNotFoundError(GovernanceError):
    def __init__(self, case_id: str) -> None:
        super().__init__(f"no retention evaluation exists for case: {case_id}")
        self.case_id = case_id


class LegalHoldNotFoundError(GovernanceError):
    def __init__(self, hold_id: str) -> None:
        super().__init__(f"legal hold not found: {hold_id}")
        self.hold_id = hold_id


class LegalHoldVersionConflictError(GovernanceError):
    def __init__(self, hold_id: str, expected: int, actual: int) -> None:
        super().__init__(
            f"legal hold {hold_id} was updated concurrently (expected version {expected}, actual {actual})"
        )
        self.hold_id = hold_id
        self.expected = expected
        self.actual = actual


class LegalHoldStateError(GovernanceError):
    """A legal-hold transition is not allowed from the current state."""


class SeparationOfDutiesError(GovernanceError):
    """The requester cannot approve or decide their own request."""


class DispositionNotFoundError(GovernanceError):
    def __init__(self, disposition_id: str) -> None:
        super().__init__(f"disposition request not found: {disposition_id}")
        self.disposition_id = disposition_id


class DispositionVersionConflictError(GovernanceError):
    def __init__(self, disposition_id: str, expected: int, actual: int) -> None:
        super().__init__(
            f"disposition request {disposition_id} was updated concurrently "
            f"(expected version {expected}, actual {actual})"
        )
        self.disposition_id = disposition_id
        self.expected = expected
        self.actual = actual


class DispositionStateError(GovernanceError):
    """A disposition transition is not allowed from the current state."""


class DispositionBlockedError(GovernanceError):
    """A disposition request cannot be created or approved."""

    def __init__(self, message: str, *, reason_codes: list[str] | None = None) -> None:
        super().__init__(message)
        self.reason_codes = sorted(set(reason_codes or []))


class ExportApprovalNotFoundError(GovernanceError):
    def __init__(self, approval_id: str) -> None:
        super().__init__(f"export approval request not found: {approval_id}")
        self.approval_id = approval_id


class ExportApprovalVersionConflictError(GovernanceError):
    def __init__(self, approval_id: str, expected: int, actual: int) -> None:
        super().__init__(
            f"export approval {approval_id} was updated concurrently "
            f"(expected version {expected}, actual {actual})"
        )
        self.approval_id = approval_id
        self.expected = expected
        self.actual = actual


class ExportApprovalStateError(GovernanceError):
    """An export approval transition is not allowed from the current state."""


class GovernanceAuditNotFoundError(GovernanceError):
    def __init__(self, event_id: str) -> None:
        super().__init__(f"governance audit event not found: {event_id}")
        self.event_id = event_id


class GovernanceReportError(GovernanceError):
    """A compliance-readiness report could not be generated."""


class IdempotencyConflictError(GovernanceError):
    """An idempotency key was reused for a different operation."""


__all__ = [
    "DispositionBlockedError",
    "DispositionNotFoundError",
    "DispositionStateError",
    "DispositionVersionConflictError",
    "EvaluationNotFoundError",
    "ExportApprovalNotFoundError",
    "ExportApprovalStateError",
    "ExportApprovalVersionConflictError",
    "GovernanceAuditNotFoundError",
    "GovernanceDisabledError",
    "GovernanceError",
    "GovernanceReportError",
    "IdempotencyConflictError",
    "LegalHoldNotFoundError",
    "LegalHoldStateError",
    "LegalHoldVersionConflictError",
    "PolicyNotFoundError",
    "PolicyValidationError",
    "PolicyVersionConflictError",
    "SeparationOfDutiesError",
]
