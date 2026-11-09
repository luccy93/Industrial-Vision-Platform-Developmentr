"""Explicit forensic case workflow validation (V34)."""

from __future__ import annotations

from backend.app.forensics.constants import (
    CLOSE_STATUSES,
    CaseStatus,
    is_reopen_allowed,
    is_transition_allowed,
)
from backend.app.forensics.errors import InvalidCaseTransitionError


def validate_case_transition(
    current: CaseStatus | str,
    target: CaseStatus | str,
    *,
    reopening: bool = False,
) -> None:
    """Validate one explicit transition; raise ``InvalidCaseTransitionError``."""
    current_status = current if isinstance(current, CaseStatus) else CaseStatus(str(current))
    target_status = target if isinstance(target, CaseStatus) else CaseStatus(str(target))
    if current_status is target_status:
        raise InvalidCaseTransitionError(current_status.value, target_status.value)
    if reopening:
        if not is_reopen_allowed(current_status, target_status):
            raise InvalidCaseTransitionError(current_status.value, target_status.value)
        return
    if not is_transition_allowed(current_status, target_status):
        raise InvalidCaseTransitionError(current_status.value, target_status.value)


def requires_close_capability(target: CaseStatus | str, *, reopening: bool = False) -> bool:
    status = target if isinstance(target, CaseStatus) else CaseStatus(str(target))
    return reopening or status in CLOSE_STATUSES


__all__ = ["requires_close_capability", "validate_case_transition"]
