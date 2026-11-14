"""V37 governance-intelligence domain errors."""

from __future__ import annotations


class IntelligenceError(ValueError):
    """Base class for sanitized intelligence-domain failures."""


class IntelligenceDisabledError(IntelligenceError):
    """Governance intelligence is disabled or not initialized."""


class RiskModelNotFoundError(IntelligenceError):
    def __init__(self, model_id: str) -> None:
        super().__init__(f"governance risk model not found: {model_id}")
        self.model_id = model_id


class RiskModelVersionConflictError(IntelligenceError):
    def __init__(self, expected: int, actual: int) -> None:
        super().__init__(
            f"governance risk model was updated concurrently (expected version {expected}, actual {actual})"
        )
        self.expected = expected
        self.actual = actual


class SlaTargetNotFoundError(IntelligenceError):
    def __init__(self, target_key: str) -> None:
        super().__init__(f"governance SLA target not found: {target_key}")
        self.target_key = target_key


class SlaTargetVersionConflictError(IntelligenceError):
    def __init__(self, target_key: str, expected: int, actual: int) -> None:
        super().__init__(
            f"governance SLA target {target_key} was updated concurrently "
            f"(expected version {expected}, actual {actual})"
        )
        self.target_key = target_key
        self.expected = expected
        self.actual = actual


class RecommendationNotFoundError(IntelligenceError):
    def __init__(self, recommendation_id: str) -> None:
        super().__init__(f"governance recommendation not found: {recommendation_id}")
        self.recommendation_id = recommendation_id


class RiskCaseNotFoundError(IntelligenceError):
    def __init__(self, case_id: str) -> None:
        super().__init__(f"forensic case not found: {case_id}")
        self.case_id = case_id


class RecommendationVersionConflictError(IntelligenceError):
    def __init__(self, recommendation_id: str, expected: int, actual: int) -> None:
        super().__init__(
            f"governance recommendation {recommendation_id} was updated concurrently "
            f"(expected version {expected}, actual {actual})"
        )
        self.recommendation_id = recommendation_id
        self.expected = expected
        self.actual = actual


class RecommendationStateError(IntelligenceError):
    """A recommendation transition is not allowed from the current state."""


class SnapshotNotFoundError(IntelligenceError):
    def __init__(self, snapshot_id: str) -> None:
        super().__init__(f"governance snapshot not found: {snapshot_id}")
        self.snapshot_id = snapshot_id


class SnapshotIncompatibleError(IntelligenceError):
    """Two snapshots cannot be compared because their type or schema differs."""


class SnapshotIntegrityError(IntelligenceError):
    """A snapshot self-digest does not match its stored payload."""


class IntelligenceValidationError(IntelligenceError):
    """A request or configuration value is invalid."""


__all__ = [
    "IntelligenceDisabledError",
    "IntelligenceError",
    "IntelligenceValidationError",
    "RecommendationNotFoundError",
    "RecommendationStateError",
    "RecommendationVersionConflictError",
    "RiskCaseNotFoundError",
    "RiskModelNotFoundError",
    "RiskModelVersionConflictError",
    "SlaTargetNotFoundError",
    "SlaTargetVersionConflictError",
    "SnapshotIncompatibleError",
    "SnapshotIntegrityError",
    "SnapshotNotFoundError",
]
