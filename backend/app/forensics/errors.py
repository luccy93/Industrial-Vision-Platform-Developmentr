"""V34 forensic domain errors (mapped to HTTP codes by the API layer)."""

from __future__ import annotations


class ForensicError(ValueError):
    """Base class for sanitized forensic-domain failures."""


class ForensicCaseNotFoundError(ForensicError):
    def __init__(self, case_id: str) -> None:
        super().__init__(f"forensic case not found: {case_id}")
        self.case_id = case_id


class ForensicExportNotFoundError(ForensicError):
    def __init__(self, export_id: str) -> None:
        super().__init__(f"forensic export not found: {export_id}")
        self.export_id = export_id


class ForensicNoteNotFoundError(ForensicError):
    def __init__(self, note_id: str) -> None:
        super().__init__(f"forensic note not found: {note_id}")
        self.note_id = note_id


class InvalidCaseTransitionError(ForensicError):
    def __init__(self, current: str, attempted: str) -> None:
        super().__init__(f"invalid forensic case transition: {current} -> {attempted}")
        self.current = current
        self.attempted = attempted


class CaseVersionConflictError(ForensicError):
    def __init__(self, case_id: str, expected: int, actual: int) -> None:
        super().__init__(
            f"forensic case {case_id} was updated concurrently (expected version {expected}, actual {actual})"
        )
        self.case_id = case_id
        self.expected = expected
        self.actual = actual


class NoteVersionConflictError(ForensicError):
    def __init__(self, note_id: str, expected: int, actual: int) -> None:
        super().__init__(
            f"forensic note {note_id} was updated concurrently (expected version {expected}, actual {actual})"
        )
        self.note_id = note_id
        self.expected = expected
        self.actual = actual


class DuplicateCaseError(ForensicError):
    """Idempotent creation returned an existing case; not an API failure."""

    def __init__(self, case_id: str, case_number: str) -> None:
        super().__init__(f"forensic case already exists: {case_number}")
        self.case_id = case_id
        self.case_number = case_number


class ResolutionRequirementsError(ForensicError):
    """A resolution/closure request lacks required evidence or acknowledgement."""


class UnresolvedCriticalFindingError(ForensicError):
    """A case cannot be silently closed while critical findings are unresolved."""


class EvidenceReferenceError(ForensicError):
    """An evidence reference is malformed or unsafe."""


class EvidencePathUnavailable(ForensicError):
    """The referenced artifact is not available; the reference is preserved."""


class ExportPolicyError(ForensicError):
    """The requested export violates the configured export policy."""


class ExportVerificationError(ForensicError):
    """A forensic package failed structural or digest verification."""


class ExportTooLargeError(ExportPolicyError):
    """A forensic package exceeds the bounded size or member count."""


class UnsafeArchivePathError(ExportVerificationError):
    """A forensic package contains an absolute, traversal, or symlink entry."""


class CorrelationError(ForensicError):
    """A finding cannot be deterministically correlated."""


__all__ = [
    "CaseVersionConflictError",
    "CorrelationError",
    "DuplicateCaseError",
    "EvidencePathUnavailable",
    "EvidenceReferenceError",
    "ExportPolicyError",
    "ExportTooLargeError",
    "ExportVerificationError",
    "ForensicCaseNotFoundError",
    "ForensicError",
    "ForensicExportNotFoundError",
    "ForensicNoteNotFoundError",
    "InvalidCaseTransitionError",
    "NoteVersionConflictError",
    "ResolutionRequirementsError",
    "UnresolvedCriticalFindingError",
    "UnsafeArchivePathError",
]
