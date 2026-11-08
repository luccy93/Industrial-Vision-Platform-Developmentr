"""Typed V33 integrity-audit errors.

These are domain errors, not HTTP concerns; the API layer maps them to the
existing error envelope. Messages never include raw evidence, credentials,
private keys, or absolute protected paths.
"""

from __future__ import annotations


class IntegrityAuditError(RuntimeError):
    """Base class for continuous-audit failures."""


class InvalidAuditScopeError(IntegrityAuditError, ValueError):
    """The requested scope list is empty, duplicated, unknown, or too large."""


class DuplicateAuditRunError(IntegrityAuditError):
    """A run with the same idempotency key or an active run already exists."""

    def __init__(self, existing_run_id: str | None = None) -> None:
        super().__init__("an audit run is already active or the idempotency key was already used")
        self.existing_run_id = existing_run_id


class AuditRunNotFoundError(IntegrityAuditError):
    """No audit run with the requested identifier exists."""


class AuditRunNotCancellableError(IntegrityAuditError):
    """The requested run is not running in this process, so it cannot be cancelled."""


class AuditCancelledError(IntegrityAuditError):
    """The operator or scheduler cancelled the audit gracefully."""


class AuditTimeoutError(IntegrityAuditError):
    """The bounded execution deadline expired."""


class MonitoringStoreUnavailable(IntegrityAuditError):
    """The isolated monitoring store cannot be opened or written."""


class MonitoringStoreError(IntegrityAuditError):
    """A monitoring-store operation failed unexpectedly."""


class AuditLimitError(IntegrityAuditError):
    """A configured resource bound was exceeded."""
