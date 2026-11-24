"""Read-only V39 cross-domain reference resolution.

Every reference is resolved through the source domain's own repository. V39
never copies a source payload, fabricates a missing record, mutates a source
record, or elevates a caller beyond the source domain's read capability. Missing,
unavailable, unauthorized, and explicitly deleted sources are distinct states.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from backend.app.core.redaction import redact_text
from backend.app.governance.workflows.constants import (
    REFERENCE_DOMAIN_CAPABILITY,
    REFERENCE_DOMAIN_VALUES,
    ReferenceAvailability,
    ReferenceDomain,
)
from backend.app.governance.workflows.errors import WorkflowValidationError

_DELETED_STATUSES: frozenset[str] = frozenset({"DELETED", "PURGED", "DESTROYED", "DISPOSED", "EXPUNGED"})


def _label(*values: Any, limit: int = 200) -> str:
    for value in values:
        text = redact_text(str(value or "").strip())
        if text:
            return text[:limit]
    return ""


def _status(record: Mapping[str, Any]) -> str:
    return str(record.get("status") or record.get("governance_state") or "").upper()[:32]


def _availability_for(record: Mapping[str, Any]) -> str:
    if _status(record) in _DELETED_STATUSES:
        return ReferenceAvailability.DELETED.value
    return ReferenceAvailability.AVAILABLE.value


class ReferenceResolver:
    """Resolve V34-V38 source records without writing to any source domain."""

    def __init__(
        self,
        *,
        forensic_repository: Any = None,
        integrity_store: Any = None,
        governance_repository: Any = None,
        automation_repository: Any = None,
        intelligence_repository: Any = None,
        executive_repository: Any = None,
        authorized_capabilities: frozenset[str] | set[str] | None = None,
        capability_lookup: Callable[[str], bool] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._forensics = forensic_repository
        self._integrity = integrity_store
        self._governance = governance_repository
        self._automation = automation_repository
        self._intelligence = intelligence_repository
        self._executive = executive_repository
        self._authorized = frozenset(authorized_capabilities) if authorized_capabilities is not None else None
        self._capability_lookup = capability_lookup
        self._clock = clock or (lambda: datetime.now(UTC))

    def authorized(self, domain: str) -> bool:
        capability = REFERENCE_DOMAIN_CAPABILITY.get(str(domain).upper())
        if capability is None:
            return False
        if self._capability_lookup is not None:
            return bool(self._capability_lookup(capability))
        if self._authorized is None:
            return True
        return capability in self._authorized

    def resolve(self, domain: str, source_id: str) -> dict[str, Any]:
        """Resolve one source record into a bounded availability envelope."""
        normalized = str(domain or "").strip().upper()
        source = str(source_id or "").strip()
        if normalized not in REFERENCE_DOMAIN_VALUES:
            raise WorkflowValidationError(f"unsupported reference domain: {domain}")
        if not source or len(source) > 128:
            raise WorkflowValidationError("source_id is required and must be at most 128 characters")
        base = {
            "domain": normalized,
            "source_id": source,
            "availability": ReferenceAvailability.UNAVAILABLE.value,
            "source_label": "",
            "source_case_id": None,
            "source_status": "",
            "source_version": None,
            "checked_at": self._clock().astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "message": "",
            "source_mutated": False,
        }
        if not self.authorized(normalized):
            base["availability"] = ReferenceAvailability.UNAUTHORIZED.value
            base["message"] = "The caller lacks the source domain's own read capability."
            return base
        reader = self._reader(normalized)
        if reader is None:
            base["message"] = f"{normalized} source is not initialized in this deployment."
            return base
        try:
            record = reader(source)
        except Exception as exc:  # noqa: BLE001 - one unavailable source must not fabricate data
            base["availability"] = ReferenceAvailability.UNAVAILABLE.value
            base["message"] = f"{normalized} source could not be read ({type(exc).__name__})."
            return base
        if record is None:
            base["availability"] = ReferenceAvailability.MISSING.value
            base["message"] = "No source record exists for this identifier."
            return base
        if hasattr(record, "to_dict"):
            try:
                record = record.to_dict()
            except Exception:  # noqa: BLE001 - fall back to attribute reads
                record = {
                    key: getattr(record, key, None)
                    for key in ("finding_id", "severity", "reason_code", "artifact_id")
                }
        if not isinstance(record, Mapping):
            base["availability"] = ReferenceAvailability.UNAVAILABLE.value
            base["message"] = "The source record could not be interpreted safely."
            return base
        return self._envelope(normalized, source, record, base)

    # ------------------------------------------------------------------
    # Source readers
    # ------------------------------------------------------------------
    def _reader(self, domain: str) -> Callable[[str], Any] | None:
        if domain == ReferenceDomain.FORENSIC_CASE.value:
            return getattr(self._forensics, "get_case", None)
        if domain == ReferenceDomain.FORENSIC_FINDING.value:
            return getattr(self._integrity, "get_finding", None)
        if domain == ReferenceDomain.RETENTION_REVIEW.value:
            return getattr(self._governance, "get_evaluation", None)
        if domain == ReferenceDomain.LEGAL_HOLD.value:
            return getattr(self._governance, "get_hold", None)
        if domain == ReferenceDomain.DISPOSITION.value:
            return getattr(self._governance, "get_disposition", None)
        if domain == ReferenceDomain.EXPORT_APPROVAL.value:
            return getattr(self._governance, "get_export_approval", None)
        if domain == ReferenceDomain.AUTOMATION_JOB.value:
            return getattr(self._automation, "get_job", None)
        if domain == ReferenceDomain.RECOMMENDATION.value:
            return getattr(self._intelligence, "get_recommendation", None)
        if domain == ReferenceDomain.EXECUTIVE_ACTION.value:
            return getattr(self._executive, "get_action", None)
        return None

    def _envelope(
        self,
        domain: str,
        source_id: str,
        record: Mapping[str, Any],
        base: dict[str, Any],
    ) -> dict[str, Any]:
        status = _status(record)
        availability = _availability_for(record)
        case_id = str(record.get("case_id") or "").strip() or None
        if domain == ReferenceDomain.FORENSIC_CASE.value:
            case_id = str(record.get("case_id") or record.get("id") or source_id).strip() or source_id
        if domain == ReferenceDomain.FORENSIC_FINDING.value and case_id is None:
            correlation = None
            try:
                correlation = getattr(self._forensics, "find_correlation_by_finding_id", lambda _: None)(
                    source_id
                )
            except Exception:  # noqa: BLE001 - correlation is optional boundary evidence
                correlation = None
            if isinstance(correlation, Mapping):
                case_id = str(correlation.get("case_id") or "").strip() or None
        version = record.get("version")
        try:
            source_version = int(version) if version is not None else None
        except (TypeError, ValueError):
            source_version = None
        base.update(
            {
                "availability": availability,
                "source_label": _label(
                    record.get("title"),
                    record.get("name"),
                    record.get("case_number"),
                    record.get("hold_number"),
                    record.get("request_number"),
                    record.get("job_type"),
                    record.get("rule_id"),
                    record.get("approval_id"),
                    record.get("recommendation_id"),
                    record.get("finding_id"),
                    record.get("evaluation_id"),
                    source_id,
                ),
                "source_case_id": case_id,
                "source_status": status,
                "source_version": source_version,
                "message": (
                    "The source reports an explicit deleted or disposed status."
                    if availability == ReferenceAvailability.DELETED.value
                    else ""
                ),
            }
        )
        return base

    def reference_key(self, domain: str, source_id: str) -> str:
        return f"{str(domain).strip().upper()}:{str(source_id).strip()}"[:160]


__all__ = ["ReferenceResolver"]
