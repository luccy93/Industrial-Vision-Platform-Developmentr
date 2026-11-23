"""V38 executive governance application service.

Coordinates read-only executive KPIs, the deterministic ``EXEC_HEALTH_V1``
health model, compatible historical comparisons, advisory strategic actions,
bounded local executive reports, and executive operational configuration on top
of the existing V10-V37 records.

The service never approves or releases a legal hold, decides a disposition,
modifies evidence, deletes a record, or executes a sensitive governance action.
Strategic actions never resolve a V37 recommendation automatically, and reports
are never emailed, published, exported to a third party, or rendered as PDF.
"""

from __future__ import annotations

import csv
import io
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from backend.app.core.logging import get_logger
from backend.app.core.metrics import (
    record_governance_executive_action_transition,
    record_governance_executive_comparison,
    record_governance_executive_report,
    set_governance_executive_action_counts,
    set_governance_executive_health,
    set_governance_executive_kpi_availability,
)
from backend.app.core.redaction import redact_structure
from backend.app.domain.common import utcnow
from backend.app.forensics.custody import canonical_json_bytes, sha256_hex
from backend.app.governance.constants import GovernanceAuditEventType
from backend.app.governance.executive.constants import (
    ACTION_STATUS_VALUES,
    ACTION_TERMINAL_STATUSES,
    ACTION_TRANSITIONS,
    ACTIONABLE_RECOMMENDATION_STATUSES,
    COMPARISON_COMPARABLE,
    COMPARISON_COMPATIBILITY_VERSION,
    COMPARISON_INCOMPATIBLE,
    COMPARISON_UNAVAILABLE,
    COVERAGE_COMPLETE,
    COVERAGE_PARTIAL,
    COVERAGE_UNAVAILABLE,
    DEFAULT_EXECUTIVE_CONFIG,
    DEFAULT_PAGE_SIZE,
    DEFAULT_WINDOW_DAYS,
    EXECUTIVE_ASSURANCE,
    EXECUTIVE_CONFIG_KEYS,
    EXECUTIVE_CONFIG_SCHEMA_VERSION,
    EXECUTIVE_CONFIG_SNAPSHOT_TYPE,
    EXECUTIVE_LIMITATIONS,
    EXECUTIVE_NON_CLAIMS,
    HEALTH_MODEL_VERSION,
    KPI_AVAILABLE,
    KPI_COUNT,
    KPI_DEFINITIONS,
    KPI_ORDER,
    KPI_PARTIAL,
    KPI_UNAVAILABLE,
    MAX_COMPARISON_DIFF_ITEMS,
    MAX_PAGE_SIZE,
    MAX_REPORT_CSV_BYTES,
    MAX_REPORT_PAYLOAD_BYTES,
    MAX_REPORT_ROWS,
    MAX_WINDOW_DAYS,
    MIN_REPORT_REASON_LENGTH,
    MIN_WINDOW_DAYS,
    REPORT_FORMAT_VALUES,
    REPORT_SCHEMA_VERSION,
    REPORT_SECTION_ORDER,
    REPORT_SNAPSHOT_TYPE_BY_REPORT,
    REPORT_TYPE_VALUES,
    ActionStatus,
    report_dedup_key,
)
from backend.app.governance.executive.errors import (
    ActionNotFoundError,
    ExecutiveConfigError,
    ExecutiveDisabledError,
    ExecutiveValidationError,
    RecommendationNotActionableError,
    RecommendationNotFoundForActionError,
    ReportIntegrityError,
    ReportNotFoundError,
    ReportUnavailableError,
)
from backend.app.governance.executive.health import evaluate_health
from backend.app.governance.executive.repository import report_digest_for

logger = get_logger(__name__)

_TERMINAL_CASE_STATUSES = frozenset({"RESOLVED", "CLOSED"})
_SLA_KNOWN_STATES = frozenset({"WITHIN_TARGET", "AT_RISK", "BREACHED", "MISSED"})
_SLA_COMPLIANT_STATES = frozenset({"WITHIN_TARGET", "AT_RISK"})
_SLA_BREACHED_STATES = frozenset({"BREACHED", "MISSED"})


def _as_utc(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _bounded_window_days(value: Any, default: int = DEFAULT_WINDOW_DAYS) -> int:
    if value is None:
        return max(MIN_WINDOW_DAYS, min(MAX_WINDOW_DAYS, int(default)))
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ExecutiveValidationError("window_days must be an integer") from None
    if parsed < MIN_WINDOW_DAYS or parsed > MAX_WINDOW_DAYS:
        raise ExecutiveValidationError(f"window_days must be between {MIN_WINDOW_DAYS} and {MAX_WINDOW_DAYS}")
    return parsed


def _completeness(
    status: str,
    *,
    known: int | None = None,
    unknown: int | None = None,
    total: int | None = None,
    message: str = "",
) -> dict[str, Any]:
    return {
        "status": status,
        "known": known,
        "unknown": unknown,
        "total": total,
        "message": message,
    }


def _kpi(
    kpi_id: str,
    *,
    window: Mapping[str, Any],
    calculated_at: datetime,
    availability: str,
    completeness: Mapping[str, Any],
    value: Any,
    applicable: bool = True,
    numerator: Any = None,
    denominator: Any = None,
    detail: Mapping[str, Any] | None = None,
    model_version: Any = None,
    policy_version: Any = None,
    unavailable_reason: str | None = None,
    source_refs: list[str] | None = None,
) -> dict[str, Any]:
    definition = KPI_DEFINITIONS[kpi_id]
    return {
        "kpi_id": kpi_id,
        "name": definition["name"],
        "definition": definition["definition"],
        "source": definition["source"],
        "unit": definition["unit"],
        "window": dict(window),
        "calculated_at": _iso(calculated_at),
        "availability": availability,
        "completeness": dict(completeness),
        "applicable": bool(applicable),
        "value": value,
        "numerator": numerator,
        "denominator": denominator,
        "detail": dict(detail or {}),
        "model_version": model_version,
        "policy_version": policy_version,
        "unavailable_reason": unavailable_reason,
        "source_refs": list(source_refs or []),
    }


def _source_coverage(kpis: list[Mapping[str, Any]]) -> dict[str, Any]:
    applicable = [kpi for kpi in kpis if bool(kpi.get("applicable", True))]
    available = [kpi for kpi in applicable if str(kpi.get("availability")) == KPI_AVAILABLE]
    partial = [kpi for kpi in applicable if str(kpi.get("availability")) == KPI_PARTIAL]
    unavailable = [kpi for kpi in applicable if str(kpi.get("availability")) == KPI_UNAVAILABLE]
    if not applicable or not available:
        status = COVERAGE_UNAVAILABLE
        message = (
            "No applicable executive KPI source could be read; the result is explicitly "
            "unavailable rather than zero."
        )
    elif partial or unavailable:
        status = COVERAGE_PARTIAL
        message = (
            "At least one applicable executive KPI source is partial or unavailable; the "
            "result is explicitly qualified."
        )
    else:
        status = COVERAGE_COMPLETE
        message = "Every applicable executive KPI source was available and complete."
    return {
        "status": status,
        "message": message,
        "applicable_kpis": len(applicable),
        "available_kpis": len(available),
        "partial_kpis": len(partial),
        "unavailable_kpis": len(unavailable),
        "partial_kpi_ids": sorted(str(kpi.get("kpi_id")) for kpi in partial),
        "unavailable_kpi_ids": sorted(str(kpi.get("kpi_id")) for kpi in unavailable),
    }


class GovernanceExecutiveService:
    """Executive aggregation, advisory actions, reports, and configuration."""

    def __init__(
        self,
        *,
        settings: Any,
        repository: Any,
        governance_service: Any,
        governance_repository: Any,
        forensic_repository: Any,
        forensic_service: Any,
        automation_repository: Any,
        intelligence_service: Any,
        intelligence_repository: Any,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._governance = governance_service
        self._governance_repository = governance_repository
        self._forensics = forensic_repository
        self._forensic_service = forensic_service or forensic_repository
        self._automation = automation_repository
        self._intelligence = intelligence_service
        self._intelligence_repository = intelligence_repository
        self._clock = clock or utcnow

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def _require_enabled(self) -> None:
        if not bool(getattr(self._settings, "governance_enabled", True)):
            raise ExecutiveDisabledError("governance is disabled")
        if not bool(getattr(self._settings, "governance_executive_enabled", True)):
            raise ExecutiveDisabledError("executive governance is disabled")

    def _safe_source(self, name: str, reader: Callable[[], Any]) -> tuple[Any, dict[str, Any]]:
        try:
            return reader(), {"name": name, "availability": "OK", "message": ""}
        except Exception as exc:  # noqa: BLE001 - one unavailable source must not break the page
            logger.warning("executive source %s could not be read", name, exc_info=True)
            return None, {
                "name": name,
                "availability": "UNAVAILABLE",
                "message": f"{name} could not be read ({type(exc).__name__}).",
            }

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        self._require_enabled()
        action_counts = self._repository.action_status_counts()
        report_counts = self._repository.report_type_counts()
        set_governance_executive_action_counts(action_counts)
        config_source = self._config_source_summary()
        return {
            "enabled": True,
            "assurance": EXECUTIVE_ASSURANCE,
            "health_model_version": HEALTH_MODEL_VERSION,
            "kpi_count": KPI_COUNT,
            "kpi_ids": list(KPI_ORDER),
            "action_counts": action_counts,
            "action_total": sum(int(value) for value in action_counts.values()),
            "report_counts": report_counts,
            "report_total": sum(int(value) for value in report_counts.values()),
            "config_source": config_source,
            "sources": {
                "forensic": "AVAILABLE" if self._forensic_service is not None else "UNAVAILABLE",
                "governance": "AVAILABLE" if self._governance is not None else "UNAVAILABLE",
                "automation": "AVAILABLE" if self._automation is not None else "UNAVAILABLE",
                "intelligence": "AVAILABLE" if self._intelligence is not None else "UNAVAILABLE",
                "snapshot_storage": "AVAILABLE" if self._automation is not None else "UNAVAILABLE",
            },
            "scheduled_executive": False,
            "scheduled_executive_note": (
                "V38 computes executive views on demand; no executive scheduler is started."
            ),
            "generated_at": _iso(self._clock()),
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
            "limitations": list(EXECUTIVE_LIMITATIONS),
        }

    # ------------------------------------------------------------------
    # KPIs
    # ------------------------------------------------------------------
    def kpis(
        self,
        *,
        window_days: int | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        days = _bounded_window_days(
            window_days,
            default=int(
                getattr(
                    self._settings,
                    "governance_executive_default_window_days",
                    DEFAULT_WINDOW_DAYS,
                )
            ),
        )
        moment = _as_utc(now) or _as_utc(self._clock()) or datetime.now(UTC)
        start = moment - timedelta(days=days)
        current_window = {"kind": "CURRENT_STATE", "as_of": _iso(moment)}
        rolling_window = {
            "kind": "ROLLING_WINDOW",
            "start_at": _iso(start),
            "end_at": _iso(moment),
            "days": days,
        }

        sources: dict[str, dict[str, Any]] = {}

        forensic_summary, forensic_source = self._safe_source(
            "forensic_cases", self._forensic_service.summary
        )
        sources["forensic_cases"] = forensic_source

        readiness, readiness_source = self._safe_source(
            "governance_readiness", self._governance.readiness_metrics
        )
        sources["governance_readiness"] = readiness_source

        policy_version: Any = None
        if self._governance_repository is not None:
            policy, policy_source = self._safe_source(
                "governance_policy",
                lambda: self._governance_repository.get_policy("POL-DEFAULT"),
            )
            sources["governance_policy"] = policy_source
            policy_version = (policy or {}).get("version")

        automation_queue: dict[str, int] | None = None
        automation_stale: int | None = None
        automation_failed: int | None = None
        automation_job_count: int | None = None
        if self._automation is None:
            sources["automation"] = {
                "name": "automation",
                "availability": "UNAVAILABLE",
                "message": "Governance automation storage is not initialized.",
            }
        else:
            automation_queue, queue_source = self._safe_source(
                "automation_queue", self._automation.queue_counts
            )
            sources["automation_queue"] = queue_source
            automation_stale, stale_source = self._safe_source(
                "automation_stale", lambda: self._automation.stale_job_count(now=moment)
            )
            sources["automation_stale"] = stale_source
            automation_failed, failed_source = self._safe_source(
                "automation_failed",
                lambda: self._automation.count_jobs_in_range(start=start, end=moment, status="FAILED"),
            )
            sources["automation_failed"] = failed_source
            automation_job_count, job_count_source = self._safe_source(
                "automation_job_count", self._automation.count_jobs
            )
            sources["automation_job_count"] = job_count_source

        recommendation_counts: dict[str, Any] | None = None
        risk_model: dict[str, Any] | None = None
        sla_backlog: dict[str, Any] | None = None
        if self._intelligence is None or self._intelligence_repository is None:
            sources["intelligence"] = {
                "name": "intelligence",
                "availability": "UNAVAILABLE",
                "message": "Governance intelligence is not initialized.",
            }
        else:
            recommendation_counts, recommendation_source = self._safe_source(
                "intelligence_recommendations",
                self._intelligence_repository.recommendation_counts,
            )
            sources["intelligence_recommendations"] = recommendation_source
            risk_model, model_source = self._safe_source(
                "intelligence_risk_model", self._intelligence_repository.latest_risk_model
            )
            sources["intelligence_risk_model"] = model_source
            sla_backlog, sla_source = self._safe_source(
                "intelligence_sla",
                lambda: self._intelligence.sla_backlog(page=1, page_size=1),
            )
            sources["intelligence_sla"] = sla_source

        kpis: list[dict[str, Any]] = []
        kpis.extend(
            self._forensic_kpis(
                forensic_summary,
                forensic_source,
                window=current_window,
                calculated_at=moment,
            )
        )
        kpis.extend(
            self._governance_kpis(
                readiness,
                readiness_source,
                policy_version=policy_version,
                window=current_window,
                calculated_at=moment,
            )
        )
        kpis.extend(
            self._automation_kpis(
                automation_queue,
                automation_stale,
                automation_failed,
                automation_job_count,
                sources,
                window=rolling_window,
                calculated_at=moment,
            )
        )
        kpis.extend(
            self._intelligence_kpis(
                recommendation_counts,
                risk_model,
                sla_backlog,
                sources,
                window=current_window,
                calculated_at=moment,
            )
        )
        by_id = {str(kpi["kpi_id"]): kpi for kpi in kpis}
        ordered = [by_id[kpi_id] for kpi_id in KPI_ORDER if kpi_id in by_id]
        coverage = _source_coverage(ordered)
        set_governance_executive_kpi_availability(
            {str(kpi["kpi_id"]): str(kpi["availability"]) for kpi in ordered}
        )
        return {
            "items": ordered,
            "total": len(ordered),
            "window": rolling_window,
            "window_days": days,
            "health_model_version": HEALTH_MODEL_VERSION,
            "source_coverage": coverage,
            "sources": sources,
            "calculated_at": _iso(moment),
            "assurance": EXECUTIVE_ASSURANCE,
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
            "limitations": list(EXECUTIVE_LIMITATIONS),
        }

    def _forensic_kpis(
        self,
        summary: Mapping[str, Any] | None,
        source: Mapping[str, Any],
        *,
        window: Mapping[str, Any],
        calculated_at: datetime,
    ) -> list[dict[str, Any]]:
        if summary is None:
            reason = str(source.get("message") or "Forensic summary is unavailable.")
            return [
                _kpi(
                    "FORENSIC_OPEN_CASES",
                    window=window,
                    calculated_at=calculated_at,
                    availability=KPI_UNAVAILABLE,
                    completeness=_completeness("UNAVAILABLE", message=reason),
                    value=None,
                    unavailable_reason="SOURCE_UNAVAILABLE",
                ),
                _kpi(
                    "FORENSIC_CRITICAL_CASES",
                    window=window,
                    calculated_at=calculated_at,
                    availability=KPI_UNAVAILABLE,
                    completeness=_completeness("UNAVAILABLE", message=reason),
                    value=None,
                    unavailable_reason="SOURCE_UNAVAILABLE",
                ),
                _kpi(
                    "INTEGRITY_CRITICAL_FINDINGS",
                    window={**dict(window), "kind": "LATEST_AUDIT_RUN"},
                    calculated_at=calculated_at,
                    availability=KPI_UNAVAILABLE,
                    completeness=_completeness("UNAVAILABLE", message=reason),
                    value=None,
                    unavailable_reason="SOURCE_UNAVAILABLE",
                ),
            ]
        by_status = {str(status): int(count) for status, count in (summary.get("by_status") or {}).items()}
        total = int(summary.get("total") or 0)
        terminal = sum(int(by_status.get(status, 0)) for status in _TERMINAL_CASE_STATUSES)
        open_cases = max(0, total - terminal)
        critical = int(summary.get("critical") or 0)
        integrity = summary.get("integrity_findings") or {}
        integrity_available = str(integrity.get("availability")) == "AVAILABLE"
        latest_audit_id = integrity.get("latest_audit_id")
        by_severity = {
            str(severity): int(count)
            for severity, count in (integrity.get("latest_findings_by_severity") or {}).items()
        }
        if not integrity_available:
            integrity_value = None
            integrity_availability = KPI_UNAVAILABLE
            integrity_completeness = _completeness(
                "UNAVAILABLE",
                message=str(integrity.get("message") or "The V33 integrity findings source is unavailable."),
            )
            integrity_reason = "SOURCE_UNAVAILABLE"
            integrity_applicable = True
        elif latest_audit_id is None:
            integrity_value = None
            integrity_availability = KPI_UNAVAILABLE
            integrity_completeness = _completeness(
                "UNAVAILABLE",
                message="No V33 integrity audit run is stored.",
            )
            integrity_reason = "NO_INTEGRITY_AUDIT_HISTORY"
            integrity_applicable = False
        else:
            integrity_value = int(by_severity.get("CRITICAL", 0))
            integrity_availability = KPI_AVAILABLE
            integrity_completeness = _completeness(
                "COMPLETE",
                known=integrity_value,
                unknown=0,
                total=integrity_value,
            )
            integrity_reason = None
            integrity_applicable = True
        return [
            _kpi(
                "FORENSIC_OPEN_CASES",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_AVAILABLE,
                completeness=_completeness("COMPLETE", known=open_cases, unknown=0, total=open_cases),
                value=open_cases,
                detail={
                    "total_cases": total,
                    "terminal_cases": terminal,
                    "by_status": by_status,
                },
            ),
            _kpi(
                "FORENSIC_CRITICAL_CASES",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_AVAILABLE,
                completeness=_completeness("COMPLETE", known=critical, unknown=0, total=critical),
                value=critical,
                detail={"by_severity": dict(summary.get("by_severity") or {})},
            ),
            _kpi(
                "INTEGRITY_CRITICAL_FINDINGS",
                window={**dict(window), "kind": "LATEST_AUDIT_RUN"},
                calculated_at=calculated_at,
                availability=integrity_availability,
                completeness=integrity_completeness,
                value=integrity_value,
                applicable=integrity_applicable,
                unavailable_reason=integrity_reason,
                detail={
                    "latest_audit_id": latest_audit_id,
                    "latest_audit_status": integrity.get("latest_audit_status"),
                    "latest_findings": integrity.get("latest_findings"),
                    "latest_findings_by_severity": by_severity,
                },
                source_refs=([f"integrity_audit:{latest_audit_id}"] if latest_audit_id else []),
            ),
        ]

    def _governance_kpis(
        self,
        readiness: Mapping[str, Any] | None,
        source: Mapping[str, Any],
        *,
        policy_version: Any,
        window: Mapping[str, Any],
        calculated_at: datetime,
    ) -> list[dict[str, Any]]:
        if readiness is None:
            reason = str(source.get("message") or "Governance readiness is unavailable.")
            return [
                _kpi(
                    kpi_id,
                    window=window,
                    calculated_at=calculated_at,
                    availability=KPI_UNAVAILABLE,
                    completeness=_completeness("UNAVAILABLE", message=reason),
                    value=None,
                    policy_version=policy_version,
                    unavailable_reason="SOURCE_UNAVAILABLE",
                )
                for kpi_id in (
                    "GOVERNANCE_OVERDUE_REVIEWS",
                    "GOVERNANCE_RETENTION_DUE",
                    "GOVERNANCE_BLOCKING_HOLDS",
                    "GOVERNANCE_OLDEST_BLOCKING_HOLD_AGE_HOURS",
                    "GOVERNANCE_OPEN_DISPOSITIONS",
                    "GOVERNANCE_PENDING_EXPORT_APPROVALS",
                )
            ]
        evaluations = list(readiness.get("evaluations") or [])
        next_review_known = int(readiness.get("next_review_known") or 0)
        next_review_unknown = int(readiness.get("next_review_unknown") or 0)
        deadline_known = int(readiness.get("retention_deadline_known") or 0)
        deadline_unknown = int(readiness.get("retention_deadline_unknown") or 0)
        truncated = bool(readiness.get("evaluations_truncated"))
        if not evaluations:
            overdue = _kpi(
                "GOVERNANCE_OVERDUE_REVIEWS",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_UNAVAILABLE,
                completeness=_completeness("UNAVAILABLE", message="No V35 retention evaluation is stored."),
                value=None,
                applicable=False,
                policy_version=policy_version,
                unavailable_reason="NO_RETENTION_EVALUATIONS",
            )
            retention_due = _kpi(
                "GOVERNANCE_RETENTION_DUE",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_UNAVAILABLE,
                completeness=_completeness("UNAVAILABLE", message="No V35 retention evaluation is stored."),
                value=None,
                applicable=False,
                policy_version=policy_version,
                unavailable_reason="NO_RETENTION_EVALUATIONS",
            )
        else:
            overdue_value = 0
            deadline_value = 0
            for item in evaluations:
                next_review = _as_utc(item.get("next_review_at"))
                if next_review is not None and next_review < calculated_at:
                    overdue_value += 1
                deadline = _as_utc(item.get("retention_deadline"))
                if deadline is not None and deadline <= calculated_at:
                    deadline_value += 1
            overdue_status = KPI_PARTIAL if next_review_unknown or truncated else KPI_AVAILABLE
            deadline_status = KPI_PARTIAL if deadline_unknown or truncated else KPI_AVAILABLE
            overdue = _kpi(
                "GOVERNANCE_OVERDUE_REVIEWS",
                window=window,
                calculated_at=calculated_at,
                availability=overdue_status,
                completeness=_completeness(
                    "PARTIAL" if next_review_unknown or truncated else "COMPLETE",
                    known=next_review_known,
                    unknown=next_review_unknown,
                    total=len(evaluations),
                    message=(
                        "Some evaluations have no stored next-review time or the source was truncated."
                        if next_review_unknown or truncated
                        else ""
                    ),
                ),
                value=overdue_value,
                policy_version=policy_version,
                detail={
                    "evaluated_cases": len(evaluations),
                    "truncated": truncated,
                },
            )
            retention_due = _kpi(
                "GOVERNANCE_RETENTION_DUE",
                window=window,
                calculated_at=calculated_at,
                availability=deadline_status,
                completeness=_completeness(
                    "PARTIAL" if deadline_unknown or truncated else "COMPLETE",
                    known=deadline_known,
                    unknown=deadline_unknown,
                    total=len(evaluations),
                    message=(
                        "Some evaluations have no stored retention deadline or the source was truncated."
                        if deadline_unknown or truncated
                        else ""
                    ),
                ),
                value=deadline_value,
                policy_version=policy_version,
                detail={
                    "evaluated_cases": len(evaluations),
                    "truncated": truncated,
                },
            )
        blocking_holds = int(readiness.get("blocking_hold_count") or 0)
        hold_states = dict(readiness.get("hold_states") or {})
        oldest_at = _as_utc(readiness.get("oldest_blocking_requested_at"))
        if blocking_holds == 0:
            oldest_age = _kpi(
                "GOVERNANCE_OLDEST_BLOCKING_HOLD_AGE_HOURS",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_UNAVAILABLE,
                completeness=_completeness(
                    "UNAVAILABLE",
                    message="No blocking legal hold exists; the age KPI is not applicable.",
                ),
                value=None,
                applicable=False,
                policy_version=policy_version,
                unavailable_reason="NO_BLOCKING_HOLDS",
            )
        elif oldest_at is None:
            oldest_age = _kpi(
                "GOVERNANCE_OLDEST_BLOCKING_HOLD_AGE_HOURS",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_UNAVAILABLE,
                completeness=_completeness(
                    "UNAVAILABLE",
                    message="The oldest blocking hold timestamp could not be parsed.",
                ),
                value=None,
                policy_version=policy_version,
                unavailable_reason="OLDEST_HOLD_TIMESTAMP_UNAVAILABLE",
            )
        else:
            age_hours = max(0.0, round((calculated_at - oldest_at).total_seconds() / 3600.0, 2))
            oldest_age = _kpi(
                "GOVERNANCE_OLDEST_BLOCKING_HOLD_AGE_HOURS",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_AVAILABLE,
                completeness=_completeness("COMPLETE", known=blocking_holds, unknown=0, total=blocking_holds),
                value=age_hours,
                policy_version=policy_version,
                detail={
                    "oldest_blocking_requested_at": _iso(oldest_at),
                    "blocking_hold_count": blocking_holds,
                },
            )
        open_dispositions = int(readiness.get("open_disposition_count") or 0)
        pending_exports = int(readiness.get("pending_export_approvals") or 0)
        return [
            overdue,
            retention_due,
            _kpi(
                "GOVERNANCE_BLOCKING_HOLDS",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_AVAILABLE,
                completeness=_completeness("COMPLETE", known=blocking_holds, unknown=0, total=blocking_holds),
                value=blocking_holds,
                policy_version=policy_version,
                detail={"hold_states": hold_states},
            ),
            oldest_age,
            _kpi(
                "GOVERNANCE_OPEN_DISPOSITIONS",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_AVAILABLE,
                completeness=_completeness(
                    "COMPLETE",
                    known=open_dispositions,
                    unknown=0,
                    total=open_dispositions,
                ),
                value=open_dispositions,
                policy_version=policy_version,
                detail={"disposition_states": dict(readiness.get("disposition_states") or {})},
            ),
            _kpi(
                "GOVERNANCE_PENDING_EXPORT_APPROVALS",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_AVAILABLE,
                completeness=_completeness(
                    "COMPLETE",
                    known=pending_exports,
                    unknown=0,
                    total=pending_exports,
                ),
                value=pending_exports,
                policy_version=policy_version,
                detail={"export_states": dict(readiness.get("export_states") or {})},
            ),
        ]

    def _automation_kpis(
        self,
        queue: Mapping[str, Any] | None,
        stale: int | None,
        failed: int | None,
        job_count: int | None,
        sources: Mapping[str, Mapping[str, Any]],
        *,
        window: Mapping[str, Any],
        calculated_at: datetime,
    ) -> list[dict[str, Any]]:
        queue_status = str((sources.get("automation_queue") or {}).get("availability"))
        stale_status = str((sources.get("automation_stale") or {}).get("availability"))
        failed_status = str((sources.get("automation_failed") or {}).get("availability"))
        job_count_status = str((sources.get("automation_job_count") or {}).get("availability"))
        queue_available = queue_status == "OK" and queue is not None
        stale_available = stale_status == "OK" and stale is not None
        failed_available = failed_status == "OK" and failed is not None
        job_count_available = job_count_status == "OK" and job_count is not None
        if failed_available:
            failed_kpi = _kpi(
                "AUTOMATION_FAILED_JOBS",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_AVAILABLE,
                completeness=_completeness("COMPLETE", known=int(failed), unknown=0, total=int(failed)),
                value=int(failed),
                detail={
                    "job_count": int(job_count) if job_count_available else None,
                    "queue": dict(queue) if queue_available else None,
                },
            )
        else:
            failed_kpi = _kpi(
                "AUTOMATION_FAILED_JOBS",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_UNAVAILABLE,
                completeness=_completeness(
                    "UNAVAILABLE",
                    message=str(
                        (sources.get("automation_failed") or {}).get("message")
                        or "Automation jobs are unavailable."
                    ),
                ),
                value=None,
                unavailable_reason="SOURCE_UNAVAILABLE",
            )
        if stale_available:
            stale_kpi = _kpi(
                "AUTOMATION_STALE_JOBS",
                window={**dict(window), "kind": "CURRENT_STATE", "as_of": _iso(calculated_at)},
                calculated_at=calculated_at,
                availability=KPI_AVAILABLE,
                completeness=_completeness("COMPLETE", known=int(stale), unknown=0, total=int(stale)),
                value=int(stale),
                detail={
                    "queue": dict(queue) if queue_available else None,
                    "job_count": int(job_count) if job_count_available else None,
                },
            )
        else:
            stale_kpi = _kpi(
                "AUTOMATION_STALE_JOBS",
                window={**dict(window), "kind": "CURRENT_STATE", "as_of": _iso(calculated_at)},
                calculated_at=calculated_at,
                availability=KPI_UNAVAILABLE,
                completeness=_completeness(
                    "UNAVAILABLE",
                    message=str(
                        (sources.get("automation_stale") or {}).get("message")
                        or "Automation jobs are unavailable."
                    ),
                ),
                value=None,
                unavailable_reason="SOURCE_UNAVAILABLE",
            )
        return [failed_kpi, stale_kpi]

    def _intelligence_kpis(
        self,
        recommendation_counts: Mapping[str, Any] | None,
        risk_model: Mapping[str, Any] | None,
        sla_backlog: Mapping[str, Any] | None,
        sources: Mapping[str, Mapping[str, Any]],
        *,
        window: Mapping[str, Any],
        calculated_at: datetime,
    ) -> list[dict[str, Any]]:
        model_version = (risk_model or {}).get("version")
        recommendation_status = str((sources.get("intelligence_recommendations") or {}).get("availability"))
        if recommendation_counts is not None and recommendation_status == "OK":
            by_status = {
                str(status): int(count)
                for status, count in (recommendation_counts.get("by_status") or {}).items()
            }
            by_status_severity = recommendation_counts.get("by_status_severity") or {}
            open_count = int(by_status.get("OPEN", 0)) + int(by_status.get("ACKNOWLEDGED", 0))
            critical_count = 0
            for status in ("OPEN", "ACKNOWLEDGED"):
                critical_count += int((by_status_severity.get(status) or {}).get("CRITICAL", 0))
            open_kpi = _kpi(
                "RECOMMENDATIONS_OPEN",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_AVAILABLE,
                completeness=_completeness("COMPLETE", known=open_count, unknown=0, total=open_count),
                value=open_count,
                model_version=model_version,
                detail={"by_status": by_status},
            )
            critical_kpi = _kpi(
                "RECOMMENDATIONS_OPEN_CRITICAL",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_AVAILABLE,
                completeness=_completeness("COMPLETE", known=critical_count, unknown=0, total=critical_count),
                value=critical_count,
                model_version=model_version,
                detail={"by_status_severity": by_status_severity},
            )
        else:
            reason = str(
                (sources.get("intelligence_recommendations") or {}).get("message")
                or "Governance recommendations are unavailable."
            )
            open_kpi = _kpi(
                "RECOMMENDATIONS_OPEN",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_UNAVAILABLE,
                completeness=_completeness("UNAVAILABLE", message=reason),
                value=None,
                model_version=model_version,
                unavailable_reason="SOURCE_UNAVAILABLE",
            )
            critical_kpi = _kpi(
                "RECOMMENDATIONS_OPEN_CRITICAL",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_UNAVAILABLE,
                completeness=_completeness("UNAVAILABLE", message=reason),
                value=None,
                model_version=model_version,
                unavailable_reason="SOURCE_UNAVAILABLE",
            )
        sla_status = str((sources.get("intelligence_sla") or {}).get("availability"))
        if sla_backlog is None or sla_status != "OK":
            reason = str(
                (sources.get("intelligence_sla") or {}).get("message")
                or "The operational SLA backlog is unavailable."
            )
            breached_kpi = _kpi(
                "SLA_BREACHED_ITEMS",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_UNAVAILABLE,
                completeness=_completeness("UNAVAILABLE", message=reason),
                value=None,
                model_version=model_version,
                unavailable_reason="SOURCE_UNAVAILABLE",
            )
            ratio_kpi = _kpi(
                "SLA_COMPLIANCE_RATIO",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_UNAVAILABLE,
                completeness=_completeness("UNAVAILABLE", message=reason),
                value=None,
                model_version=model_version,
                unavailable_reason="SOURCE_UNAVAILABLE",
            )
            return [open_kpi, critical_kpi, breached_kpi, ratio_kpi]

        state_counts = sla_backlog.get("state_counts") or {}
        availability_map = sla_backlog.get("availability") or {}
        unavailable_sources = list(sla_backlog.get("unavailable_sources") or [])
        truncated = bool(sla_backlog.get("truncated"))
        totals = {
            "WITHIN_TARGET": 0,
            "AT_RISK": 0,
            "BREACHED": 0,
            "MISSED": 0,
            "UNKNOWN": 0,
            "NOT_APPLICABLE": 0,
        }
        per_target: dict[str, Any] = {}
        for target_key, states in state_counts.items():
            target_states = {str(state): int(count) for state, count in (states or {}).items()}
            for state, count in target_states.items():
                if state in totals:
                    totals[state] += int(count)
            numerator = sum(int(target_states.get(state, 0)) for state in _SLA_COMPLIANT_STATES)
            denominator = sum(int(target_states.get(state, 0)) for state in _SLA_KNOWN_STATES)
            per_target[str(target_key)] = {
                "numerator": numerator,
                "denominator": denominator,
                "ratio": round(numerator / denominator, 4) if denominator else None,
                "states": target_states,
                "source_availability": (availability_map.get(target_key) or {}).get("availability"),
            }
        numerator_total = sum(int(totals[state]) for state in _SLA_COMPLIANT_STATES)
        denominator_total = sum(int(totals[state]) for state in _SLA_KNOWN_STATES)
        breached_total = sum(int(totals[state]) for state in _SLA_BREACHED_STATES)
        unknown_total = int(totals["UNKNOWN"]) + int(totals["NOT_APPLICABLE"])
        partial = bool(unavailable_sources or truncated)
        sla_availability = KPI_PARTIAL if partial else KPI_AVAILABLE
        completeness_message = (
            "Some SLA sources are unavailable or the backlog was truncated; the value covers "
            "known items only."
            if partial
            else ""
        )
        breached_kpi = _kpi(
            "SLA_BREACHED_ITEMS",
            window=window,
            calculated_at=calculated_at,
            availability=sla_availability,
            completeness=_completeness(
                "PARTIAL" if partial else "COMPLETE",
                known=denominator_total,
                unknown=unknown_total,
                total=denominator_total + unknown_total,
                message=completeness_message,
            ),
            value=breached_total,
            model_version=model_version,
            detail={
                "state_counts": state_counts,
                "per_target": per_target,
                "unavailable_sources": unavailable_sources,
                "truncated": truncated,
            },
        )
        if denominator_total == 0:
            ratio_kpi = _kpi(
                "SLA_COMPLIANCE_RATIO",
                window=window,
                calculated_at=calculated_at,
                availability=KPI_UNAVAILABLE,
                completeness=_completeness(
                    "UNAVAILABLE",
                    known=0,
                    unknown=unknown_total,
                    total=unknown_total,
                    message="No known operational SLA item is available for the ratio.",
                ),
                value=None,
                applicable=False,
                numerator=0,
                denominator=0,
                model_version=model_version,
                unavailable_reason="NO_KNOWN_SLA_ITEMS",
                detail={"per_target": per_target},
            )
        else:
            ratio_kpi = _kpi(
                "SLA_COMPLIANCE_RATIO",
                window=window,
                calculated_at=calculated_at,
                availability=sla_availability,
                completeness=_completeness(
                    "PARTIAL" if partial else "COMPLETE",
                    known=denominator_total,
                    unknown=unknown_total,
                    total=denominator_total + unknown_total,
                    message=completeness_message,
                ),
                value=round(numerator_total / denominator_total, 4),
                numerator=numerator_total,
                denominator=denominator_total,
                model_version=model_version,
                detail={
                    "per_target": per_target,
                    "state_counts": state_counts,
                    "unavailable_sources": unavailable_sources,
                    "truncated": truncated,
                    "excluded_unknown": unknown_total,
                    "definition": KPI_DEFINITIONS["SLA_COMPLIANCE_RATIO"]["definition"],
                },
            )
        return [open_kpi, critical_kpi, breached_kpi, ratio_kpi]

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------
    def health(
        self,
        *,
        window_days: int | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        kpi_payload = self.kpis(window_days=window_days, now=now)
        moment = _as_utc(now) or _as_utc(self._clock()) or datetime.now(UTC)
        evaluated = evaluate_health(
            kpi_payload["items"],
            calculated_at=moment,
            model_version=HEALTH_MODEL_VERSION,
        )
        set_governance_executive_health(str(evaluated["overall_status"]))
        return {
            "health": evaluated,
            "kpi_summary": [
                {
                    "kpi_id": kpi["kpi_id"],
                    "name": kpi["name"],
                    "value": kpi["value"],
                    "unit": kpi["unit"],
                    "availability": kpi["availability"],
                    "completeness": kpi["completeness"],
                    "applicable": kpi["applicable"],
                    "model_version": kpi["model_version"],
                    "policy_version": kpi["policy_version"],
                }
                for kpi in kpi_payload["items"]
            ],
            "window": kpi_payload["window"],
            "window_days": kpi_payload["window_days"],
            "source_coverage": kpi_payload["source_coverage"],
            "sources": kpi_payload["sources"],
            "calculated_at": _iso(moment),
            "assurance": EXECUTIVE_ASSURANCE,
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
            "limitations": list(EXECUTIVE_LIMITATIONS),
        }

    # ------------------------------------------------------------------
    # Configuration (read-only in commit 1)
    # ------------------------------------------------------------------
    def _config_source_summary(self) -> dict[str, Any]:
        if self._automation is None:
            return {
                "availability": "UNAVAILABLE",
                "message": "Governance snapshot storage is not initialized.",
                "snapshot_id": None,
            }
        try:
            items, _ = self._automation.list_snapshots(
                snapshot_type=EXECUTIVE_CONFIG_SNAPSHOT_TYPE, page=1, page_size=1
            )
        except Exception as exc:  # noqa: BLE001
            return {
                "availability": "UNAVAILABLE",
                "message": f"Executive configuration could not be read ({type(exc).__name__}).",
                "snapshot_id": None,
            }
        if not items:
            return {
                "availability": "DEFAULT",
                "message": "No stored executive configuration; bounded defaults apply.",
                "snapshot_id": None,
            }
        snapshot = items[0]
        return {
            "availability": "OK" if snapshot.get("digest_valid") else "INTEGRITY_FAILED",
            "message": (
                ""
                if snapshot.get("digest_valid")
                else "The stored executive configuration failed self-digest validation."
            ),
            "snapshot_id": snapshot.get("snapshot_id"),
            "generated_at": snapshot.get("generated_at"),
        }

    def config(self) -> dict[str, Any]:
        self._require_enabled()
        summary = self._config_source_summary()
        config = dict(DEFAULT_EXECUTIVE_CONFIG)
        availability = str(summary.get("availability") or "UNAVAILABLE")
        message = str(summary.get("message") or "")
        source: dict[str, Any] = {
            "snapshot_id": summary.get("snapshot_id"),
            "generated_at": summary.get("generated_at"),
            "digest_valid": availability == "OK",
        }
        if availability == "OK" and summary.get("snapshot_id") and self._automation is not None:
            try:
                snapshot = self._automation.get_snapshot(str(summary["snapshot_id"]))
            except Exception as exc:  # noqa: BLE001
                snapshot = None
                availability = "UNAVAILABLE"
                message = f"Executive configuration could not be read ({type(exc).__name__})."
            if snapshot is not None:
                source["generated_by"] = snapshot.get("generated_by")
                source["payload_digest"] = snapshot.get("payload_digest")
                source["schema_version"] = snapshot.get("schema_version")
                source["digest_valid"] = bool(snapshot.get("digest_valid"))
                if not snapshot.get("digest_valid"):
                    availability = "INTEGRITY_FAILED"
                    message = (
                        "The stored executive configuration failed self-digest validation; "
                        "bounded defaults are shown instead."
                    )
                else:
                    payload = snapshot.get("payload") or {}
                    stored = payload.get("config") if isinstance(payload, Mapping) else None
                    if isinstance(stored, Mapping):
                        candidate = {**config, **dict(stored)}
                        try:
                            config = self._validate_config(candidate)
                        except ExecutiveValidationError as exc:
                            availability = "INVALID"
                            message = f"Stored executive configuration is invalid: {exc}"
                    else:
                        availability = "INVALID"
                        message = "Stored executive configuration has no config object."
        return {
            "config": config,
            "schema_version": EXECUTIVE_CONFIG_SCHEMA_VERSION,
            "availability": availability,
            "message": message,
            "source": source,
            "fixed_health_model_version": HEALTH_MODEL_VERSION,
            "health_thresholds_fixed": True,
            "assurance": EXECUTIVE_ASSURANCE,
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
            "limitations": list(EXECUTIVE_LIMITATIONS),
        }

    @staticmethod
    def _validate_config(value: Mapping[str, Any]) -> dict[str, Any]:
        unknown = sorted(set(map(str, value)) - EXECUTIVE_CONFIG_KEYS)
        if unknown:
            raise ExecutiveValidationError(f"unknown executive configuration keys: {', '.join(unknown)}")
        normalized = dict(DEFAULT_EXECUTIVE_CONFIG)
        for key in EXECUTIVE_CONFIG_KEYS:
            if key in value:
                normalized[key] = value[key]
        window = int(normalized["default_window_days"])
        if window < MIN_WINDOW_DAYS or window > MAX_WINDOW_DAYS:
            raise ExecutiveValidationError(
                f"default_window_days must be between {MIN_WINDOW_DAYS} and {MAX_WINDOW_DAYS}"
            )
        comparison = int(normalized["comparison_period_days"])
        if comparison < MIN_WINDOW_DAYS or comparison > MAX_WINDOW_DAYS:
            raise ExecutiveValidationError(
                f"comparison_period_days must be between {MIN_WINDOW_DAYS} and {MAX_WINDOW_DAYS}"
            )
        due_soon = int(normalized["action_due_soon_hours"])
        if due_soon < 1 or due_soon > 720:
            raise ExecutiveValidationError("action_due_soon_hours must be between 1 and 720")
        report_rows = int(normalized["report_max_rows"])
        if report_rows < 50 or report_rows > 5000:
            raise ExecutiveValidationError("report_max_rows must be between 50 and 5000")
        if not isinstance(normalized["include_recommendations_in_summary"], bool):
            raise ExecutiveValidationError("include_recommendations_in_summary must be a boolean")
        if normalized["health_thresholds_fixed"] is not True:
            raise ExecutiveValidationError("health_thresholds_fixed is fixed by EXEC_HEALTH_V1")
        normalized["default_window_days"] = window
        normalized["comparison_period_days"] = comparison
        normalized["action_due_soon_hours"] = due_soon
        normalized["report_max_rows"] = report_rows
        return normalized

    # ------------------------------------------------------------------
    # Strategic actions
    # ------------------------------------------------------------------
    def create_action(
        self,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        recommendation_id = str(payload.get("recommendation_id") or "").strip()
        if not recommendation_id:
            raise ExecutiveValidationError("recommendation_id is required")
        idempotency_key = str(payload.get("idempotency_key") or "").strip()
        if not idempotency_key:
            raise ExecutiveValidationError("idempotency_key is required")
        if self._intelligence_repository is None:
            raise ExecutiveDisabledError("governance intelligence is not initialized")
        recommendation = self._intelligence_repository.get_recommendation(recommendation_id)
        if recommendation is None:
            raise RecommendationNotFoundForActionError(recommendation_id)
        recommendation_status = str(recommendation.get("status") or "").upper()
        if recommendation_status not in ACTIONABLE_RECOMMENDATION_STATUSES:
            raise RecommendationNotActionableError(
                f"recommendation {recommendation_id} is {recommendation_status}"
            )
        title = str(payload.get("title") or "").strip()
        owner_id = str(payload.get("owner_id") or "").strip()
        if len(title) < 3:
            raise ExecutiveValidationError("title must be at least 3 characters")
        if not owner_id:
            raise ExecutiveValidationError("owner_id is required")
        due_at = _as_utc(payload.get("due_at"))
        if due_at is None:
            raise ExecutiveValidationError("due_at must be a valid timestamp")
        now = _as_utc(self._clock()) or datetime.now(UTC)
        if due_at <= now:
            raise ExecutiveValidationError("due_at must be in the future")
        priority = str(payload.get("priority") or "MEDIUM").upper()
        if priority not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ExecutiveValidationError(f"unsupported action priority: {priority}")
        action, created = self._repository.create_action(
            recommendation_id=recommendation_id,
            recommendation_rule_id=str(recommendation.get("rule_id") or ""),
            recommendation_severity=str(recommendation.get("severity") or ""),
            case_id=recommendation.get("case_id"),
            title=title,
            description=str(payload.get("description") or ""),
            owner_id=owner_id,
            due_at=due_at,
            priority=priority,
            created_by=str(actor_id or "SYSTEM"),
            idempotency_key=idempotency_key,
            actor_role=actor_role,
            now=now,
        )
        replayed = not created
        if created:
            self._audit(
                event_type=GovernanceAuditEventType.EXECUTIVE_ACTION_CREATED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="EXECUTIVE_ACTION",
                target_id=str(action["action_id"]),
                case_id=action.get("case_id"),
                reason=str(payload.get("reason") or "Strategic action created."),
                request_id=request_id,
                metadata={
                    "recommendation_id": recommendation_id,
                    "owner_id": owner_id,
                    "priority": priority,
                },
            )
        self._refresh_action_metrics()
        return {
            "action": action,
            "events": self._repository.action_events(str(action["action_id"])),
            "replayed": replayed,
            "recommendation_status": recommendation_status,
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
        }

    def list_actions(
        self,
        *,
        status: str | None = None,
        owner_id: str | None = None,
        recommendation_id: str | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        normalized_status = str(status).upper() if status else None
        if normalized_status and normalized_status not in ACTION_STATUS_VALUES:
            raise ExecutiveValidationError(f"unsupported executive action status: {status}")
        items, total = self._repository.list_actions(
            status=normalized_status,
            owner_id=owner_id,
            recommendation_id=recommendation_id,
            page=max(1, int(page)),
            page_size=self._page_size(page_size),
        )
        return {
            "items": items,
            "total": total,
            "page": max(1, int(page)),
            "page_size": self._page_size(page_size),
            "status_counts": self._repository.action_status_counts(),
            "lifecycle": {
                "statuses": list(ACTION_STATUS_VALUES),
                "transitions": {key: sorted(value) for key, value in ACTION_TRANSITIONS.items()},
                "terminal": sorted(ACTION_TERMINAL_STATUSES),
            },
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
        }

    def action_detail(self, action_id: str) -> dict[str, Any]:
        self._require_enabled()
        action = self._repository.get_action(action_id)
        if action is None:
            raise ActionNotFoundError(action_id)
        return {
            "action": action,
            "events": self._repository.action_events(action_id),
            "linked_recommendation": self._linked_recommendation(action),
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
        }

    def transition_action(
        self,
        action_id: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        target_status = str(payload.get("target_status") or "").upper()
        if target_status not in ACTION_STATUS_VALUES:
            raise ExecutiveValidationError(f"unsupported executive action status: {target_status}")
        expected_version = int(payload.get("expected_version") or 0)
        if expected_version < 1:
            raise ExecutiveValidationError("expected_version must be at least 1")
        reason = str(payload.get("reason") or "").strip()
        outcome_summary = str(payload.get("outcome_summary") or "").strip()
        block_reason = str(payload.get("block_reason") or "").strip()
        cancel_reason = str(payload.get("cancel_reason") or "").strip()
        if target_status == ActionStatus.COMPLETED.value and len(outcome_summary) < 3:
            raise ExecutiveValidationError("completion requires an outcome summary of at least 3 characters")
        if target_status == ActionStatus.BLOCKED.value and len(block_reason or reason) < 3:
            raise ExecutiveValidationError("blocking requires a block reason of at least 3 characters")
        if target_status == ActionStatus.CANCELLED.value and len(cancel_reason or reason) < 3:
            raise ExecutiveValidationError(
                "cancellation requires a cancellation reason of at least 3 characters"
            )
        if reason and len(reason) < 3:
            raise ExecutiveValidationError("reason must be at least 3 characters")
        current = self._repository.get_action(action_id)
        if current is None:
            raise ActionNotFoundError(action_id)
        from_status = str(current.get("status"))
        try:
            action = self._repository.transition_action(
                action_id,
                target_status=target_status,
                expected_version=expected_version,
                actor_id=actor_id,
                actor_role=actor_role,
                reason=reason or f"Transitioned to {target_status}.",
                outcome_summary=outcome_summary or None,
                block_reason=block_reason or None,
                cancel_reason=cancel_reason or None,
                now=_as_utc(self._clock()) or datetime.now(UTC),
            )
        except Exception:
            record_governance_executive_action_transition(
                from_status=from_status, to_status=target_status, outcome="REJECTED"
            )
            raise
        record_governance_executive_action_transition(
            from_status=from_status, to_status=target_status, outcome="APPLIED"
        )
        self._audit(
            event_type=GovernanceAuditEventType.EXECUTIVE_ACTION_TRANSITIONED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="EXECUTIVE_ACTION",
            target_id=action_id,
            case_id=action.get("case_id"),
            reason=reason or f"Transitioned to {target_status}.",
            request_id=request_id,
            metadata={"from_status": from_status, "to_status": target_status},
        )
        self._refresh_action_metrics()
        return {
            "action": action,
            "events": self._repository.action_events(action_id),
            "from_status": from_status,
            "to_status": target_status,
            "recommendation_resolved": False,
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
        }

    def assign_action(
        self,
        action_id: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        owner_id = str(payload.get("owner_id") or "").strip()
        if not owner_id:
            raise ExecutiveValidationError("owner_id is required")
        expected_version = int(payload.get("expected_version") or 0)
        if expected_version < 1:
            raise ExecutiveValidationError("expected_version must be at least 1")
        reason = str(payload.get("reason") or "").strip()
        if len(reason) < 3:
            raise ExecutiveValidationError("reason must be at least 3 characters")
        action = self._repository.assign_action(
            action_id,
            owner_id=owner_id,
            expected_version=expected_version,
            actor_id=actor_id,
            actor_role=actor_role,
            reason=reason,
            now=_as_utc(self._clock()) or datetime.now(UTC),
        )
        self._audit(
            event_type=GovernanceAuditEventType.EXECUTIVE_ACTION_ASSIGNED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="EXECUTIVE_ACTION",
            target_id=action_id,
            case_id=action.get("case_id"),
            reason=reason,
            request_id=request_id,
            metadata={"owner_id": owner_id},
        )
        self._refresh_action_metrics()
        return {
            "action": action,
            "events": self._repository.action_events(action_id),
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
        }

    # ------------------------------------------------------------------
    # Executive reports
    # ------------------------------------------------------------------
    def generate_report(
        self,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        report_type = str(payload.get("report_type") or "").upper()
        if report_type not in REPORT_TYPE_VALUES:
            raise ExecutiveValidationError(f"unsupported report type: {report_type}")
        report_format = str(payload.get("format") or "json").lower()
        if report_format not in REPORT_FORMAT_VALUES:
            raise ExecutiveValidationError(f"unsupported report format: {report_format}")
        idempotency_key = str(payload.get("idempotency_key") or "").strip()
        if not idempotency_key:
            raise ExecutiveValidationError("idempotency_key is required")
        reason = str(payload.get("reason") or "").strip()
        if len(reason) < MIN_REPORT_REASON_LENGTH:
            raise ExecutiveValidationError(f"reason must be at least {MIN_REPORT_REASON_LENGTH} characters")
        if self._automation is None:
            raise ReportUnavailableError("governance snapshot storage is not initialized")
        existing = self._repository.find_report_by_idempotency_key(idempotency_key)
        if existing is not None:
            content = self.get_report_content(str(existing["report_id"]))
            return {
                "report": content["report"],
                "payload": content["payload"],
                "content": content["content"],
                "media_type": content["media_type"],
                "replayed": True,
                "non_claims": list(EXECUTIVE_NON_CLAIMS),
            }

        now = _as_utc(self._clock()) or datetime.now(UTC)
        window_days = _bounded_window_days(
            payload.get("window_days"),
            default=int(
                getattr(
                    self._settings,
                    "governance_executive_default_window_days",
                    DEFAULT_WINDOW_DAYS,
                )
            ),
        )
        started = time.perf_counter()
        try:
            report_payload = self._build_report_payload(report_type, now=now, window_days=window_days)
            redacted = redact_structure(report_payload)
            bounded = dict(redacted) if isinstance(redacted, Mapping) else {}
            encoded = canonical_json_bytes(bounded)
            max_bytes = min(
                MAX_REPORT_PAYLOAD_BYTES,
                int(
                    getattr(
                        self._settings,
                        "governance_executive_report_max_bytes",
                        MAX_REPORT_PAYLOAD_BYTES,
                    )
                ),
            )
            if len(encoded) > max_bytes:
                raise ReportUnavailableError(
                    f"report payload exceeds the bounded size limit ({len(encoded)} bytes)"
                )
            snapshot, _ = self._automation.create_snapshot(
                snapshot_type=REPORT_SNAPSHOT_TYPE_BY_REPORT[report_type],
                as_of=now,
                generated_by=str(actor_id or "SYSTEM"),
                dedup_key=report_dedup_key(report_type, idempotency_key),
                payload=bounded,
                row_count=len((bounded.get("sections") or {}).get("kpis", {}).get("items", [])),
                trigger="MANUAL",
                schema_version=REPORT_SCHEMA_VERSION,
                now=now,
            )
            sections = bounded.get("sections") or {}
            sections_available = [
                name
                for name in REPORT_SECTION_ORDER
                if str((sections.get(name) or {}).get("availability")) != "UNAVAILABLE"
            ]
            sections_unavailable = [
                name
                for name in REPORT_SECTION_ORDER
                if str((sections.get(name) or {}).get("availability")) == "UNAVAILABLE"
            ]
            report, created = self._repository.create_report(
                report_type=report_type,
                report_format=report_format,
                window_start=_as_utc(bounded.get("period", {}).get("start_at")),
                window_end=_as_utc(bounded.get("period", {}).get("end_at")),
                generated_by=str(actor_id or "SYSTEM"),
                snapshot_id=str(snapshot["snapshot_id"]),
                snapshot_type=REPORT_SNAPSHOT_TYPE_BY_REPORT[report_type],
                schema_version=REPORT_SCHEMA_VERSION,
                source_coverage=bounded.get("source_coverage") or {},
                sections_available=sections_available,
                sections_unavailable=sections_unavailable,
                payload_digest=str(snapshot["payload_digest"]),
                row_count=len((bounded.get("sections") or {}).get("kpis", {}).get("items", [])),
                idempotency_key=idempotency_key,
                reason=reason,
                now=now,
            )
        except Exception:
            record_governance_executive_report(
                report_type=report_type,
                report_format=report_format,
                outcome="FAILED",
                duration_seconds=time.perf_counter() - started,
            )
            raise
        if not created:
            # A concurrent request with the same idempotency key won the unique
            # insert. Return the stored winner verbatim; do not audit, do not
            # substitute the locally built payload, and do not emit a second
            # GENERATED metric.
            content = self.get_report_content(str(report["report_id"]))
            return {
                "report": content["report"],
                "payload": content["payload"],
                "content": content["content"],
                "media_type": content["media_type"],
                "replayed": True,
                "non_claims": list(EXECUTIVE_NON_CLAIMS),
            }
        replayed = False
        record_governance_executive_report(
            report_type=report_type,
            report_format=report_format,
            outcome="REPLAYED" if replayed else "GENERATED",
            duration_seconds=time.perf_counter() - started,
        )
        self._audit(
            event_type=GovernanceAuditEventType.EXECUTIVE_REPORT_GENERATED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="EXECUTIVE_REPORT",
            target_id=str(report["report_id"]),
            reason=reason,
            request_id=request_id,
            metadata={
                "report_type": report_type,
                "format": report_format,
                "snapshot_id": report["snapshot_id"],
            },
        )
        content = self._render_report_content(report, bounded)
        return {
            "report": report,
            "payload": bounded,
            "content": content["content"],
            "media_type": content["media_type"],
            "replayed": replayed,
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
        }

    def list_reports(
        self,
        *,
        report_type: str | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        normalized_type = str(report_type).upper() if report_type else None
        if normalized_type and normalized_type not in REPORT_TYPE_VALUES:
            raise ExecutiveValidationError(f"unsupported report type: {report_type}")
        items, total = self._repository.list_reports(
            report_type=normalized_type,
            page=max(1, int(page)),
            page_size=self._page_size(page_size),
        )
        return {
            "items": items,
            "total": total,
            "page": max(1, int(page)),
            "page_size": self._page_size(page_size),
            "report_types": list(REPORT_TYPE_VALUES),
            "formats": list(REPORT_FORMAT_VALUES),
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
        }

    def get_report(
        self,
        report_id: str,
        *,
        actor_id: str | None = None,
        actor_role: str = "SYSTEM",
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        report, payload = self._load_report_snapshot(report_id)
        self._audit(
            event_type=GovernanceAuditEventType.EXECUTIVE_REPORT_VIEWED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="EXECUTIVE_REPORT",
            target_id=report_id,
            reason="Executive report read.",
            request_id=request_id,
        )
        return {
            "report": report,
            "payload": payload,
            "integrity": {
                "report_digest_valid": True,
                "snapshot_digest_valid": True,
                "redaction_applied": bool(report.get("redaction_applied")),
                "schema_version": report.get("schema_version"),
            },
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
        }

    def get_report_content(self, report_id: str) -> dict[str, Any]:
        self._require_enabled()
        report, payload = self._load_report_snapshot(report_id)
        rendered = self._render_report_content(report, payload)
        return {
            "report": report,
            "payload": payload,
            "content": rendered["content"],
            "media_type": rendered["media_type"],
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
        }

    def audit_report_view(
        self,
        report_id: str,
        *,
        actor_id: str | None = None,
        actor_role: str = "SYSTEM",
        request_id: str | None = None,
    ) -> None:
        """Record a report-content read without re-rendering the report."""
        self._audit(
            event_type=GovernanceAuditEventType.EXECUTIVE_REPORT_VIEWED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="EXECUTIVE_REPORT",
            target_id=report_id,
            reason="Executive report content read.",
            request_id=request_id,
        )

    # ------------------------------------------------------------------
    # Compatible historical comparison
    # ------------------------------------------------------------------
    def compare_reports(
        self,
        report_id: str,
        *,
        other_report_id: str | None = None,
        window_days: int | None = None,
        actor_id: str | None = None,
        actor_role: str = "SYSTEM",
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        baseline_report, baseline_payload = self._load_report_snapshot(report_id)
        if other_report_id:
            current_report, current_payload = self._load_report_snapshot(other_report_id)
            current_label = "REPORT"
        else:
            current_report = None
            days = _bounded_window_days(
                window_days,
                default=int(
                    baseline_payload.get("window_days")
                    or getattr(
                        self._settings,
                        "governance_executive_default_window_days",
                        DEFAULT_WINDOW_DAYS,
                    )
                ),
            )
            now = _as_utc(self._clock()) or datetime.now(UTC)
            current_payload = self._build_report_payload(
                str(baseline_report.get("report_type") or "EXECUTIVE_SUMMARY"),
                now=now,
                window_days=days,
            )
            current_label = "CURRENT"
        result = self._compare_payloads(
            baseline_report=baseline_report,
            baseline_payload=baseline_payload,
            current_report=current_report,
            current_payload=current_payload,
            current_label=current_label,
        )
        record_governance_executive_comparison(str(result["status"]))
        self._audit(
            event_type=GovernanceAuditEventType.EXECUTIVE_COMPARISON_VIEWED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="EXECUTIVE_REPORT",
            target_id=report_id,
            reason="Executive historical comparison read.",
            request_id=request_id,
            metadata={
                "other_report_id": other_report_id,
                "status": result["status"],
            },
        )
        return result

    def _compare_payloads(
        self,
        *,
        baseline_report: Mapping[str, Any],
        baseline_payload: Mapping[str, Any],
        current_report: Mapping[str, Any] | None,
        current_payload: Mapping[str, Any],
        current_label: str,
    ) -> dict[str, Any]:
        incompatibilities: list[dict[str, Any]] = []
        baseline_type = str(baseline_payload.get("report_type") or "")
        current_type = str(current_payload.get("report_type") or "")
        if baseline_type != current_type:
            incompatibilities.append(
                {
                    "code": "REPORT_TYPE_MISMATCH",
                    "message": f"{baseline_type} cannot be compared with {current_type}.",
                }
            )
        baseline_schema = int(baseline_payload.get("schema_version") or 0)
        current_schema = int(current_payload.get("schema_version") or 0)
        if baseline_schema != current_schema:
            incompatibilities.append(
                {
                    "code": "SCHEMA_VERSION_MISMATCH",
                    "message": f"schema {baseline_schema} is not compatible with {current_schema}.",
                }
            )
        baseline_health = str(baseline_payload.get("health_model_version") or "")
        current_health = str(current_payload.get("health_model_version") or "")
        if baseline_health != current_health:
            incompatibilities.append(
                {
                    "code": "HEALTH_MODEL_VERSION_MISMATCH",
                    "message": f"{baseline_health} is not comparable with {current_health}.",
                }
            )
        baseline_days = int(baseline_payload.get("window_days") or 0)
        current_days = int(current_payload.get("window_days") or 0)
        if baseline_days != current_days:
            incompatibilities.append(
                {
                    "code": "PERIOD_LENGTH_MISMATCH",
                    "message": (
                        f"baseline period is {baseline_days} days but the compared period is "
                        f"{current_days} days."
                    ),
                }
            )
        baseline_risk = str(baseline_payload.get("risk_model_version") or "")
        current_risk = str(current_payload.get("risk_model_version") or "")
        if baseline_risk != current_risk:
            incompatibilities.append(
                {
                    "code": "RISK_MODEL_VERSION_MISMATCH",
                    "message": (
                        f"risk model {baseline_risk or 'unknown'} is not comparable with "
                        f"{current_risk or 'unknown'}; no past risk score was recomputed."
                    ),
                }
            )

        baseline_kpis = {
            str(item.get("kpi_id")): item
            for item in ((baseline_payload.get("sections") or {}).get("kpis") or {}).get("items", [])
        }
        current_kpis = {
            str(item.get("kpi_id")): item
            for item in ((current_payload.get("sections") or {}).get("kpis") or {}).get("items", [])
        }
        changes: list[dict[str, Any]] = []
        gaps: list[dict[str, Any]] = []
        for kpi_id in KPI_ORDER:
            baseline = baseline_kpis.get(kpi_id)
            current = current_kpis.get(kpi_id)
            if baseline is None or current is None:
                gaps.append(
                    {
                        "kpi_id": kpi_id,
                        "code": "KPI_MISSING",
                        "message": "The KPI is not present in one of the compared periods.",
                    }
                )
                continue
            baseline_availability = str(baseline.get("availability"))
            current_availability = str(current.get("availability"))
            if baseline_availability == KPI_UNAVAILABLE or current_availability == KPI_UNAVAILABLE:
                gaps.append(
                    {
                        "kpi_id": kpi_id,
                        "code": "SOURCE_UNAVAILABLE",
                        "baseline_availability": baseline_availability,
                        "current_availability": current_availability,
                        "message": (
                            "At least one period reports this KPI as unavailable; no delta is "
                            "calculated and no value is interpolated."
                        ),
                    }
                )
                continue
            if str(baseline.get("unit")) != str(current.get("unit")):
                incompatibilities.append(
                    {
                        "code": "KPI_UNIT_MISMATCH",
                        "kpi_id": kpi_id,
                        "message": (
                            f"unit {baseline.get('unit')} is not comparable with {current.get('unit')}."
                        ),
                    }
                )
                continue
            if str(baseline.get("definition")) != str(current.get("definition")):
                incompatibilities.append(
                    {
                        "code": "KPI_DEFINITION_MISMATCH",
                        "kpi_id": kpi_id,
                        "message": "The KPI definition changed between the compared periods.",
                    }
                )
                continue
            baseline_model = baseline.get("model_version")
            current_model = current.get("model_version")
            if baseline_model != current_model:
                incompatibilities.append(
                    {
                        "code": "KPI_MODEL_VERSION_MISMATCH",
                        "kpi_id": kpi_id,
                        "baseline_model_version": baseline_model,
                        "current_model_version": current_model,
                        "message": (
                            "The applicable model version changed; no historical value was "
                            "recomputed or fabricated."
                        ),
                    }
                )
                continue
            baseline_value = baseline.get("value")
            current_value = current.get("value")
            if (
                baseline_value is None
                or current_value is None
                or isinstance(baseline_value, bool)
                or isinstance(current_value, bool)
            ):
                gaps.append(
                    {
                        "kpi_id": kpi_id,
                        "code": "NON_NUMERIC_VALUE",
                        "message": "A non-numeric value cannot be compared as a delta.",
                    }
                )
                continue
            try:
                before = float(baseline_value)
                after = float(current_value)
            except (TypeError, ValueError):
                gaps.append(
                    {
                        "kpi_id": kpi_id,
                        "code": "NON_NUMERIC_VALUE",
                        "message": "A non-numeric value cannot be compared as a delta.",
                    }
                )
                continue
            delta = round(after - before, 6)
            percent = round((delta / before) * 100.0, 4) if before != 0 else None
            partial = baseline_availability == KPI_PARTIAL or current_availability == KPI_PARTIAL
            if partial:
                gaps.append(
                    {
                        "kpi_id": kpi_id,
                        "code": "PARTIAL_COVERAGE",
                        "message": (
                            "At least one period reports partial source coverage; the delta "
                            "covers known items only."
                        ),
                    }
                )
            changes.append(
                {
                    "kpi_id": kpi_id,
                    "name": baseline.get("name"),
                    "unit": baseline.get("unit"),
                    "baseline_value": before,
                    "current_value": after,
                    "delta": delta,
                    "percent_change": percent,
                    "baseline_availability": baseline_availability,
                    "current_availability": current_availability,
                    "baseline_model_version": baseline_model,
                    "current_model_version": current_model,
                    "partial": partial,
                }
            )
            if len(changes) >= MAX_COMPARISON_DIFF_ITEMS:
                break

        if incompatibilities:
            status = COMPARISON_INCOMPATIBLE
            message = (
                "The compared periods are not fully compatible. Incompatible model versions, "
                "definitions, or periods are explained explicitly."
            )
        elif not changes:
            status = COMPARISON_UNAVAILABLE
            message = (
                "No KPI could be compared because every source is unavailable or non-numeric; "
                "no value was interpolated."
            )
        else:
            status = COMPARISON_COMPARABLE
            message = (
                "Compatible periods compared using stored snapshot values only. Gaps and "
                "partial coverage are listed explicitly."
            )
        return {
            "status": status,
            "compatibility_version": COMPARISON_COMPATIBILITY_VERSION,
            "message": message,
            "comparable": status == COMPARISON_COMPARABLE,
            "baseline": {
                "report_id": baseline_report.get("report_id"),
                "report_type": baseline_type,
                "generated_at": baseline_report.get("generated_at"),
                "window_start": baseline_report.get("window_start"),
                "window_end": baseline_report.get("window_end"),
                "window_days": baseline_days,
                "snapshot_id": baseline_report.get("snapshot_id"),
                "snapshot_digest": baseline_report.get("payload_digest"),
            },
            "current": {
                "report_id": (current_report or {}).get("report_id"),
                "label": current_label,
                "report_type": current_type,
                "generated_at": (current_report or {}).get("generated_at"),
                "window_start": (current_report or {}).get("window_start"),
                "window_end": (current_report or {}).get("window_end"),
                "window_days": current_days,
                "snapshot_id": (current_report or {}).get("snapshot_id"),
            },
            "model_versions": {
                "baseline_health_model": baseline_health,
                "current_health_model": current_health,
                "baseline_risk_model": baseline_risk,
                "current_risk_model": current_risk,
            },
            "changes": changes,
            "gaps": gaps,
            "incompatibilities": incompatibilities,
            "truncated": len(changes) >= MAX_COMPARISON_DIFF_ITEMS,
            "interpolated": False,
            "fabricated_history": False,
            "source_preserved": True,
            "assurance": EXECUTIVE_ASSURANCE,
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
        }

    # ------------------------------------------------------------------
    # Configuration write
    # ------------------------------------------------------------------
    def update_config(
        self,
        config: Mapping[str, Any],
        *,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        if self._automation is None:
            raise ExecutiveConfigError("governance snapshot storage is not initialized")
        reason_text = str(reason or "").strip()
        if len(reason_text) < MIN_REPORT_REASON_LENGTH:
            raise ExecutiveValidationError(f"reason must be at least {MIN_REPORT_REASON_LENGTH} characters")
        normalized = self._validate_config(config)
        digest = sha256_hex(canonical_json_bytes(normalized))
        now = _as_utc(self._clock()) or datetime.now(UTC)
        snapshot, created = self._automation.create_snapshot(
            snapshot_type=EXECUTIVE_CONFIG_SNAPSHOT_TYPE,
            as_of=now,
            generated_by=str(actor_id or "SYSTEM"),
            dedup_key=f"executive:config:{digest}"[:200],
            payload={
                "config": normalized,
                "schema_version": EXECUTIVE_CONFIG_SCHEMA_VERSION,
                "updated_by": str(actor_id or "SYSTEM"),
                "reason": reason_text,
            },
            row_count=len(normalized),
            trigger="MANUAL",
            schema_version=EXECUTIVE_CONFIG_SCHEMA_VERSION,
            now=now,
        )
        if created:
            self._audit(
                event_type=GovernanceAuditEventType.EXECUTIVE_CONFIG_UPDATED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="EXECUTIVE_CONFIG",
                target_id=str(snapshot["snapshot_id"]),
                reason=reason_text,
                request_id=request_id,
                metadata={"config_digest": digest},
            )
        return {
            "config": normalized,
            "schema_version": EXECUTIVE_CONFIG_SCHEMA_VERSION,
            "availability": "OK",
            "message": "",
            "snapshot_id": snapshot["snapshot_id"],
            "payload_digest": snapshot["payload_digest"],
            "replayed": not created,
            "fixed_health_model_version": HEALTH_MODEL_VERSION,
            "health_thresholds_fixed": True,
            "assurance": EXECUTIVE_ASSURANCE,
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
            "limitations": list(EXECUTIVE_LIMITATIONS),
        }

    # ------------------------------------------------------------------
    # Report internals
    # ------------------------------------------------------------------
    def _build_report_payload(
        self,
        report_type: str,
        *,
        now: datetime,
        window_days: int,
    ) -> dict[str, Any]:
        kpi_payload = self.kpis(window_days=window_days, now=now)
        health = evaluate_health(
            kpi_payload["items"],
            calculated_at=now,
            model_version=HEALTH_MODEL_VERSION,
        )
        by_id = {str(item["kpi_id"]): item for item in kpi_payload["items"]}
        risk_section = self._report_risk_section(now)
        sla_section = self._report_sla_section(by_id, now)
        operations_section = self._report_operations_section(by_id, now)
        actions_section = self._report_actions_section(now)
        sections: dict[str, Any] = {
            "executive_health": {
                "availability": "AVAILABLE",
                "status": health["overall_status"],
                "status_reason": health["status_reason"],
                "model_version": health["model_version"],
                "coverage": health["coverage"],
                "triggered_signals": health["triggered_signals"],
            },
            "kpis": {
                "availability": (
                    "UNAVAILABLE"
                    if kpi_payload["source_coverage"]["status"] == COVERAGE_UNAVAILABLE
                    else "AVAILABLE"
                ),
                "items": kpi_payload["items"],
                "total": kpi_payload["total"],
                "window": kpi_payload["window"],
                "source_coverage": kpi_payload["source_coverage"],
            },
            "risk": risk_section,
            "sla": sla_section,
            "operations": operations_section,
            "actions": actions_section,
            "source_coverage": {
                "availability": (
                    "UNAVAILABLE"
                    if kpi_payload["source_coverage"]["status"] == COVERAGE_UNAVAILABLE
                    else "AVAILABLE"
                ),
                **kpi_payload["source_coverage"],
            },
            "assurance": {
                "availability": "AVAILABLE",
                "assurance": EXECUTIVE_ASSURANCE,
                "non_claims": list(EXECUTIVE_NON_CLAIMS),
                "limitations": list(EXECUTIVE_LIMITATIONS),
                "external_distribution": False,
                "pdf_supported": False,
                "email_supported": False,
            },
        }
        start = now - timedelta(days=window_days)
        risk_model_version = None
        if self._intelligence_repository is not None:
            try:
                risk_model = self._intelligence_repository.latest_risk_model() or {}
                risk_model_version = risk_model.get("version")
            except Exception:  # noqa: BLE001 - report section remains explicit
                risk_model_version = None
        return {
            "report_type": report_type,
            "schema_version": REPORT_SCHEMA_VERSION,
            "generated_at": _iso(now),
            "window_days": window_days,
            "period": {
                "start_at": _iso(start),
                "end_at": _iso(now),
                "boundary": "UTC",
            },
            "health_model_version": HEALTH_MODEL_VERSION,
            "risk_model_version": risk_model_version,
            "sections": sections,
            "source_coverage": kpi_payload["source_coverage"],
            "redaction_applied": True,
            "assurance": EXECUTIVE_ASSURANCE,
            "non_claims": list(EXECUTIVE_NON_CLAIMS),
            "limitations": list(EXECUTIVE_LIMITATIONS),
        }

    def _report_risk_section(self, now: datetime) -> dict[str, Any]:
        if self._intelligence is None or self._intelligence_repository is None:
            return {
                "availability": "UNAVAILABLE",
                "message": "Governance intelligence is not initialized.",
            }
        try:
            cases = self._intelligence.risk_cases(page=1, page_size=1)
            recommendations = self._intelligence_repository.recommendation_counts()
            risk_model = self._intelligence_repository.latest_risk_model() or {}
        except Exception as exc:  # noqa: BLE001 - explicit unavailable section
            return {
                "availability": "UNAVAILABLE",
                "message": f"Risk sources could not be read ({type(exc).__name__}).",
            }
        return {
            "availability": "PARTIAL" if cases.get("partial") else "AVAILABLE",
            "message": (
                "Some risk sources are unavailable; counts cover known cases only."
                if cases.get("partial")
                else ""
            ),
            "calculated_at": _iso(now),
            "model_id": risk_model.get("model_id"),
            "model_version": risk_model.get("version"),
            "risk_level_counts": cases.get("risk_level_counts") or {},
            "truncated": bool(cases.get("truncated")),
            "unavailable_case_count": int(cases.get("unavailable_case_count") or 0),
            "partial": bool(cases.get("partial")),
            "recommendation_counts": recommendations,
            "past_risk_scores_recomputed": False,
        }

    def _report_sla_section(self, by_id: Mapping[str, Mapping[str, Any]], now: datetime) -> dict[str, Any]:
        breached = by_id.get("SLA_BREACHED_ITEMS") or {}
        ratio = by_id.get("SLA_COMPLIANCE_RATIO") or {}
        availability = str(breached.get("availability") or "UNAVAILABLE")
        if availability == KPI_UNAVAILABLE:
            return {
                "availability": "UNAVAILABLE",
                "message": str(
                    breached.get("unavailable_reason") or "The operational SLA backlog is unavailable."
                ),
                "calculated_at": _iso(now),
            }
        detail = breached.get("detail") or {}
        ratio_detail = ratio.get("detail") or {}
        return {
            "availability": availability,
            "message": str((breached.get("completeness") or {}).get("message") or ""),
            "calculated_at": _iso(now),
            "state_counts": detail.get("state_counts") or {},
            "per_target": detail.get("per_target") or {},
            "unavailable_sources": detail.get("unavailable_sources") or [],
            "truncated": bool(detail.get("truncated")),
            "breached_items": breached.get("value"),
            "compliance_ratio": ratio.get("value"),
            "numerator": ratio.get("numerator"),
            "denominator": ratio.get("denominator"),
            "excluded_unknown": ratio_detail.get("excluded_unknown"),
            "ratio_definition": ratio.get("definition"),
        }

    def _report_operations_section(
        self, by_id: Mapping[str, Mapping[str, Any]], now: datetime
    ) -> dict[str, Any]:
        failed = by_id.get("AUTOMATION_FAILED_JOBS") or {}
        stale = by_id.get("AUTOMATION_STALE_JOBS") or {}
        availability = (
            "UNAVAILABLE"
            if str(failed.get("availability")) == KPI_UNAVAILABLE
            and str(stale.get("availability")) == KPI_UNAVAILABLE
            else "AVAILABLE"
        )
        if availability == "UNAVAILABLE":
            return {
                "availability": "UNAVAILABLE",
                "message": "Governance automation storage is unavailable.",
                "calculated_at": _iso(now),
            }
        readiness: dict[str, Any] = {}
        readiness_available = self._governance is not None
        if readiness_available:
            try:
                readiness = self._governance.readiness_metrics()
            except Exception:  # noqa: BLE001 - one section source is explicitly unavailable
                readiness_available = False
        return {
            "availability": "AVAILABLE" if readiness_available else "PARTIAL",
            "message": (
                ""
                if readiness_available
                else "Governance workflow counts are unavailable; automation counts remain known."
            ),
            "calculated_at": _iso(now),
            "automation": {
                "failed_jobs": failed.get("value"),
                "failed_jobs_availability": failed.get("availability"),
                "stale_jobs": stale.get("value"),
                "stale_jobs_availability": stale.get("availability"),
                "queue": (failed.get("detail") or {}).get("queue")
                or (stale.get("detail") or {}).get("queue"),
                "job_count": (failed.get("detail") or {}).get("job_count")
                or (stale.get("detail") or {}).get("job_count"),
                "scheduler_started_by_v38": False,
            },
            "governance": {
                "evaluation_count": readiness.get("evaluation_count"),
                "blocking_hold_count": readiness.get("blocking_hold_count"),
                "open_disposition_count": readiness.get("open_disposition_count"),
                "pending_export_approvals": readiness.get("pending_export_approvals"),
                "evaluations_truncated": readiness.get("evaluations_truncated"),
            },
        }

    def _report_actions_section(self, now: datetime) -> dict[str, Any]:
        try:
            counts = self._repository.action_status_counts()
            due_soon_hours = int(self.config().get("config", {}).get("action_due_soon_hours", 72))
            due = self._repository.action_due_counts(now=now, due_soon_hours=due_soon_hours)
        except Exception as exc:  # noqa: BLE001 - explicit unavailable section
            return {
                "availability": "UNAVAILABLE",
                "message": f"Strategic action storage could not be read ({type(exc).__name__}).",
            }
        return {
            "availability": "AVAILABLE",
            "message": "",
            "calculated_at": _iso(now),
            "status_counts": counts,
            "total": due["total"],
            "overdue": due["overdue"],
            "due_soon": due["due_soon"],
            "due_soon_hours": due_soon_hours,
            "automatic_recommendation_resolution": False,
            "sensitive_governance_execution": False,
        }

    def _load_report_snapshot(self, report_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        report = self._repository.get_report(report_id)
        if report is None:
            raise ReportNotFoundError(report_id)
        expected_digest = report_digest_for(report)
        if expected_digest != report.get("report_digest"):
            raise ReportIntegrityError(f"executive report {report_id} failed self-digest validation")
        if self._automation is None:
            raise ReportUnavailableError("governance snapshot storage is not initialized")
        snapshot = self._automation.get_snapshot(str(report.get("snapshot_id")))
        if snapshot is None:
            raise ReportUnavailableError(f"executive report {report_id} source snapshot is unavailable")
        if not snapshot.get("digest_valid"):
            raise ReportIntegrityError(
                f"executive report {report_id} source snapshot failed self-digest validation"
            )
        payload = snapshot.get("payload") or {}
        if not isinstance(payload, Mapping):
            raise ReportIntegrityError(
                f"executive report {report_id} source snapshot payload is not an object"
            )
        if str(payload.get("report_type") or "") != str(report.get("report_type") or ""):
            raise ReportIntegrityError(
                f"executive report {report_id} source snapshot type does not match metadata"
            )
        return report, dict(payload)

    def _render_report_content(self, report: Mapping[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
        if str(report.get("format") or "json").lower() == "csv":
            return {
                "content": self._payload_csv(payload),
                "media_type": "text/csv",
            }
        return {
            "content": canonical_json_bytes(payload).decode("utf-8"),
            "media_type": "application/json",
        }

    def _payload_csv(self, payload: Mapping[str, Any]) -> str:
        rows: list[tuple[str, str]] = []

        def _walk(prefix: str, value: Any) -> None:
            if len(rows) >= MAX_REPORT_ROWS:
                return
            if isinstance(value, Mapping):
                for key in sorted(value, key=lambda item: str(item)):
                    _walk(f"{prefix}.{key}" if prefix else str(key), value[key])
                return
            if isinstance(value, (list, tuple)):
                for index, item in enumerate(value):
                    _walk(f"{prefix}[{index}]", item)
                return
            if value is None:
                rendered = ""
            elif isinstance(value, bool):
                rendered = "true" if value else "false"
            else:
                rendered = str(value)
            rows.append((prefix, rendered))

        _walk("", payload)
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(["path", "value"])
        for path, value in rows[:MAX_REPORT_ROWS]:
            writer.writerow([path, value])
        content = buffer.getvalue()
        if len(content.encode("utf-8")) > MAX_REPORT_CSV_BYTES:
            content = content.encode("utf-8")[:MAX_REPORT_CSV_BYTES].decode("utf-8", errors="ignore")
        return content

    # ------------------------------------------------------------------
    # Shared internals
    # ------------------------------------------------------------------
    def _linked_recommendation(self, action: Mapping[str, Any]) -> dict[str, Any] | None:
        if self._intelligence_repository is None:
            return None
        try:
            recommendation = self._intelligence_repository.get_recommendation(
                str(action.get("recommendation_id"))
            )
        except Exception:  # noqa: BLE001 - a linked read must not break the action
            return None
        if recommendation is None:
            return None
        return {
            "recommendation_id": recommendation.get("recommendation_id"),
            "rule_id": recommendation.get("rule_id"),
            "severity": recommendation.get("severity"),
            "status": recommendation.get("status"),
            "version": recommendation.get("version"),
            "case_id": recommendation.get("case_id"),
        }

    def _refresh_action_metrics(self) -> None:
        try:
            set_governance_executive_action_counts(self._repository.action_status_counts())
        except Exception:  # noqa: BLE001 - metrics must never break a request
            logger.warning("executive action metrics refresh failed", exc_info=True)

    def _audit(
        self,
        *,
        event_type: str,
        actor_id: str | None,
        actor_role: str,
        target_type: str,
        target_id: str,
        case_id: str | None = None,
        reason: str = "",
        request_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        if self._governance is None:
            return
        try:
            self._governance.record_access(
                event_type=event_type,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type=target_type,
                target_id=target_id,
                case_id=case_id,
                reason=reason,
                request_id=request_id,
                metadata=metadata,
            )
        except Exception:  # noqa: BLE001 - audit failure must not fabricate success
            logger.warning("executive governance audit write failed", exc_info=True)

    # ------------------------------------------------------------------
    # Bounded page helpers
    # ------------------------------------------------------------------
    def _page_size(self, page_size: int | None) -> int:
        size = int(page_size or getattr(self._settings, "governance_executive_page_size", DEFAULT_PAGE_SIZE))
        return min(MAX_PAGE_SIZE, max(1, size))


__all__ = ["GovernanceExecutiveService"]
