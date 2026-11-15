"""V38 executive governance application service.

Coordinates read-only executive KPIs, the deterministic ``EXEC_HEALTH_V1``
health model, and executive operational configuration on top of the existing
V10-V37 records. Commit 1 of V38 intentionally implements reads only; strategic
actions and report generation are added in the next layer without changing the
KPI or health contracts.

The service never approves or releases a legal hold, decides a disposition,
modifies evidence, deletes a record, or executes a sensitive governance action.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from backend.app.core.logging import get_logger
from backend.app.core.metrics import (
    set_governance_executive_action_counts,
    set_governance_executive_health,
    set_governance_executive_kpi_availability,
)
from backend.app.domain.common import utcnow
from backend.app.governance.executive.constants import (
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
    MAX_PAGE_SIZE,
    MAX_WINDOW_DAYS,
    MIN_WINDOW_DAYS,
)
from backend.app.governance.executive.errors import (
    ExecutiveDisabledError,
    ExecutiveValidationError,
)
from backend.app.governance.executive.health import evaluate_health

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
    """Read-only executive aggregation service (commit 1 foundation)."""

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
    # Bounded page helpers
    # ------------------------------------------------------------------
    def _page_size(self, page_size: int | None) -> int:
        size = int(page_size or getattr(self._settings, "governance_executive_page_size", DEFAULT_PAGE_SIZE))
        return min(MAX_PAGE_SIZE, max(1, size))


__all__ = ["GovernanceExecutiveService"]
