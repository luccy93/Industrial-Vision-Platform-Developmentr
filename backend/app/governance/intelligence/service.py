"""V37 governance intelligence application service.

Coordinates deterministic risk scoring, versioned operational SLAs, bounded
analytics, advisory recommendations, and local snapshot comparison on top of
the existing V35 governance, V36 automation, V34 forensic, V10 incident, and
V15 notification services. It never approves or releases a legal hold, decides
a disposition, modifies evidence, deletes a record, or makes an automatic
governance decision.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from backend.app.analytics.contracts import TimeRange, bucket_start, validate_bucket
from backend.app.core.logging import get_logger
from backend.app.core.metrics import (
    record_governance_intelligence_refresh,
    record_governance_intelligence_score,
    record_governance_intelligence_snapshot_comparison,
    set_governance_intelligence_recommendation_counts,
    set_governance_intelligence_sla_counts,
)
from backend.app.domain.common import utcnow
from backend.app.governance.constants import (
    BLOCKING_HOLD_STATUSES,
    GovernanceAuditEventType,
    GovernanceState,
)
from backend.app.governance.intelligence.constants import (
    DEFAULT_PAGE_SIZE,
    DEFAULT_RISK_CASES,
    DEFAULT_TREND_BUCKET,
    DEFAULT_TREND_WINDOW_DAYS,
    FACTOR_LABELS,
    INTELLIGENCE_ALERT_EVENT_TYPE,
    INTELLIGENCE_ASSURANCE,
    INTELLIGENCE_LIMITATIONS,
    INTELLIGENCE_NON_CLAIMS,
    MAX_DISMISS_REASON_LENGTH,
    MAX_PAGE_SIZE,
    MAX_RECOMMENDATION_REASON_LENGTH,
    MAX_REFRESH_ITEMS,
    MAX_SNAPSHOT_DIFF_ITEMS,
    MAX_TREND_ROWS,
    MAX_TREND_WINDOW_DAYS,
    MIN_DISMISS_REASON_LENGTH,
    RECOMMENDATION_EVENT_VALUES,
    RECOMMENDATION_RULES,
    RECOMMENDATION_SCOPE_AUTOMATION,
    RECOMMENDATION_SCOPE_CASE,
    RECOMMENDATION_SCOPE_DISPOSITION,
    RECOMMENDATION_SCOPE_EXPORT_APPROVAL,
    RECOMMENDATION_SCOPE_LEGAL_HOLD,
    RECOMMENDATION_SCOPE_SNAPSHOT,
    RECOMMENDATION_SEVERITY_VALUES,
    RECOMMENDATION_STATUS_VALUES,
    RISK_LEVEL_ORDER,
    RULE_IDS,
    SLA_KIND_OPERATIONAL,
    SLA_NON_CLAIM,
    SLA_TARGET_KEYS,
    SNAPSHOT_TYPE_INTELLIGENCE_SUMMARY,
    SNAPSHOT_VOLATILE_KEYS,
    TREND_AUDIT_GROUPS,
    TREND_SOURCE_ORDER,
    RecommendationStatus,
    SlaState,
    audit_event_group,
    recommendation_key,
)
from backend.app.governance.intelligence.errors import (
    IntelligenceDisabledError,
    IntelligenceValidationError,
    RecommendationNotFoundError,
    RiskCaseNotFoundError,
    SlaTargetNotFoundError,
    SnapshotNotFoundError,
)
from backend.app.governance.intelligence.scoring import score_case
from backend.app.governance.intelligence.sla import calculate_sla
from backend.app.governance.policies import select_policy

logger = get_logger(__name__)

_TERMINAL_DISPOSITION_STATUSES = frozenset({"APPROVED", "BLOCKED", "WITHDRAWN"})
_TERMINAL_HOLD_STATUSES = frozenset({"REJECTED", "RELEASED", "WITHDRAWN"})


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


_TREND_STEP = {
    "hour": timedelta(hours=1),
    "day": timedelta(days=1),
    "week": timedelta(weeks=1),
}

_TREND_DEFINITIONS = {
    "governance_events": ("Append-only V35 governance access-audit events, grouped by bounded event family."),
    "retention_evaluations": (
        "Append-only V35 retention evaluation rows, grouped by the stored governance state."
    ),
    "recommendations": (
        "V37 recommendation lifecycle events (creation, acknowledgement, dismissal, resolution)."
    ),
    "sla_inflow": (
        "Governance records observed entering an operational SLA queue. Retention rows are "
        "counted at evaluation time, which is not necessarily the original review due time."
    ),
    "risk_scores": (
        "Historical risk-score persistence is not implemented. Scores are computed on demand; "
        "this source is explicitly unavailable rather than zero."
    ),
}

_RETENTION_TREND_CATEGORIES: tuple[str, ...] = tuple(
    sorted({state.value for state in GovernanceState} | {"OTHER"})
)
_RECOMMENDATION_TREND_CATEGORIES: tuple[str, ...] = tuple(sorted(RECOMMENDATION_EVENT_VALUES | {"OTHER"}))


def _bounded_category(value: Any, allowed: Sequence[str]) -> str:
    text = str(value or "").upper()
    return text if text in allowed else "OTHER"


def _bucket_series(
    moments: Sequence[Any],
    *,
    start: datetime,
    end: datetime,
    bucket: str,
    coverage_start: datetime | None,
    coverage_known: bool,
    counts_unavailable: bool = False,
) -> list[dict[str, Any]]:
    """Build a bounded bucket series with explicit coverage gaps.

    Buckets before the earliest stored record are ``null`` rather than zero. A
    bucket that straddles the first stored record is marked partial. When
    coverage could not be read, counts remain actual but ``in_coverage`` is
    unknown instead of being asserted. A source that is itself unavailable
    always reports ``null`` counts so a failed read is never rendered as zero.
    """
    step = _TREND_STEP[bucket]
    boundaries: list[datetime] = []
    cursor = bucket_start(start, bucket)
    while cursor < end and len(boundaries) < 800:
        boundaries.append(cursor)
        cursor = cursor + step
    counts = [0] * len(boundaries)
    for moment in moments:
        parsed = _as_utc(moment)
        if parsed is None or parsed < start or parsed >= end or not boundaries:
            continue
        position = int((bucket_start(parsed, bucket) - boundaries[0]).total_seconds() // step.total_seconds())
        if 0 <= position < len(counts):
            counts[position] += 1
    series: list[dict[str, Any]] = []
    for position, boundary in enumerate(boundaries):
        bucket_end = boundary + step
        partial_coverage = False
        if not coverage_known:
            in_coverage: bool | None = None
            coverage_state = "UNKNOWN"
            count: int | None = counts[position]
        elif coverage_start is None:
            in_coverage = False
            coverage_state = "NO_HISTORY"
            count = None
        elif bucket_end <= coverage_start:
            in_coverage = False
            coverage_state = "BEFORE_COVERAGE"
            count = None
        else:
            in_coverage = True
            coverage_state = "IN_COVERAGE"
            count = counts[position]
            partial_coverage = boundary < coverage_start
        if counts_unavailable:
            count = None
        series.append(
            {
                "bucket_start": _iso(boundary),
                "bucket_end": _iso(bucket_end),
                "count": count,
                "in_coverage": in_coverage,
                "coverage": coverage_state,
                "partial_coverage": partial_coverage,
            }
        )
    return series


def _coverage_min(values: Sequence[str | None]) -> datetime | None:
    parsed = [_as_utc(value) for value in values if value]
    present = [value for value in parsed if value is not None]
    return min(present) if present else None


def _diff_payload(
    before: Any,
    after: Any,
    *,
    path: str = "",
    changes: list[dict[str, Any]],
    limit: int = MAX_SNAPSHOT_DIFF_ITEMS,
) -> bool:
    """Append bounded leaf differences; returns ``True`` when truncated."""
    if len(changes) >= limit:
        return True
    if isinstance(before, Mapping) and isinstance(after, Mapping):
        keys = sorted({str(key) for key in before} | {str(key) for key in after})
        for key in keys:
            if not path and key in SNAPSHOT_VOLATILE_KEYS:
                continue
            child_path = f"{path}.{key}" if path else key
            if key not in before:
                changes.append({"path": child_path, "change": "ADDED", "before": None, "after": after[key]})
            elif key not in after:
                changes.append(
                    {"path": child_path, "change": "REMOVED", "before": before[key], "after": None}
                )
            elif _diff_payload(
                before[key],
                after[key],
                path=child_path,
                changes=changes,
                limit=limit,
            ):
                return True
            if len(changes) >= limit:
                return True
        return False
    if before != after:
        changes.append({"path": path or "$", "change": "CHANGED", "before": before, "after": after})
    return len(changes) >= limit


class GovernanceIntelligenceService:
    """Application-level API over governance risk and operational SLAs."""

    def __init__(
        self,
        *,
        settings: Any,
        repository: Any,
        governance_service: Any,
        governance_repository: Any,
        forensic_repository: Any,
        forensic_service: Any | None = None,
        automation_repository: Any | None = None,
        incident_repository: Any | None = None,
        notifier: Any | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._governance = governance_service
        self._governance_repository = governance_repository
        self._forensics = forensic_repository
        self._forensic_service = forensic_service or forensic_repository
        self._automation = automation_repository
        self._incidents = incident_repository
        self._notifier = notifier
        self._clock = clock or utcnow
        self._defaults_ready = False

    # ------------------------------------------------------------------
    # Status and configuration
    # ------------------------------------------------------------------
    def _ensure_defaults(self) -> None:
        if self._defaults_ready:
            return
        try:
            self._repository.ensure_defaults(now=self._clock())
        except Exception:  # noqa: BLE001 - defaults are best-effort and idempotent
            logger.warning("governance intelligence default seeding failed", exc_info=True)
        self._defaults_ready = True

    def _require_enabled(self) -> None:
        if not bool(getattr(self._settings, "governance_intelligence_enabled", True)):
            raise IntelligenceDisabledError("governance intelligence is disabled")
        if not bool(getattr(self._settings, "governance_enabled", True)):
            raise IntelligenceDisabledError("governance is disabled")

    def status(self) -> dict[str, Any]:
        self._require_enabled()
        self._ensure_defaults()
        model = self._repository.latest_risk_model()
        targets = self._repository.latest_sla_targets()
        recommendations = self._repository.recommendation_counts()
        return {
            "enabled": True,
            "assurance": INTELLIGENCE_ASSURANCE,
            "model": {
                "model_id": (model or {}).get("model_id"),
                "version": (model or {}).get("version"),
                "name": (model or {}).get("name"),
                "state": (model or {}).get("state"),
            },
            "sla_targets": [
                {
                    "target_key": key,
                    "version": value.get("version"),
                    "target_hours": value.get("target_hours"),
                    "warning_hours": value.get("warning_hours"),
                    "effective_from": value.get("effective_from"),
                }
                for key, value in sorted(targets.items())
            ],
            "recommendation_counts": recommendations,
            "scheduled_intelligence": False,
            "scheduled_intelligence_note": (
                "V37 computes intelligence on demand; no intelligence scheduler is started."
            ),
            "alerts_enabled": bool(getattr(self._settings, "governance_intelligence_alerts_enabled", False)),
            "generated_at": _iso(self._clock()),
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
            "limitations": list(INTELLIGENCE_LIMITATIONS),
        }

    def risk_model(self) -> dict[str, Any]:
        self._require_enabled()
        self._ensure_defaults()
        model = self._repository.latest_risk_model()
        if model is None:
            raise IntelligenceValidationError("governance risk model is not initialized")
        return {
            "model": model,
            "factor_catalog": [
                {
                    "factor_id": factor,
                    "label": label,
                    "default_points": (model.get("factor_points") or {}).get(factor),
                }
                for factor, label in sorted(FACTOR_LABELS.items())
            ],
            "assurance": INTELLIGENCE_ASSURANCE,
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }

    def list_risk_model_versions(
        self, *, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE
    ) -> dict[str, Any]:
        self._require_enabled()
        self._ensure_defaults()
        items, total = self._repository.list_risk_models(page=page, page_size=page_size)
        return {
            "items": items,
            "total": total,
            "page": max(1, int(page)),
            "page_size": min(MAX_PAGE_SIZE, max(1, int(page_size))),
        }

    def update_risk_model(
        self,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        self._ensure_defaults()
        reason = str(payload.get("reason") or "").strip()
        if len(reason) < 3:
            raise IntelligenceValidationError("a reason of at least 3 characters is required")
        expected_version = payload.get("expected_version")
        if expected_version is not None:
            try:
                expected_version = int(expected_version)
            except (TypeError, ValueError):
                raise IntelligenceValidationError("expected_version must be an integer") from None
        model, created = self._repository.create_risk_model(
            name=str(payload.get("name") or ""),
            thresholds=payload.get("thresholds") or {},
            factor_points=payload.get("factor_points"),
            effective_from=_as_utc(payload.get("effective_from")),
            actor_id=actor_id,
            actor_role=actor_role,
            reason=reason,
            idempotency_key=payload.get("idempotency_key"),
            expected_version=expected_version,
            now=self._clock(),
        )
        if created:
            self._audit(
                event_type=GovernanceAuditEventType.INTELLIGENCE_RISK_MODEL_UPDATED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="RISK_MODEL",
                target_id=f"{model['model_id']}@{model['version']}",
                reason=reason,
                request_id=request_id,
                event_key=f"intelligence:risk-model:{model['model_id']}:v{model['version']}",
                metadata={
                    "model_id": model["model_id"],
                    "version": model["version"],
                    "effective_from": model["effective_from"],
                },
            )
        return {
            "model": model,
            "created": created,
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }

    # ------------------------------------------------------------------
    # SLA targets
    # ------------------------------------------------------------------
    def list_sla_targets(
        self,
        *,
        target_key: str | None = None,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> dict[str, Any]:
        self._require_enabled()
        self._ensure_defaults()
        if target_key and str(target_key).upper() not in SLA_TARGET_KEYS:
            raise SlaTargetNotFoundError(str(target_key).upper())
        items, total = self._repository.list_sla_targets(
            target_key=target_key, page=page, page_size=page_size
        )
        return {
            "items": items,
            "total": total,
            "page": max(1, int(page)),
            "page_size": min(MAX_PAGE_SIZE, max(1, int(page_size))),
            "sla_kind": SLA_KIND_OPERATIONAL,
            "non_claim": SLA_NON_CLAIM,
        }

    def update_sla_target(
        self,
        target_key: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        self._ensure_defaults()
        normalized_key = str(target_key or "").upper()
        if normalized_key not in SLA_TARGET_KEYS:
            raise SlaTargetNotFoundError(normalized_key)
        reason = str(payload.get("reason") or "").strip()
        if len(reason) < 3:
            raise IntelligenceValidationError("a reason of at least 3 characters is required")
        expected_version = payload.get("expected_version")
        if expected_version is not None:
            try:
                expected_version = int(expected_version)
            except (TypeError, ValueError):
                raise IntelligenceValidationError("expected_version must be an integer") from None
        target, created = self._repository.create_sla_target(
            target_key=normalized_key,
            target_hours=payload.get("target_hours"),
            warning_hours=payload.get("warning_hours"),
            effective_from=_as_utc(payload.get("effective_from")),
            actor_id=actor_id,
            actor_role=actor_role,
            reason=reason,
            idempotency_key=payload.get("idempotency_key"),
            expected_version=expected_version,
            now=self._clock(),
        )
        if created:
            self._audit(
                event_type=GovernanceAuditEventType.INTELLIGENCE_SLA_TARGET_UPDATED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="SLA_TARGET",
                target_id=f"{normalized_key}@v{target['version']}",
                reason=reason,
                request_id=request_id,
                event_key=f"intelligence:sla:{normalized_key}:v{target['version']}",
                metadata={
                    "target_key": normalized_key,
                    "version": target["version"],
                    "target_hours": target["target_hours"],
                    "warning_hours": target["warning_hours"],
                    "effective_from": target["effective_from"],
                },
            )
        return {
            "target": target,
            "created": created,
            "sla_kind": SLA_KIND_OPERATIONAL,
            "non_claim": SLA_NON_CLAIM,
        }

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------
    def _bounded_cases(self, limit: int) -> tuple[list[dict[str, Any]], bool]:
        max_cases = max(1, min(2000, int(limit)))
        collected: list[dict[str, Any]] = []
        total = 0
        page = 1
        while len(collected) < max_cases:
            size = min(100, max_cases - len(collected))
            items, total = self._forensics.list_cases(page=page, page_size=size)
            collected.extend(items)
            if len(collected) >= int(total) or not items:
                break
            page += 1
        return collected[:max_cases], int(total) > len(collected)

    def _sla_versions(self) -> dict[str, list[dict[str, Any]]]:
        return {key: self._repository.sla_target_versions(key) for key in SLA_TARGET_KEYS}

    def _previous_due_evaluation(
        self, case_id: str, *, current_evaluation_id: str | None = None
    ) -> Mapping[str, Any] | None:
        """Return the most recent earlier evaluation that was ``REVIEW_DUE``.

        The V35 evaluation history is append-only: a human review appends a new
        ``REVIEW`` row rather than mutating the due row. Scanning a bounded
        history lets V37 resolve a retention SLA without inventing a timestamp.
        """
        try:
            items, _ = self._governance_repository.list_evaluations(case_id, page=1, page_size=10)
        except Exception:  # noqa: BLE001 - resolution degrades to UNKNOWN
            return None
        for item in items:
            if current_evaluation_id and str(item.get("evaluation_id")) == current_evaluation_id:
                continue
            if str(item.get("governance_state") or "").upper() == "REVIEW_DUE":
                return item
        return None

    def _evidence_categories(self, case_id: str) -> list[str]:
        try:
            references = self._forensics.list_evidence_references(case_id)
        except Exception:  # noqa: BLE001 - policy selection degrades explicitly
            return []
        return sorted(
            {
                str(reference.get("artifact_type") or "").upper()
                for reference in references
                if reference.get("artifact_type")
            }
        )

    def _policy_for_case(self, case: Mapping[str, Any], categories: Sequence[str]) -> Any | None:
        return select_policy(
            self._governance_repository.latest_enabled_policies(),
            case_type=str(case.get("case_type") or ""),
            evidence_categories=categories,
        )

    def _sla_context(
        self,
        *,
        case_id: str,
        evaluation: Mapping[str, Any] | None,
        disposition: Mapping[str, Any] | None,
        holds: Sequence[Mapping[str, Any]],
        approvals: Sequence[Mapping[str, Any]],
        now: datetime,
        versions: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
        resolve_retention: bool = True,
    ) -> dict[str, dict[str, Any]]:
        context: dict[str, dict[str, Any]] = {}
        resolved_versions = dict(versions or self._sla_versions())

        review_state = str((evaluation or {}).get("governance_state") or "").upper()
        review_applicable = False
        review_start: datetime | None = None
        review_resolution: datetime | None = None
        if evaluation is not None:
            if review_state == "REVIEW_DUE":
                review_applicable = True
                review_start = _as_utc(evaluation.get("next_review_at"))
            elif str(evaluation.get("evaluation_kind") or "").upper() == "REVIEW":
                # A review appends a new row; resolve against the prior due row
                # instead of using the review row's own timestamp as the start.
                review_applicable = True
                prior = (
                    self._previous_due_evaluation(
                        case_id,
                        current_evaluation_id=str(evaluation.get("evaluation_id") or "") or None,
                    )
                    if resolve_retention
                    else None
                )
                review_start = _as_utc((prior or {}).get("next_review_at"))
                review_resolution = _as_utc(evaluation.get("evaluated_at"))
        context["RETENTION_REVIEW"] = calculate_sla(
            target_key="RETENTION_REVIEW",
            versions=resolved_versions["RETENTION_REVIEW"],
            item_start=review_start,
            resolved_at=review_resolution,
            now=now,
            applicable=review_applicable,
            source_ref=(
                f"governance_retention_evaluation:{(evaluation or {}).get('evaluation_id')}"
                if evaluation is not None
                else None
            ),
        )

        disposition_status = str((disposition or {}).get("status") or "").upper()
        context["DISPOSITION_REVIEW"] = calculate_sla(
            target_key="DISPOSITION_REVIEW",
            versions=resolved_versions["DISPOSITION_REVIEW"],
            item_start=_as_utc((disposition or {}).get("requested_at")),
            resolved_at=(
                _as_utc((disposition or {}).get("reviewed_at"))
                if disposition is not None and disposition_status in _TERMINAL_DISPOSITION_STATUSES
                else None
            ),
            now=now,
            applicable=disposition is not None,
            source_ref=(
                f"governance_disposition:{(disposition or {}).get('disposition_id')}"
                if disposition is not None
                else None
            ),
        )

        active_holds = [
            hold for hold in holds if str(hold.get("status") or "").upper() in BLOCKING_HOLD_STATUSES
        ]
        earliest_hold = None
        for hold in active_holds:
            requested = _as_utc(hold.get("requested_at"))
            if requested is not None and (earliest_hold is None or requested < earliest_hold[0]):
                earliest_hold = (requested, hold)
        context["LEGAL_HOLD_REVIEW"] = calculate_sla(
            target_key="LEGAL_HOLD_REVIEW",
            versions=resolved_versions["LEGAL_HOLD_REVIEW"],
            item_start=earliest_hold[0] if earliest_hold is not None else None,
            resolved_at=None,
            now=now,
            applicable=bool(active_holds),
            source_ref=(
                f"governance_legal_hold:{earliest_hold[1].get('hold_id')}"
                if earliest_hold is not None
                else None
            ),
        )

        open_approvals = [
            approval
            for approval in approvals
            if str(approval.get("status") or "").upper()
            not in {"REJECTED", "VERIFIED", "EXPIRED", "WITHDRAWN"}
        ]
        earliest_approval = None
        for approval in open_approvals:
            requested = _as_utc(approval.get("requested_at"))
            if requested is not None and (earliest_approval is None or requested < earliest_approval[0]):
                earliest_approval = (requested, approval)
        context["EXPORT_APPROVAL"] = calculate_sla(
            target_key="EXPORT_APPROVAL",
            versions=resolved_versions["EXPORT_APPROVAL"],
            item_start=earliest_approval[0] if earliest_approval is not None else None,
            resolved_at=None,
            now=now,
            applicable=bool(open_approvals),
            source_ref=(
                f"governance_export_approval:{earliest_approval[1].get('approval_id')}"
                if earliest_approval is not None
                else None
            ),
        )
        return context

    def _case_inputs(
        self,
        case: Mapping[str, Any],
        *,
        now: datetime,
        evaluations: Mapping[str, Mapping[str, Any]] | None = None,
        sla_versions: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
        resolve_retention: bool = True,
    ) -> dict[str, Any]:
        case_id = str(case.get("case_id") or "")
        evaluation = (
            evaluations.get(case_id)
            if evaluations is not None
            else self._governance_repository.latest_evaluation(case_id)
        )
        verification: Mapping[str, Any] | None = None
        verification_error: str | None = None
        try:
            verification = self._forensics.latest_verification(case_id)
        except Exception as exc:  # noqa: BLE001 - reported as unavailable, never as PASS
            verification_error = type(exc).__name__
        try:
            holds, _ = self._governance_repository.list_holds(case_id=case_id, page_size=100)
        except Exception:  # noqa: BLE001 - scoring reports missing context
            holds = []
        try:
            disposition = self._governance_repository.latest_disposition(case_id)
        except Exception:  # noqa: BLE001
            disposition = None
        try:
            approvals, _ = self._governance_repository.list_export_approvals(case_id=case_id, page_size=100)
        except Exception:  # noqa: BLE001
            approvals = []
        categories = self._evidence_categories(case_id)
        try:
            policy = self._policy_for_case(case, categories)
        except Exception:  # noqa: BLE001 - policy context is reported unavailable
            policy = None
        incident = None
        incident_error = None
        incident_id = str(case.get("originating_incident_id") or "")
        if incident_id and self._incidents is not None:
            try:
                incident = self._incidents.get_incident(incident_id)
            except Exception as exc:  # noqa: BLE001
                incident_error = type(exc).__name__
        policy_mapping = policy.snapshot() if policy is not None else None
        sla_context = self._sla_context(
            case_id=case_id,
            evaluation=evaluation,
            disposition=disposition,
            holds=holds,
            approvals=approvals,
            now=now,
            versions=sla_versions,
            resolve_retention=resolve_retention,
        )
        return {
            "case": case,
            "evaluation": evaluation,
            "verification": verification,
            "verification_error": verification_error,
            "holds": holds,
            "disposition": disposition,
            "export_approvals": approvals,
            "policy": policy_mapping,
            "incident": incident,
            "incident_error": incident_error,
            "sla_context": sla_context,
        }

    def _score(
        self,
        case: Mapping[str, Any],
        *,
        now: datetime,
        model: Mapping[str, Any],
        evaluations: Mapping[str, Mapping[str, Any]] | None = None,
        sla_versions: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
        resolve_retention: bool = True,
        with_inputs: bool = False,
    ) -> dict[str, Any]:
        inputs = self._case_inputs(
            case,
            now=now,
            evaluations=evaluations,
            sla_versions=sla_versions,
            resolve_retention=resolve_retention,
        )
        result = score_case(
            case_id=str(case.get("case_id") or ""),
            case=case,
            evaluation=inputs["evaluation"],
            verification=inputs["verification"],
            verification_error=inputs["verification_error"],
            holds=inputs["holds"],
            disposition=inputs["disposition"],
            export_approvals=inputs["export_approvals"],
            policy=inputs["policy"],
            incident=inputs["incident"],
            incident_error=inputs["incident_error"],
            sla_context=inputs["sla_context"],
            model=model,
            now=now,
        )
        result["sla_context"] = inputs["sla_context"]
        result["non_claims"] = list(INTELLIGENCE_NON_CLAIMS)
        if with_inputs:
            result["_inputs"] = inputs
        return result

    def _scored_cases(
        self,
        *,
        now: datetime,
        model: Mapping[str, Any],
        case_status: str | None = None,
        case_severity: str | None = None,
        with_inputs: bool = False,
    ) -> tuple[list[dict[str, Any]], int, bool]:
        """Score a bounded case page once for listing and recommendation rules."""
        max_cases = int(getattr(self._settings, "governance_intelligence_max_cases", DEFAULT_RISK_CASES))
        cases, truncated = self._bounded_cases(max_cases)
        evaluation_limit = max(1, min(5000, max_cases))
        evaluations = {
            str(item.get("case_id")): item
            for item in self._governance_repository.latest_evaluations(limit=evaluation_limit)
        }
        sla_versions = self._sla_versions()
        scored: list[dict[str, Any]] = []
        unavailable = 0
        for case in cases:
            status = str(case.get("status") or "").upper()
            severity = str(case.get("severity") or "").upper()
            if case_status and status != str(case_status).upper():
                continue
            if case_severity and severity != str(case_severity).upper():
                continue
            try:
                result = self._score(
                    case,
                    now=now,
                    model=model,
                    evaluations=evaluations,
                    sla_versions=sla_versions,
                    resolve_retention=False,
                    with_inputs=with_inputs,
                )
            except Exception:  # noqa: BLE001 - one case must not break the page
                logger.warning("governance risk scoring failed for one case", exc_info=True)
                unavailable += 1
                continue
            record_governance_intelligence_score(
                risk_level=result["risk_level"],
                data_completeness=result["data_completeness"],
                duration_seconds=0.0,
            )
            scored.append(result)
        scored.sort(key=lambda item: (-int(item["score"]), item["case_id"]))
        return scored, unavailable, truncated

    def risk_cases(
        self,
        *,
        risk_level: str | None = None,
        case_status: str | None = None,
        case_severity: str | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        self._ensure_defaults()
        moment = self._clock()
        model = self._repository.latest_risk_model()
        if model is None:
            raise IntelligenceValidationError("governance risk model is not initialized")
        scored, unavailable, truncated = self._scored_cases(
            now=moment,
            model=model,
            case_status=case_status,
            case_severity=case_severity,
        )
        if risk_level:
            scored = [item for item in scored if item["risk_level"] == str(risk_level).upper()]
        size = int(
            page_size or getattr(self._settings, "governance_intelligence_page_size", DEFAULT_PAGE_SIZE)
        )
        size = min(MAX_PAGE_SIZE, max(1, size))
        page_number = max(1, int(page))
        start = (page_number - 1) * size
        counts = {level: 0 for level in RISK_LEVEL_ORDER}
        for item in scored:
            counts[item["risk_level"]] = counts.get(item["risk_level"], 0) + 1
        return {
            "items": [
                {
                    "case_id": item["case_id"],
                    "case_number": item.get("case_number"),
                    "case_status": item.get("case_status"),
                    "case_severity": item.get("case_severity"),
                    "score": item["score"],
                    "risk_level": item["risk_level"],
                    "data_completeness": item["data_completeness"],
                    "top_factors": [
                        factor["factor_id"] for factor in item["factors"] if not factor["suppressed"]
                    ][:3],
                    "model_version": item["model_version"],
                    "calculated_at": item["calculated_at"],
                }
                for item in scored[start : start + size]
            ],
            "total": len(scored),
            "page": page_number,
            "page_size": size,
            "risk_level_counts": counts,
            "model": {
                "model_id": model.get("model_id"),
                "version": model.get("version"),
            },
            "truncated": truncated,
            "unavailable_case_count": unavailable,
            "partial": truncated or unavailable > 0,
            "assurance": INTELLIGENCE_ASSURANCE,
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }

    def case_risk(self, case_id: str) -> dict[str, Any]:
        self._require_enabled()
        self._ensure_defaults()
        case = self._forensics.get_case(case_id)
        if case is None:
            raise RiskCaseNotFoundError(case_id)
        model = self._repository.latest_risk_model()
        if model is None:
            raise IntelligenceValidationError("governance risk model is not initialized")
        return {
            "risk": self._score(
                case,
                now=self._clock(),
                model=model,
                sla_versions=self._sla_versions(),
            ),
            "assurance": INTELLIGENCE_ASSURANCE,
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }

    # ------------------------------------------------------------------
    # SLA backlog
    # ------------------------------------------------------------------
    def sla_backlog(
        self,
        *,
        target_key: str | None = None,
        state: str | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        self._ensure_defaults()
        moment = self._clock()
        max_items = int(getattr(self._settings, "governance_intelligence_max_cases", DEFAULT_RISK_CASES))
        items: list[dict[str, Any]] = []
        availability: dict[str, dict[str, Any]] = {}
        truncated = False
        sla_versions = self._sla_versions()

        try:
            retention = self._governance_repository.latest_evaluations(limit=max_items)
            availability["retention"] = {"availability": "OK", "message": ""}
        except Exception as exc:  # noqa: BLE001
            retention = []
            availability["retention"] = {
                "availability": "UNAVAILABLE",
                "message": f"Retention evaluations could not be read ({type(exc).__name__}).",
            }
        retention_versions = sla_versions["RETENTION_REVIEW"]
        for evaluation in retention:
            review_state = str(evaluation.get("governance_state") or "").upper()
            if review_state != "REVIEW_DUE":
                continue
            sla = calculate_sla(
                target_key="RETENTION_REVIEW",
                versions=retention_versions,
                item_start=_as_utc(evaluation.get("next_review_at")),
                resolved_at=None,
                now=moment,
                source_ref=f"governance_retention_evaluation:{evaluation.get('evaluation_id')}",
            )
            items.append(
                {
                    "item_type": "RETENTION_REVIEW",
                    "item_id": evaluation.get("evaluation_id"),
                    "case_id": evaluation.get("case_id"),
                    "label": "Retention review",
                    "sla": sla,
                }
            )

        try:
            dispositions = self._governance_repository.list_open_dispositions(limit=max_items)
            availability["disposition"] = {"availability": "OK", "message": ""}
        except Exception as exc:  # noqa: BLE001
            dispositions = []
            availability["disposition"] = {
                "availability": "UNAVAILABLE",
                "message": f"Open dispositions could not be read ({type(exc).__name__}).",
            }
        disposition_versions = sla_versions["DISPOSITION_REVIEW"]
        for disposition in dispositions:
            items.append(
                {
                    "item_type": "DISPOSITION_REVIEW",
                    "item_id": disposition.get("disposition_id"),
                    "case_id": disposition.get("case_id"),
                    "label": "Disposition review",
                    "sla": calculate_sla(
                        target_key="DISPOSITION_REVIEW",
                        versions=disposition_versions,
                        item_start=_as_utc(disposition.get("requested_at")),
                        resolved_at=None,
                        now=moment,
                        source_ref=f"governance_disposition:{disposition.get('disposition_id')}",
                    ),
                }
            )

        try:
            holds = self._governance_repository.list_blocking_holds(limit=max_items)
            availability["legal_hold"] = {"availability": "OK", "message": ""}
        except Exception as exc:  # noqa: BLE001
            holds = []
            availability["legal_hold"] = {
                "availability": "UNAVAILABLE",
                "message": f"Blocking legal holds could not be read ({type(exc).__name__}).",
            }
        hold_versions = sla_versions["LEGAL_HOLD_REVIEW"]
        for hold in holds:
            items.append(
                {
                    "item_type": "LEGAL_HOLD_REVIEW",
                    "item_id": hold.get("hold_id"),
                    "case_id": hold.get("case_id"),
                    "label": "Legal hold review",
                    "sla": calculate_sla(
                        target_key="LEGAL_HOLD_REVIEW",
                        versions=hold_versions,
                        item_start=_as_utc(hold.get("requested_at")),
                        resolved_at=None,
                        now=moment,
                        source_ref=f"governance_legal_hold:{hold.get('hold_id')}",
                    ),
                }
            )

        try:
            approvals = self._governance_repository.list_export_approvals_all(limit=max_items)
            availability["export_approval"] = {"availability": "OK", "message": ""}
        except Exception as exc:  # noqa: BLE001
            approvals = []
            availability["export_approval"] = {
                "availability": "UNAVAILABLE",
                "message": f"Export approvals could not be read ({type(exc).__name__}).",
            }
        export_versions = sla_versions["EXPORT_APPROVAL"]
        open_export_statuses = {
            "PENDING_APPROVAL",
            "POLICY_AUTO_APPROVED",
            "APPROVED",
            "GENERATED",
            "VERIFICATION_FAILED",
        }
        for approval in approvals:
            if str(approval.get("status") or "").upper() not in open_export_statuses:
                continue
            items.append(
                {
                    "item_type": "EXPORT_APPROVAL",
                    "item_id": approval.get("approval_id"),
                    "case_id": approval.get("case_id"),
                    "label": "Export approval",
                    "sla": calculate_sla(
                        target_key="EXPORT_APPROVAL",
                        versions=export_versions,
                        item_start=_as_utc(approval.get("requested_at")),
                        resolved_at=None,
                        now=moment,
                        source_ref=f"governance_export_approval:{approval.get('approval_id')}",
                    ),
                }
            )

        if len(items) > max_items:
            items = items[:max_items]
            truncated = True
        if target_key:
            normalized_key = str(target_key).upper()
            if normalized_key not in SLA_TARGET_KEYS:
                raise SlaTargetNotFoundError(normalized_key)
            items = [item for item in items if item["sla"]["target_key"] == normalized_key]
        if state:
            normalized_state = str(state).upper()
            if normalized_state not in {member.value for member in SlaState}:
                raise IntelligenceValidationError(f"unsupported SLA state: {state}")
            items = [item for item in items if item["sla"]["state"] == normalized_state]

        items.sort(
            key=lambda item: (
                -int(item["sla"].get("open_age_hours") or 0),
                str(item["item_type"]),
                str(item["item_id"]),
            )
        )
        counts: dict[str, dict[str, int]] = {}
        for item in items:
            key = item["sla"]["target_key"]
            state_name = item["sla"]["state"]
            counts.setdefault(key, {}).setdefault(state_name, 0)
            counts[key][state_name] += 1
        for key, states in counts.items():
            set_governance_intelligence_sla_counts(key, states)

        size = int(
            page_size or getattr(self._settings, "governance_intelligence_page_size", DEFAULT_PAGE_SIZE)
        )
        size = min(MAX_PAGE_SIZE, max(1, size))
        page_number = max(1, int(page))
        start = (page_number - 1) * size
        unavailable_sources = [
            name for name, status in availability.items() if status.get("availability") == "UNAVAILABLE"
        ]
        return {
            "items": items[start : start + size],
            "total": len(items),
            "page": page_number,
            "page_size": size,
            "state_counts": counts,
            "availability": availability,
            "partial": truncated or bool(unavailable_sources),
            "truncated": truncated,
            "unavailable_sources": unavailable_sources,
            "sla_kind": SLA_KIND_OPERATIONAL,
            "non_claim": SLA_NON_CLAIM,
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }

    # ------------------------------------------------------------------
    # Bounded trend analytics
    # ------------------------------------------------------------------
    def trends(
        self,
        *,
        start_at: datetime | str | None = None,
        end_at: datetime | str | None = None,
        bucket: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        moment = self._clock()
        if start_at is None and end_at is None:
            days = min(
                MAX_TREND_WINDOW_DAYS,
                max(
                    1,
                    int(
                        getattr(
                            self._settings,
                            "governance_intelligence_default_window_days",
                            DEFAULT_TREND_WINDOW_DAYS,
                        )
                    ),
                ),
            )
            end_at = moment
            start_at = moment - timedelta(days=days)
        try:
            window = TimeRange(start_at=start_at, end_at=end_at)
            start = window.start_at
            end = window.end_at
            if start is None or end is None:
                raise ValueError("time window bounds are required")
            grain = validate_bucket(bucket or DEFAULT_TREND_BUCKET, start, end)
        except Exception as exc:
            raise IntelligenceValidationError(f"invalid trend window: {exc}") from None

        try:
            coverage = self._governance_repository.historical_coverage()
            coverage_known = True
            coverage_message = ""
        except Exception as exc:  # noqa: BLE001 - reported as unknown, never as zero
            coverage = {}
            coverage_known = False
            coverage_message = (
                f"Historical coverage could not be read ({type(exc).__name__}); "
                "buckets retain actual counts but coverage gaps are unknown."
            )

        sources: dict[str, dict[str, Any]] = {}

        def build_source(
            name: str,
            *,
            moments: Sequence[Any],
            categories: Sequence[str],
            category_values: Sequence[str],
            coverage_start: datetime | None,
            availability: str = "OK",
            message: str = "",
            truncated: bool = False,
            unavailable_categories: Sequence[str] = (),
            source_coverage_known: bool | None = None,
        ) -> None:
            known = coverage_known if source_coverage_known is None else source_coverage_known
            totals = Counter(_bounded_category(value, categories) for value in category_values)
            unavailable = {str(item) for item in unavailable_categories}
            category_totals = {
                category: (None if category in unavailable else int(totals.get(category, 0)))
                for category in categories
            }
            sources[name] = {
                "availability": availability,
                "message": message,
                "definition": _TREND_DEFINITIONS.get(name, ""),
                "coverage_start": _iso(coverage_start) if known else None,
                "coverage_available": known,
                "no_history": bool(known and coverage_start is None),
                "truncated": bool(truncated),
                "total": int(sum(value for value in category_totals.values() if value is not None)),
                "categories": list(categories),
                "category_totals": category_totals,
                "buckets": _bucket_series(
                    moments,
                    start=start,
                    end=end,
                    bucket=grain,
                    coverage_start=coverage_start,
                    coverage_known=known,
                    counts_unavailable=availability == "UNAVAILABLE",
                ),
            }

        # Governance access-audit events.
        try:
            audit_rows = self._governance_repository.audit_timestamps_in_range(
                start, end, limit=MAX_TREND_ROWS
            )
            build_source(
                "governance_events",
                moments=[row.get("created_at") for row in audit_rows],
                categories=TREND_AUDIT_GROUPS,
                category_values=[audit_event_group(str(row.get("event_type") or "")) for row in audit_rows],
                coverage_start=_as_utc(coverage.get("governance_audit")),
                truncated=len(audit_rows) >= MAX_TREND_ROWS,
            )
        except Exception as exc:  # noqa: BLE001
            build_source(
                "governance_events",
                moments=[],
                categories=TREND_AUDIT_GROUPS,
                category_values=[],
                coverage_start=None,
                availability="UNAVAILABLE",
                message=f"Governance audit events could not be read ({type(exc).__name__}).",
                source_coverage_known=False,
            )

        # Retention evaluation observations.
        try:
            retention_rows = self._governance_repository.retention_timestamps_in_range(
                start, end, limit=MAX_TREND_ROWS
            )
            build_source(
                "retention_evaluations",
                moments=[row.get("evaluated_at") for row in retention_rows],
                categories=_RETENTION_TREND_CATEGORIES,
                category_values=[
                    _bounded_category(row.get("governance_state"), _RETENTION_TREND_CATEGORIES)
                    for row in retention_rows
                ],
                coverage_start=_as_utc(coverage.get("retention_evaluations")),
                truncated=len(retention_rows) >= MAX_TREND_ROWS,
            )
        except Exception as exc:  # noqa: BLE001
            build_source(
                "retention_evaluations",
                moments=[],
                categories=_RETENTION_TREND_CATEGORIES,
                category_values=[],
                coverage_start=None,
                availability="UNAVAILABLE",
                message=f"Retention evaluations could not be read ({type(exc).__name__}).",
                source_coverage_known=False,
            )

        # Recommendation lifecycle events.
        try:
            recommendation_rows = self._repository.recommendation_timestamps_in_range(
                start, end, limit=MAX_TREND_ROWS
            )
            try:
                recommendation_coverage = _as_utc(self._repository.recommendation_coverage_start())
                recommendation_coverage_known = True
            except Exception:  # noqa: BLE001 - rows are still usable
                recommendation_coverage = None
                recommendation_coverage_known = False
            build_source(
                "recommendations",
                moments=[row.get("created_at") for row in recommendation_rows],
                categories=_RECOMMENDATION_TREND_CATEGORIES,
                category_values=[
                    _bounded_category(row.get("event_type"), _RECOMMENDATION_TREND_CATEGORIES)
                    for row in recommendation_rows
                ],
                coverage_start=recommendation_coverage,
                truncated=len(recommendation_rows) >= MAX_TREND_ROWS,
                source_coverage_known=recommendation_coverage_known,
            )
        except Exception as exc:  # noqa: BLE001
            build_source(
                "recommendations",
                moments=[],
                categories=_RECOMMENDATION_TREND_CATEGORIES,
                category_values=[],
                coverage_start=None,
                availability="UNAVAILABLE",
                message=f"Recommendation events could not be read ({type(exc).__name__}).",
                source_coverage_known=False,
            )

        # Operational SLA inflow observations.
        inflow_components: dict[str, dict[str, Any]] = {}
        inflow_moments: list[Any] = []
        inflow_categories: list[str] = []
        inflow_failed: list[str] = []
        inflow_coverage_values: list[str | None] = []
        try:
            disposition_rows = self._governance_repository.disposition_timestamps_in_range(
                start, end, limit=MAX_TREND_ROWS
            )
            inflow_moments.extend(row.get("requested_at") for row in disposition_rows)
            inflow_categories.extend(["DISPOSITION_REVIEW"] * len(disposition_rows))
            inflow_components["disposition"] = {
                "availability": "OK",
                "truncated": len(disposition_rows) >= MAX_TREND_ROWS,
            }
            inflow_coverage_values.append(coverage.get("dispositions"))
        except Exception as exc:  # noqa: BLE001
            inflow_failed.append("disposition")
            inflow_components["disposition"] = {
                "availability": "UNAVAILABLE",
                "message": f"Disposition requests could not be read ({type(exc).__name__}).",
            }
        try:
            hold_rows = self._governance_repository.legal_hold_timestamps_in_range(
                start, end, limit=MAX_TREND_ROWS
            )
            inflow_moments.extend(row.get("requested_at") for row in hold_rows)
            inflow_categories.extend(["LEGAL_HOLD_REVIEW"] * len(hold_rows))
            inflow_components["legal_hold"] = {
                "availability": "OK",
                "truncated": len(hold_rows) >= MAX_TREND_ROWS,
            }
            inflow_coverage_values.append(coverage.get("legal_holds"))
        except Exception as exc:  # noqa: BLE001
            inflow_failed.append("legal_hold")
            inflow_components["legal_hold"] = {
                "availability": "UNAVAILABLE",
                "message": f"Legal holds could not be read ({type(exc).__name__}).",
            }
        try:
            approval_rows = self._governance_repository.export_approval_timestamps_in_range(
                start, end, limit=MAX_TREND_ROWS
            )
            inflow_moments.extend(row.get("requested_at") for row in approval_rows)
            inflow_categories.extend(["EXPORT_APPROVAL"] * len(approval_rows))
            inflow_components["export_approval"] = {
                "availability": "OK",
                "truncated": len(approval_rows) >= MAX_TREND_ROWS,
            }
            inflow_coverage_values.append(coverage.get("export_approvals"))
        except Exception as exc:  # noqa: BLE001
            inflow_failed.append("export_approval")
            inflow_components["export_approval"] = {
                "availability": "UNAVAILABLE",
                "message": f"Export approvals could not be read ({type(exc).__name__}).",
            }
        try:
            due_rows = self._governance_repository.retention_timestamps_in_range(
                start, end, limit=MAX_TREND_ROWS
            )
            due_rows = [
                row for row in due_rows if str(row.get("governance_state") or "").upper() == "REVIEW_DUE"
            ]
            inflow_moments.extend(row.get("evaluated_at") for row in due_rows)
            inflow_categories.extend(["RETENTION_REVIEW"] * len(due_rows))
            inflow_components["retention"] = {
                "availability": "OK",
                "truncated": len(due_rows) >= MAX_TREND_ROWS,
            }
            inflow_coverage_values.append(coverage.get("retention_evaluations"))
        except Exception as exc:  # noqa: BLE001
            inflow_failed.append("retention")
            inflow_components["retention"] = {
                "availability": "UNAVAILABLE",
                "message": f"Retention due observations could not be read ({type(exc).__name__}).",
            }
        inflow_availability = (
            "UNAVAILABLE" if len(inflow_failed) == 4 else "DEGRADED" if inflow_failed else "OK"
        )
        build_source(
            "sla_inflow",
            moments=inflow_moments,
            categories=SLA_TARGET_KEYS,
            category_values=inflow_categories,
            coverage_start=_coverage_min(inflow_coverage_values),
            availability=inflow_availability,
            message=(
                "Some SLA inflow sources are unavailable; their categories are null, not zero."
                if inflow_failed
                else ""
            ),
            truncated=any(
                bool(component.get("truncated"))
                for component in inflow_components.values()
                if component.get("availability") == "OK"
            ),
            unavailable_categories=[
                {
                    "disposition": "DISPOSITION_REVIEW",
                    "legal_hold": "LEGAL_HOLD_REVIEW",
                    "export_approval": "EXPORT_APPROVAL",
                    "retention": "RETENTION_REVIEW",
                }[name]
                for name in inflow_failed
            ],
            source_coverage_known=coverage_known,
        )
        sources["sla_inflow"]["components"] = inflow_components

        # Risk-score history is not persisted by design.
        build_source(
            "risk_scores",
            moments=[],
            categories=[],
            category_values=[],
            coverage_start=None,
            availability="UNAVAILABLE",
            message=(
                "Historical risk scores are not persisted. Current scores are computed on "
                "demand from stored governance records."
            ),
            source_coverage_known=False,
        )

        unavailable_sources = [
            name for name, source in sources.items() if source.get("availability") == "UNAVAILABLE"
        ]
        degraded_sources = [
            name for name, source in sources.items() if source.get("availability") == "DEGRADED"
        ]
        truncated = any(bool(source.get("truncated")) for source in sources.values())
        return {
            "start_at": _iso(start),
            "end_at": _iso(end),
            "bucket": grain,
            "timezone": "UTC",
            "source_order": list(TREND_SOURCE_ORDER),
            "sources": sources,
            "coverage": {
                "available": coverage_known,
                "message": coverage_message,
                "earliest": {key: _iso(_as_utc(value)) if value else None for key, value in coverage.items()},
            },
            "partial": bool(unavailable_sources or degraded_sources or truncated or not coverage_known),
            "truncated": truncated,
            "unavailable_sources": unavailable_sources,
            "degraded_sources": degraded_sources,
            "assurance": INTELLIGENCE_ASSURANCE,
            "limitations": list(INTELLIGENCE_LIMITATIONS),
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }

    # ------------------------------------------------------------------
    # Advisory recommendations
    # ------------------------------------------------------------------
    @staticmethod
    def _recommendation_candidate(
        rule_id: str,
        scope_type: str,
        scope_id: str,
        *,
        case_id: str | None,
        severity: str | None,
        risk_level: str | None,
        rationale: str,
        source_refs: Sequence[str],
    ) -> dict[str, Any]:
        title, default_severity = RECOMMENDATION_RULES[rule_id]
        return {
            "rule_id": rule_id,
            "scope_type": scope_type,
            "scope_id": scope_id,
            "case_id": case_id,
            "severity": severity or default_severity,
            "risk_level": risk_level,
            "title": title,
            "rationale": rationale,
            "source_refs": list(source_refs),
        }

    def _recommendation_candidates(
        self,
        *,
        now: datetime,
        model: Mapping[str, Any],
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        scored, unavailable_cases, cases_truncated = self._scored_cases(
            now=now, model=model, with_inputs=True
        )
        candidates: list[dict[str, Any]] = []
        seen: set[str] = set()

        def add(candidate: dict[str, Any]) -> None:
            key = recommendation_key(candidate["rule_id"], candidate["scope_type"], candidate["scope_id"])
            if key in seen:
                return
            seen.add(key)
            candidates.append(candidate)

        for item in scored:
            case_id = str(item.get("case_id") or "")
            risk_level = str(item.get("risk_level") or "")
            active_factors = [
                factor
                for factor in item.get("factors") or []
                if not factor.get("suppressed") and int(factor.get("points") or 0) > 0
            ]
            factor_ids = {str(factor.get("factor_id") or "") for factor in active_factors}
            top_factors = sorted(
                active_factors,
                key=lambda factor: (-int(factor.get("points") or 0), str(factor.get("factor_id"))),
            )[:3]
            top_text = (
                ", ".join(
                    f"{factor.get('factor_id')} ({factor.get('points')} points)" for factor in top_factors
                )
                or "no scored factors"
            )
            if risk_level == "CRITICAL":
                add(
                    self._recommendation_candidate(
                        "GOV-RISK-001",
                        RECOMMENDATION_SCOPE_CASE,
                        case_id,
                        case_id=case_id,
                        severity="CRITICAL",
                        risk_level=risk_level,
                        rationale=(
                            f"Case {case_id} scored {item.get('score')}/100. Top factors: {top_text}."
                        ),
                        source_refs=[
                            f"risk_case:{case_id}",
                            f"risk_model:{item.get('model_id')}:v{item.get('model_version')}",
                        ],
                    )
                )
            elif risk_level == "HIGH":
                add(
                    self._recommendation_candidate(
                        "GOV-RISK-002",
                        RECOMMENDATION_SCOPE_CASE,
                        case_id,
                        case_id=case_id,
                        severity="HIGH",
                        risk_level=risk_level,
                        rationale=(
                            f"Case {case_id} scored {item.get('score')}/100. Top factors: {top_text}."
                        ),
                        source_refs=[
                            f"risk_case:{case_id}",
                            f"risk_model:{item.get('model_id')}:v{item.get('model_version')}",
                        ],
                    )
                )

            if "CONFIRMED_INTEGRITY_FAILURE" in factor_ids:
                add(
                    self._recommendation_candidate(
                        "GOV-INT-001",
                        RECOMMENDATION_SCOPE_CASE,
                        case_id,
                        case_id=case_id,
                        severity="HIGH",
                        risk_level=risk_level,
                        rationale=(
                            f"A confirmed V34 integrity failure is recorded for case {case_id}. "
                            "Only a confirmed FAIL is treated as a failure."
                        ),
                        source_refs=[f"forensic_verification:{case_id}"],
                    )
                )
            elif "INTEGRITY_VERIFICATION_UNAVAILABLE" in factor_ids:
                add(
                    self._recommendation_candidate(
                        "GOV-INT-002",
                        RECOMMENDATION_SCOPE_CASE,
                        case_id,
                        case_id=case_id,
                        severity="MEDIUM",
                        risk_level=risk_level,
                        rationale=(
                            f"Integrity verification is unavailable for case {case_id}. "
                            "This is not a confirmed failure and not a PASS."
                        ),
                        source_refs=[f"forensic_verification:{case_id}"],
                    )
                )

            sla_context = item.get("sla_context") or {}
            for target_key, rule_id, scope_type, label in (
                ("RETENTION_REVIEW", "GOV-RET-001", RECOMMENDATION_SCOPE_CASE, "retention review"),
                (
                    "DISPOSITION_REVIEW",
                    "GOV-DISP-001",
                    RECOMMENDATION_SCOPE_DISPOSITION,
                    "disposition review",
                ),
                (
                    "LEGAL_HOLD_REVIEW",
                    "GOV-HOLD-001",
                    RECOMMENDATION_SCOPE_LEGAL_HOLD,
                    "legal-hold review",
                ),
                (
                    "EXPORT_APPROVAL",
                    "GOV-EXP-001",
                    RECOMMENDATION_SCOPE_EXPORT_APPROVAL,
                    "export approval",
                ),
            ):
                context = sla_context.get(target_key) or {}
                if str(context.get("state") or "").upper() != SlaState.BREACHED.value:
                    continue
                source_ref = str(context.get("source_ref") or "")
                item_id = source_ref.split(":")[-1] if source_ref else case_id
                add(
                    self._recommendation_candidate(
                        rule_id,
                        scope_type,
                        item_id,
                        case_id=case_id,
                        severity="HIGH",
                        risk_level=risk_level,
                        rationale=(
                            f"The operational {label} SLA for case {case_id} is breached "
                            f"({context.get('open_age_hours')} hours open against a "
                            f"{context.get('target_hours')}-hour target, version "
                            f"{context.get('target_version')}). This is not a legal deadline."
                        ),
                        source_refs=[source_ref or f"case:{case_id}"],
                    )
                )

            inputs = item.get("_inputs") or {}
            for approval in inputs.get("export_approvals") or []:
                approval_id = str(approval.get("approval_id") or "")
                if not approval_id:
                    continue
                status = str(approval.get("status") or "").upper()
                expires_at = _as_utc(approval.get("expires_at"))
                expired = status == "EXPIRED" or (expires_at is not None and expires_at <= now)
                expiring = expires_at is not None and now < expires_at <= now + timedelta(days=7)
                if not (expired or expiring):
                    continue
                add(
                    self._recommendation_candidate(
                        "GOV-EXP-001",
                        RECOMMENDATION_SCOPE_EXPORT_APPROVAL,
                        approval_id,
                        case_id=case_id,
                        severity="HIGH" if expired else "MEDIUM",
                        risk_level=risk_level,
                        rationale=(
                            f"Export approval {approval_id} for case {case_id} is "
                            f"{'expired' if expired else 'expiring within 7 days'}"
                            f" (status {status or 'UNKNOWN'}, "
                            f"expires_at {_iso(expires_at) or 'unavailable'})."
                        ),
                        source_refs=[f"governance_export_approval:{approval_id}"],
                    )
                )

        source_status: dict[str, Any] = {
            "cases": {
                "availability": "DEGRADED" if unavailable_cases else "OK",
                "message": (f"{unavailable_cases} case(s) could not be scored." if unavailable_cases else ""),
                "truncated": cases_truncated,
            }
        }

        # Snapshot digest mismatches are never silently ignored.
        snapshot_status: dict[str, Any] = {
            "availability": "OK",
            "message": "",
            "truncated": False,
        }
        try:
            if self._automation is None:
                raise RuntimeError("automation repository is not initialized")
            snapshots, snapshot_total = self._automation.list_snapshots(page=1, page_size=100)
            snapshot_status["truncated"] = int(snapshot_total) > len(snapshots)
            for snapshot in snapshots:
                if snapshot.get("digest_valid") is not False:
                    continue
                snapshot_id = str(snapshot.get("snapshot_id") or "")
                add(
                    self._recommendation_candidate(
                        "GOV-SNAP-001",
                        RECOMMENDATION_SCOPE_SNAPSHOT,
                        snapshot_id,
                        case_id=None,
                        severity="HIGH",
                        risk_level=None,
                        rationale=(
                            f"Stored snapshot {snapshot_id} does not match its self-digest. "
                            "The snapshot is preserved for investigation; no diff is trusted."
                        ),
                        source_refs=[f"governance_snapshot:{snapshot_id}"],
                    )
                )
        except Exception as exc:  # noqa: BLE001
            snapshot_status = {
                "availability": "UNAVAILABLE",
                "message": f"Snapshots could not be read ({type(exc).__name__}).",
                "truncated": False,
            }
        source_status["snapshots"] = snapshot_status

        automation_status: dict[str, Any] = {
            "availability": "OK",
            "message": "",
            "truncated": False,
        }
        try:
            if self._automation is None:
                raise RuntimeError("automation repository is not initialized")
            latest_jobs = self._automation.latest_jobs_by_type()
            for job_type, job in latest_jobs.items():
                status = str(job.get("status") or "").upper()
                attempt = int(job.get("attempt") or 0)
                if status != "FAILED" or attempt < 2:
                    continue
                add(
                    self._recommendation_candidate(
                        "GOV-AUTO-001",
                        RECOMMENDATION_SCOPE_AUTOMATION,
                        str(job_type),
                        case_id=None,
                        severity="MEDIUM",
                        risk_level=None,
                        rationale=(
                            f"The latest {job_type} automation job failed after {attempt} "
                            f"attempt(s) with {job.get('error_code') or 'an unknown error'}."
                        ),
                        source_refs=[f"automation_job:{job.get('job_id')}"],
                    )
                )
        except Exception as exc:  # noqa: BLE001
            automation_status = {
                "availability": "UNAVAILABLE",
                "message": f"Automation job state could not be read ({type(exc).__name__}).",
                "truncated": False,
            }
        source_status["automation"] = automation_status
        return candidates, source_status

    def refresh_recommendations(
        self,
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
        reason: str = "",
    ) -> dict[str, Any]:
        self._require_enabled()
        self._ensure_defaults()
        moment = self._clock()
        model = self._repository.latest_risk_model()
        if model is None:
            raise IntelligenceValidationError("governance risk model is not initialized")
        try:
            candidates, source_status = self._recommendation_candidates(now=moment, model=model)
            max_items = int(
                getattr(self._settings, "governance_intelligence_max_recommendations", MAX_REFRESH_ITEMS)
            )
            summary = self._repository.sync_recommendations(
                candidates, now=moment, max_items=max(1, min(MAX_REFRESH_ITEMS, max_items))
            )
        except Exception:
            record_governance_intelligence_refresh("FAILED")
            raise

        counts = self._repository.recommendation_counts()
        set_governance_intelligence_recommendation_counts(counts.get("by_status_severity", {}))
        record_governance_intelligence_refresh("REFRESHED")
        for outcome in ("CREATED", "REOPENED", "AUTO_RESOLVED"):
            key = outcome.lower()
            if int(summary.get(key, 0) or 0) > 0:
                record_governance_intelligence_refresh(outcome)

        alerts = {
            "enabled": False,
            "considered": 0,
            "queued": 0,
            "duplicate": 0,
            "suppressed": 0,
            "no_rule": 0,
            "failed": 0,
        }
        if (
            bool(getattr(self._settings, "governance_intelligence_alerts_enabled", False))
            and self._notifier is not None
            and bool(getattr(self._notifier, "enabled", False))
        ):
            alerts["enabled"] = True
            for recommendation_id_value in summary.get("created_ids", []):
                recommendation = self._repository.get_recommendation(recommendation_id_value)
                if recommendation is None:
                    continue
                if str(recommendation.get("severity") or "").upper() != "CRITICAL":
                    continue
                stats = self._notifier.notify_event(
                    event_type=INTELLIGENCE_ALERT_EVENT_TYPE,
                    case={
                        "case_id": recommendation.get("case_id"),
                        "case_number": None,
                        "status": recommendation.get("status"),
                        "version": recommendation.get("version"),
                    },
                    target_type="GOVERNANCE_RECOMMENDATION",
                    target_id=str(recommendation.get("recommendation_id")),
                    severity="CRITICAL",
                    detail=(
                        f"Recommendation {recommendation.get('rule_id')}: "
                        f"{recommendation.get('title')}. Advisory review only."
                    ),
                    reason_codes=[str(recommendation.get("rule_id") or "")],
                    dedup_version=recommendation.get("version"),
                )
                for key in ("considered", "queued", "duplicate", "suppressed", "no_rule", "failed"):
                    alerts[key] += int(stats.get(key, 0))

        truncated = bool(summary.get("truncated")) or any(
            bool(status.get("truncated")) for status in source_status.values()
        )
        unavailable_sources = [
            name for name, status in source_status.items() if status.get("availability") == "UNAVAILABLE"
        ]
        degraded_sources = [
            name for name, status in source_status.items() if status.get("availability") == "DEGRADED"
        ]
        self._audit(
            event_type=GovernanceAuditEventType.INTELLIGENCE_RECOMMENDATIONS_REFRESHED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="GOVERNANCE_INTELLIGENCE",
            target_id="recommendations",
            reason=reason or "Manual governance recommendation refresh.",
            request_id=request_id,
            event_key=f"intelligence:recommendations:refresh:{_iso(moment)}",
            metadata={
                "created": int(summary.get("created", 0)),
                "refreshed": int(summary.get("refreshed", 0)),
                "reopened": int(summary.get("reopened", 0)),
                "auto_resolved": int(summary.get("auto_resolved", 0)),
                "suppressed": int(summary.get("suppressed", 0)),
            },
        )
        return {
            "summary": summary,
            "counts": counts,
            "alerts": alerts,
            "sources": source_status,
            "partial": bool(unavailable_sources or degraded_sources or truncated),
            "truncated": truncated,
            "unavailable_sources": unavailable_sources,
            "degraded_sources": degraded_sources,
            "assurance": INTELLIGENCE_ASSURANCE,
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }

    def list_recommendations(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        self._ensure_defaults()
        if status and str(status).upper() not in RECOMMENDATION_STATUS_VALUES:
            raise IntelligenceValidationError(f"unsupported recommendation status: {status}")
        if severity and str(severity).upper() not in RECOMMENDATION_SEVERITY_VALUES:
            raise IntelligenceValidationError(f"unsupported recommendation severity: {severity}")
        if rule_id and str(rule_id).upper() not in RULE_IDS:
            raise IntelligenceValidationError(f"unsupported recommendation rule: {rule_id}")
        size = int(
            page_size or getattr(self._settings, "governance_intelligence_page_size", DEFAULT_PAGE_SIZE)
        )
        size = min(MAX_PAGE_SIZE, max(1, size))
        page_number = max(1, int(page))
        items, total = self._repository.list_recommendations(
            status=status,
            severity=severity,
            rule_id=rule_id,
            page=page_number,
            page_size=size,
        )
        counts = self._repository.recommendation_counts()
        set_governance_intelligence_recommendation_counts(counts.get("by_status_severity", {}))
        return {
            "items": items,
            "total": total,
            "page": page_number,
            "page_size": size,
            "counts": counts,
            "assurance": INTELLIGENCE_ASSURANCE,
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }

    def recommendation_detail(self, recommendation_id: str) -> dict[str, Any]:
        self._require_enabled()
        self._ensure_defaults()
        recommendation = self._repository.get_recommendation(recommendation_id)
        if recommendation is None:
            raise RecommendationNotFoundError(recommendation_id)
        return {
            "recommendation": recommendation,
            "events": self._repository.recommendation_events(recommendation_id),
            "assurance": INTELLIGENCE_ASSURANCE,
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }

    def _transition_recommendation(
        self,
        recommendation_id: str,
        *,
        target_status: str,
        reason: str,
        expected_version: int | None,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None,
    ) -> dict[str, Any]:
        self._require_enabled()
        self._ensure_defaults()
        normalized = str(target_status).upper()
        text = str(reason or "").strip()
        if normalized == RecommendationStatus.DISMISSED.value:
            if len(text) < MIN_DISMISS_REASON_LENGTH:
                raise IntelligenceValidationError(
                    f"a dismissal reason of at least {MIN_DISMISS_REASON_LENGTH} characters is required"
                )
            if len(text) > MAX_DISMISS_REASON_LENGTH:
                raise IntelligenceValidationError(
                    f"a dismissal reason must be at most {MAX_DISMISS_REASON_LENGTH} characters"
                )
        elif len(text) > MAX_RECOMMENDATION_REASON_LENGTH:
            raise IntelligenceValidationError(
                f"a recommendation reason must be at most {MAX_RECOMMENDATION_REASON_LENGTH} characters"
            )
        updated = self._repository.transition_recommendation(
            recommendation_id,
            target_status=normalized,
            expected_version=expected_version,
            actor_id=actor_id,
            actor_role=actor_role,
            reason=text,
        )
        event_type = {
            RecommendationStatus.ACKNOWLEDGED.value: (
                GovernanceAuditEventType.INTELLIGENCE_RECOMMENDATION_ACKNOWLEDGED.value
            ),
            RecommendationStatus.DISMISSED.value: (
                GovernanceAuditEventType.INTELLIGENCE_RECOMMENDATION_DISMISSED.value
            ),
            RecommendationStatus.RESOLVED.value: (
                GovernanceAuditEventType.INTELLIGENCE_RECOMMENDATION_RESOLVED.value
            ),
        }.get(normalized, GovernanceAuditEventType.INTELLIGENCE_RECOMMENDATION_ACKNOWLEDGED.value)
        self._audit(
            event_type=event_type,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="GOVERNANCE_RECOMMENDATION",
            target_id=recommendation_id,
            case_id=updated.get("case_id"),
            reason=text or f"Recommendation transitioned to {normalized}.",
            request_id=request_id,
            event_key=(
                f"intelligence:recommendation:{recommendation_id}:{normalized.lower()}:"
                f"v{updated.get('version')}"
            ),
            metadata={
                "rule_id": updated.get("rule_id"),
                "status": normalized,
                "version": updated.get("version"),
            },
        )
        return {
            "recommendation": updated,
            "events": self._repository.recommendation_events(recommendation_id),
            "assurance": INTELLIGENCE_ASSURANCE,
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }

    def acknowledge_recommendation(
        self,
        recommendation_id: str,
        *,
        reason: str = "",
        expected_version: int | None = None,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return self._transition_recommendation(
            recommendation_id,
            target_status=RecommendationStatus.ACKNOWLEDGED.value,
            reason=reason,
            expected_version=expected_version,
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=request_id,
        )

    def dismiss_recommendation(
        self,
        recommendation_id: str,
        *,
        reason: str,
        expected_version: int | None = None,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return self._transition_recommendation(
            recommendation_id,
            target_status=RecommendationStatus.DISMISSED.value,
            reason=reason,
            expected_version=expected_version,
            actor_id=actor_id,
            actor_role=actor_role,
            request_id=request_id,
        )

    # ------------------------------------------------------------------
    # Local intelligence snapshots and comparison
    # ------------------------------------------------------------------
    def list_intelligence_snapshots(self, *, page: int = 1, page_size: int | None = None) -> dict[str, Any]:
        self._require_enabled()
        size = int(
            page_size or getattr(self._settings, "governance_intelligence_page_size", DEFAULT_PAGE_SIZE)
        )
        size = min(MAX_PAGE_SIZE, max(1, size))
        page_number = max(1, int(page))
        if self._automation is None:
            return {
                "items": [],
                "total": 0,
                "page": page_number,
                "page_size": size,
                "availability": "UNAVAILABLE",
                "message": "Governance automation snapshot storage is not initialized.",
                "assurance": INTELLIGENCE_ASSURANCE,
                "non_claims": list(INTELLIGENCE_NON_CLAIMS),
            }
        items, total = self._automation.list_snapshots(
            snapshot_type=SNAPSHOT_TYPE_INTELLIGENCE_SUMMARY,
            page=page_number,
            page_size=size,
        )
        return {
            "items": [{key: value for key, value in item.items() if key != "payload"} for item in items],
            "total": total,
            "page": page_number,
            "page_size": size,
            "availability": "OK",
            "message": "",
            "assurance": INTELLIGENCE_ASSURANCE,
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }

    def generate_intelligence_snapshot(
        self,
        *,
        idempotency_key: str,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        self._ensure_defaults()
        key = str(idempotency_key or "").strip()
        if not key:
            raise IntelligenceValidationError("idempotency_key is required")
        text = str(reason or "").strip()
        if len(text) < 3:
            raise IntelligenceValidationError("a reason of at least 3 characters is required")
        if self._automation is None:
            raise IntelligenceValidationError("governance automation snapshot storage is not initialized")
        dedup_key = f"intelligence:{SNAPSHOT_TYPE_INTELLIGENCE_SUMMARY}:manual:{key}"
        existing = self._automation.find_snapshot_by_dedup_key(dedup_key)
        if existing is not None:
            return {
                "snapshot": existing,
                "replayed": True,
                "availability": "OK",
                "assurance": INTELLIGENCE_ASSURANCE,
                "non_claims": list(INTELLIGENCE_NON_CLAIMS),
            }
        moment = self._clock()
        model = self._repository.latest_risk_model()
        if model is None:
            raise IntelligenceValidationError("governance risk model is not initialized")
        scored, unavailable_cases, cases_truncated = self._scored_cases(now=moment, model=model)
        risk_counts = {level: 0 for level in RISK_LEVEL_ORDER}
        sla_state_counts: dict[str, dict[str, int]] = {}
        for item in scored:
            risk_counts[item["risk_level"]] = risk_counts.get(item["risk_level"], 0) + 1
            for target_key, context in (item.get("sla_context") or {}).items():
                state_name = str((context or {}).get("state") or "UNKNOWN")
                sla_state_counts.setdefault(str(target_key), {}).setdefault(state_name, 0)
                sla_state_counts[str(target_key)][state_name] += 1
        recommendation_counts = self._repository.recommendation_counts()
        try:
            coverage = self._governance_repository.historical_coverage()
        except Exception:  # noqa: BLE001 - snapshot records coverage as unavailable
            coverage = {}
        automation_payload: dict[str, Any] = {"availability": "UNAVAILABLE"}
        try:
            if self._automation is not None:
                automation_payload = {
                    "availability": "OK",
                    "queue": self._automation.queue_counts(),
                    "job_count": self._automation.count_jobs(),
                    "snapshot_count": self._automation.count_snapshots(),
                    "stale_jobs": self._automation.stale_job_count(now=moment),
                }
        except Exception:  # noqa: BLE001
            automation_payload = {"availability": "UNAVAILABLE"}
        payload = {
            "snapshot_type": SNAPSHOT_TYPE_INTELLIGENCE_SUMMARY,
            "as_of": _iso(moment),
            "model": {
                "model_id": model.get("model_id"),
                "version": model.get("version"),
                "thresholds": model.get("thresholds"),
                "factor_points": model.get("factor_points"),
            },
            "risk": {
                "total_cases": len(scored),
                "unavailable_case_count": unavailable_cases,
                "truncated": cases_truncated,
                "risk_level_counts": risk_counts,
                "sla_state_counts": sla_state_counts,
            },
            "recommendations": {
                "counts": recommendation_counts,
                "rules": list(RULE_IDS),
            },
            "automation": automation_payload,
            "coverage": coverage,
            "assurance": INTELLIGENCE_ASSURANCE,
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }
        snapshot, created = self._automation.create_snapshot(
            snapshot_type=SNAPSHOT_TYPE_INTELLIGENCE_SUMMARY,
            as_of=moment,
            generated_by=str(actor_id or "SYSTEM"),
            dedup_key=dedup_key,
            payload=payload,
            row_count=len(scored),
            trigger="MANUAL",
            now=moment,
        )
        if created:
            self._audit(
                event_type=GovernanceAuditEventType.INTELLIGENCE_SNAPSHOT_GENERATED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="GOVERNANCE_INTELLIGENCE_SNAPSHOT",
                target_id=str(snapshot.get("snapshot_id")),
                reason=text,
                request_id=request_id,
                event_key=f"intelligence:snapshot:{snapshot.get('snapshot_id')}:generated",
                metadata={
                    "snapshot_type": SNAPSHOT_TYPE_INTELLIGENCE_SUMMARY,
                    "payload_digest": snapshot.get("payload_digest"),
                    "row_count": len(scored),
                },
            )
        return {
            "snapshot": snapshot,
            "replayed": not created,
            "availability": "OK",
            "assurance": INTELLIGENCE_ASSURANCE,
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }

    def get_intelligence_snapshot(self, snapshot_id: str) -> dict[str, Any]:
        self._require_enabled()
        snapshot = self._automation.get_snapshot(snapshot_id) if self._automation is not None else None
        if snapshot is None or snapshot.get("snapshot_type") != SNAPSHOT_TYPE_INTELLIGENCE_SUMMARY:
            raise SnapshotNotFoundError(snapshot_id)
        return {
            "snapshot": snapshot,
            "integrity": {
                "state": "VALID" if snapshot.get("digest_valid") else "INTEGRITY_FAILED",
                "digest_valid": bool(snapshot.get("digest_valid")),
                "message": (
                    "The stored payload matches its SHA-256 self-digest."
                    if snapshot.get("digest_valid")
                    else (
                        "The stored payload does not match its self-digest; "
                        "the snapshot is preserved for investigation."
                    )
                ),
            },
            "assurance": INTELLIGENCE_ASSURANCE,
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }

    def compare_intelligence_snapshots(
        self,
        snapshot_id: str,
        other_snapshot_id: str,
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._require_enabled()
        if self._automation is None:
            raise SnapshotNotFoundError(snapshot_id)
        left = self._automation.get_snapshot(snapshot_id)
        if left is None:
            raise SnapshotNotFoundError(snapshot_id)
        right = self._automation.get_snapshot(other_snapshot_id)
        if right is None:
            raise SnapshotNotFoundError(other_snapshot_id)
        tampered = [
            str(snapshot.get("snapshot_id"))
            for snapshot in (left, right)
            if snapshot.get("digest_valid") is not True
        ]
        base = {
            "snapshot_id": snapshot_id,
            "other_snapshot_id": other_snapshot_id,
            "snapshot_type": left.get("snapshot_type"),
            "other_snapshot_type": right.get("snapshot_type"),
            "schema_version": left.get("schema_version"),
            "other_schema_version": right.get("schema_version"),
            "assurance": INTELLIGENCE_ASSURANCE,
            "non_claims": list(INTELLIGENCE_NON_CLAIMS),
        }
        if tampered:
            record_governance_intelligence_snapshot_comparison("INTEGRITY_FAILED")
            self._audit(
                event_type=GovernanceAuditEventType.INTELLIGENCE_SNAPSHOT_COMPARED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="GOVERNANCE_INTELLIGENCE_SNAPSHOT",
                target_id=f"{snapshot_id}:{other_snapshot_id}",
                reason="Snapshot comparison rejected because a self-digest is invalid.",
                request_id=request_id,
                event_key=f"intelligence:snapshot:compare:{snapshot_id}:{other_snapshot_id}",
                metadata={"status": "INTEGRITY_FAILED", "tampered_snapshot_ids": tampered},
            )
            return {
                **base,
                "status": "INTEGRITY_FAILED",
                "comparable": False,
                "tampered_snapshot_ids": tampered,
                "diff": None,
                "changes": [],
                "summary": {"added": 0, "removed": 0, "changed": 0, "total": 0},
                "truncated": False,
                "message": (
                    "At least one snapshot payload does not match its stored self-digest. "
                    "No diff is produced and both snapshots are preserved for investigation."
                ),
            }
        if left.get("snapshot_type") != right.get("snapshot_type") or int(
            left.get("schema_version") or 0
        ) != int(right.get("schema_version") or 0):
            record_governance_intelligence_snapshot_comparison("INCOMPATIBLE")
            self._audit(
                event_type=GovernanceAuditEventType.INTELLIGENCE_SNAPSHOT_COMPARED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="GOVERNANCE_INTELLIGENCE_SNAPSHOT",
                target_id=f"{snapshot_id}:{other_snapshot_id}",
                reason="Snapshot comparison rejected because type or schema differs.",
                request_id=request_id,
                event_key=f"intelligence:snapshot:compare:{snapshot_id}:{other_snapshot_id}",
                metadata={"status": "INCOMPATIBLE"},
            )
            return {
                **base,
                "status": "INCOMPATIBLE",
                "comparable": False,
                "tampered_snapshot_ids": [],
                "diff": None,
                "changes": [],
                "summary": {"added": 0, "removed": 0, "changed": 0, "total": 0},
                "truncated": False,
                "message": ("Snapshots have a different type or schema version and cannot be compared."),
            }
        changes: list[dict[str, Any]] = []
        truncated = _diff_payload(
            left.get("payload") or {},
            right.get("payload") or {},
            changes=changes,
            limit=MAX_SNAPSHOT_DIFF_ITEMS,
        )
        summary = {
            "added": sum(1 for change in changes if change["change"] == "ADDED"),
            "removed": sum(1 for change in changes if change["change"] == "REMOVED"),
            "changed": sum(1 for change in changes if change["change"] == "CHANGED"),
            "total": len(changes),
        }
        record_governance_intelligence_snapshot_comparison("COMPARED")
        self._audit(
            event_type=GovernanceAuditEventType.INTELLIGENCE_SNAPSHOT_COMPARED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="GOVERNANCE_INTELLIGENCE_SNAPSHOT",
            target_id=f"{snapshot_id}:{other_snapshot_id}",
            reason="Local snapshot comparison completed.",
            request_id=request_id,
            event_key=f"intelligence:snapshot:compare:{snapshot_id}:{other_snapshot_id}",
            metadata={
                "status": "COMPARED",
                "changed_paths": summary["total"],
                "truncated": truncated,
            },
        )
        return {
            **base,
            "status": "COMPARED",
            "comparable": True,
            "tampered_snapshot_ids": [],
            "diff": {"changes": changes, "truncated": truncated},
            "changes": changes,
            "summary": summary,
            "truncated": truncated,
            "message": (
                "Local aggregate comparison only. This is not regulatory certification and "
                "the snapshots are not externally anchored."
            ),
        }

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
    def _audit(self, **kwargs: Any) -> None:
        try:
            self._governance.record_access(**kwargs)
        except Exception:  # noqa: BLE001 - audit must never break the request path
            logger.warning("governance intelligence audit write failed", exc_info=True)


__all__ = ["GovernanceIntelligenceService"]
