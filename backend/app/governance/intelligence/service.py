"""V37 governance intelligence application service.

Coordinates deterministic risk scoring, versioned operational SLAs, bounded
analytics, advisory recommendations, and local snapshot comparison on top of
the existing V35 governance, V36 automation, V34 forensic, V10 incident, and
V15 notification services. It never approves or releases a legal hold, decides
a disposition, modifies evidence, deletes a record, or makes an automatic
governance decision.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from backend.app.core.logging import get_logger
from backend.app.core.metrics import (
    record_governance_intelligence_score,
    set_governance_intelligence_sla_counts,
)
from backend.app.domain.common import utcnow
from backend.app.governance.constants import (
    BLOCKING_HOLD_STATUSES,
    GovernanceAuditEventType,
)
from backend.app.governance.intelligence.constants import (
    DEFAULT_PAGE_SIZE,
    DEFAULT_RISK_CASES,
    FACTOR_LABELS,
    INTELLIGENCE_ASSURANCE,
    INTELLIGENCE_LIMITATIONS,
    INTELLIGENCE_NON_CLAIMS,
    MAX_PAGE_SIZE,
    RISK_LEVEL_ORDER,
    SLA_KIND_OPERATIONAL,
    SLA_NON_CLAIM,
    SLA_TARGET_KEYS,
    SlaState,
)
from backend.app.governance.intelligence.errors import (
    IntelligenceDisabledError,
    IntelligenceValidationError,
    RiskCaseNotFoundError,
    SlaTargetNotFoundError,
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
        return result

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
                    now=moment,
                    model=model,
                    evaluations=evaluations,
                    sla_versions=sla_versions,
                    resolve_retention=False,
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
            if risk_level and result["risk_level"] != str(risk_level).upper():
                continue
            scored.append(result)
        scored.sort(key=lambda item: (-int(item["score"]), item["case_id"]))
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
    # Audit
    # ------------------------------------------------------------------
    def _audit(self, **kwargs: Any) -> None:
        try:
            self._governance.record_access(**kwargs)
        except Exception:  # noqa: BLE001 - audit must never break the request path
            logger.warning("governance intelligence audit write failed", exc_info=True)


__all__ = ["GovernanceIntelligenceService"]
