"""Deterministic, explainable governance risk scoring (V37).

The scoring function is pure: it consumes already-fetched governance and
forensic records and never queries a database, calls an external service, or
mutates state. Every factor carries a reason, source references, and an honest
data status. Correlated factors are suppressed rather than double-counted.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from backend.app.core.redaction import redact_text
from backend.app.governance.intelligence.constants import (
    CORRELATION_GROUPS,
    DEFAULT_RISK_THRESHOLDS,
    DISPOSITION_BLOCKED_INTEGRITY_CODES,
    FACTOR_CORRELATION_GROUP,
    FACTOR_LABELS,
    FACTOR_ORDER,
    MAX_TOTAL_SCORE,
    DataCompleteness,
    FactorDataStatus,
    RiskFactor,
    risk_level_for,
    validate_factor_points,
    validate_thresholds,
)

_EVENT_TERMINAL_STATUSES = frozenset({"CLOSED", "RESOLVED"})
_INTEGRITY_ORDER = (
    RiskFactor.CONFIRMED_INTEGRITY_FAILURE.value,
    RiskFactor.INTEGRITY_VERIFICATION_PARTIAL.value,
    RiskFactor.INTEGRITY_VERIFICATION_UNAVAILABLE.value,
    RiskFactor.INTEGRITY_VERIFICATION_NOT_RUN.value,
    RiskFactor.INTEGRITY_VERIFICATION_SIMULATED.value,
)


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


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _text(value: Any, limit: int = 256) -> str:
    return redact_text(str(value or "")).strip()[:limit]


def _points(model: Mapping[str, Any], factor: str) -> int:
    points = validate_factor_points(model.get("factor_points"))
    return int(points.get(factor, 0))


def _thresholds(model: Mapping[str, Any]) -> dict[str, dict[str, int]]:
    try:
        return validate_thresholds(model.get("thresholds"))
    except ValueError:
        return {level: dict(bounds) for level, bounds in DEFAULT_RISK_THRESHOLDS.items()}


def _is_simulated(verification: Mapping[str, Any] | None) -> bool:
    if not verification:
        return False
    metadata = verification.get("metadata")
    if isinstance(metadata, Mapping):
        if bool(metadata.get("simulated") or metadata.get("simulation") or metadata.get("local_test")):
            return True
        source = str(metadata.get("source") or "").upper()
        if any(marker in source for marker in ("SIMULATED", "SIMULATION", "LOCAL_TEST")):
            return True
    report = verification.get("report")
    if isinstance(report, Mapping):
        if bool(report.get("simulated")):
            return True
        source = str(report.get("source") or "").upper()
        if any(marker in source for marker in ("SIMULATED", "SIMULATION", "LOCAL_TEST")):
            return True
    return False


def _factor(
    factor: str,
    *,
    points: int,
    reason: str,
    source_refs: Sequence[str],
    data_status: str,
) -> dict[str, Any]:
    return {
        "factor_id": factor,
        "label": FACTOR_LABELS[factor],
        "points": max(0, min(MAX_TOTAL_SCORE, int(points))),
        "reason": _text(reason, 512),
        "source_refs": sorted({_text(ref, 160) for ref in source_refs if str(ref).strip()}),
        "data_status": data_status,
        "correlation_group": FACTOR_CORRELATION_GROUP.get(factor),
        "suppressed": False,
        "suppressed_by": None,
        "suppression_reason": None,
    }


def _missing(source: str, status: str, message: str) -> dict[str, str]:
    return {"source": source, "status": status, "message": _text(message, 512)}


def _integrity_factor(
    verification: Mapping[str, Any] | None,
    verification_error: str | None,
    *,
    model: Mapping[str, Any],
    missing: list[dict[str, str]],
) -> dict[str, Any] | None:
    if verification_error:
        missing.append(
            _missing(
                "forensic_verification",
                FactorDataStatus.UNAVAILABLE.value,
                "The latest integrity verification could not be read; no failure or PASS is claimed.",
            )
        )
        return _factor(
            RiskFactor.INTEGRITY_VERIFICATION_UNAVAILABLE.value,
            points=_points(model, RiskFactor.INTEGRITY_VERIFICATION_UNAVAILABLE.value),
            reason="Integrity verification is unavailable; this is not a confirmed failure.",
            source_refs=("forensic_verification:unavailable",),
            data_status=FactorDataStatus.UNAVAILABLE.value,
        )
    if verification is None:
        missing.append(
            _missing(
                "forensic_verification",
                FactorDataStatus.NOT_RUN.value,
                "No integrity verification has been run; this is not a PASS or a confirmed failure.",
            )
        )
        return _factor(
            RiskFactor.INTEGRITY_VERIFICATION_NOT_RUN.value,
            points=_points(model, RiskFactor.INTEGRITY_VERIFICATION_NOT_RUN.value),
            reason="Integrity verification has not run; no failure or PASS is claimed.",
            source_refs=("forensic_verification:not_run",),
            data_status=FactorDataStatus.NOT_RUN.value,
        )

    verification_id = str(verification.get("verification_id") or "unknown")
    source_ref = f"forensic_verification:{verification_id}"
    if _is_simulated(verification):
        missing.append(
            _missing(
                "forensic_verification",
                FactorDataStatus.SIMULATED.value,
                "The latest verification is simulated or local-test data and is not a confirmed failure.",
            )
        )
        return _factor(
            RiskFactor.INTEGRITY_VERIFICATION_SIMULATED.value,
            points=_points(model, RiskFactor.INTEGRITY_VERIFICATION_SIMULATED.value),
            reason="Verification is simulated or local-test data; it is not treated as a failure.",
            source_refs=(source_ref,),
            data_status=FactorDataStatus.SIMULATED.value,
        )

    outcome = str(verification.get("outcome") or "NOT_RUN").upper()
    if outcome == "FAIL":
        return _factor(
            RiskFactor.CONFIRMED_INTEGRITY_FAILURE.value,
            points=_points(model, RiskFactor.CONFIRMED_INTEGRITY_FAILURE.value),
            reason="The latest forensic verification outcome is FAIL.",
            source_refs=(source_ref,),
            data_status=FactorDataStatus.CONFIRMED.value,
        )
    if outcome == "PARTIAL":
        missing.append(
            _missing(
                "forensic_verification",
                FactorDataStatus.INCOMPLETE.value,
                "The latest verification is incomplete; it is not a confirmed failure or a PASS.",
            )
        )
        return _factor(
            RiskFactor.INTEGRITY_VERIFICATION_PARTIAL.value,
            points=_points(model, RiskFactor.INTEGRITY_VERIFICATION_PARTIAL.value),
            reason="The latest forensic verification is incomplete, not a confirmed failure.",
            source_refs=(source_ref,),
            data_status=FactorDataStatus.INCOMPLETE.value,
        )
    if outcome == "UNAVAILABLE":
        missing.append(
            _missing(
                "forensic_verification",
                FactorDataStatus.UNAVAILABLE.value,
                "The latest verification is unavailable; no failure or PASS is claimed.",
            )
        )
        return _factor(
            RiskFactor.INTEGRITY_VERIFICATION_UNAVAILABLE.value,
            points=_points(model, RiskFactor.INTEGRITY_VERIFICATION_UNAVAILABLE.value),
            reason="The latest verification is unavailable; this is not a confirmed failure.",
            source_refs=(source_ref,),
            data_status=FactorDataStatus.UNAVAILABLE.value,
        )
    if outcome == "NOT_RUN":
        missing.append(
            _missing(
                "forensic_verification",
                FactorDataStatus.NOT_RUN.value,
                "The latest verification has not run; no failure or PASS is claimed.",
            )
        )
        return _factor(
            RiskFactor.INTEGRITY_VERIFICATION_NOT_RUN.value,
            points=_points(model, RiskFactor.INTEGRITY_VERIFICATION_NOT_RUN.value),
            reason="The latest verification has not run; no failure or PASS is claimed.",
            source_refs=(source_ref,),
            data_status=FactorDataStatus.NOT_RUN.value,
        )
    missing.append(
        _missing(
            "forensic_verification",
            FactorDataStatus.UNAVAILABLE.value,
            "The verification outcome is not recognized; no failure or PASS is claimed.",
        )
    )
    return _factor(
        RiskFactor.INTEGRITY_VERIFICATION_UNAVAILABLE.value,
        points=_points(model, RiskFactor.INTEGRITY_VERIFICATION_UNAVAILABLE.value),
        reason="The verification outcome is not recognized; no failure or PASS is claimed.",
        source_refs=(source_ref,),
        data_status=FactorDataStatus.UNAVAILABLE.value,
    )


def score_case(
    *,
    case_id: str,
    case: Mapping[str, Any],
    evaluation: Mapping[str, Any] | None,
    verification: Mapping[str, Any] | None,
    verification_error: str | None,
    holds: Sequence[Mapping[str, Any]],
    disposition: Mapping[str, Any] | None,
    export_approvals: Sequence[Mapping[str, Any]],
    policy: Mapping[str, Any] | None,
    incident: Mapping[str, Any] | None,
    incident_error: str | None,
    sla_context: Mapping[str, Mapping[str, Any]],
    model: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Return one explainable case risk score."""
    moment = now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)
    candidates: list[dict[str, Any]] = []
    missing: list[dict[str, str]] = []

    integrity = _integrity_factor(verification, verification_error, model=model, missing=missing)
    if integrity is not None:
        candidates.append(integrity)

    if evaluation is None:
        missing.append(
            _missing(
                "governance_retention_evaluation",
                FactorDataStatus.UNAVAILABLE.value,
                "No retention evaluation exists for this case; retention risk is unassessed.",
            )
        )
    else:
        evaluation_id = str(evaluation.get("evaluation_id") or "unknown")
        next_review = _as_utc(evaluation.get("next_review_at"))
        state = str(evaluation.get("governance_state") or "").upper()
        if state == "REVIEW_DUE":
            if next_review is not None and next_review < moment:
                overdue_days = (moment - next_review).total_seconds() / 86400.0
                base = _points(model, RiskFactor.RETENTION_REVIEW_OVERDUE.value)
                points = base if overdue_days > 7 else max(1, base // 2)
                candidates.append(
                    _factor(
                        RiskFactor.RETENTION_REVIEW_OVERDUE.value,
                        points=points,
                        reason=f"Retention review is overdue by {int(overdue_days)} day(s).",
                        source_refs=(f"governance_retention_evaluation:{evaluation_id}",),
                        data_status=FactorDataStatus.CONFIRMED.value,
                    )
                )
            elif next_review is None:
                candidates.append(
                    _factor(
                        RiskFactor.RETENTION_REVIEW_OVERDUE.value,
                        points=_points(model, RiskFactor.RETENTION_REVIEW_OVERDUE.value),
                        reason="Retention state is REVIEW_DUE; the due timestamp is unavailable.",
                        source_refs=(f"governance_retention_evaluation:{evaluation_id}",),
                        data_status=FactorDataStatus.CONFIRMED.value,
                    )
                )

    if disposition is not None:
        disposition_id = str(disposition.get("disposition_id") or "unknown")
        disposition_status = str(disposition.get("status") or "").upper()
        if disposition_status in {"REVIEW_REQUIRED", "APPROVAL_PENDING"}:
            sla = sla_context.get("DISPOSITION_REVIEW") or {}
            if str(sla.get("state") or "").upper() == "BREACHED":
                candidates.append(
                    _factor(
                        RiskFactor.DISPOSITION_REVIEW_OVERDUE.value,
                        points=_points(model, RiskFactor.DISPOSITION_REVIEW_OVERDUE.value),
                        reason=(
                            "Disposition review is past its operational SLA "
                            f"(target version {sla.get('target_version') or 'unknown'})."
                        ),
                        source_refs=(f"governance_disposition:{disposition_id}",),
                        data_status=FactorDataStatus.CONFIRMED.value,
                    )
                )
        elif disposition_status == "BLOCKED":
            codes = {str(code).upper() for code in disposition.get("blocked_reason_codes") or []}
            candidates.append(
                _factor(
                    RiskFactor.DISPOSITION_BLOCKED.value,
                    points=_points(model, RiskFactor.DISPOSITION_BLOCKED.value),
                    reason=(
                        "Disposition review is blocked" + (f" ({', '.join(sorted(codes))})" if codes else ".")
                    ),
                    source_refs=(f"governance_disposition:{disposition_id}",),
                    data_status=FactorDataStatus.CONFIRMED.value,
                )
            )

    active_holds = [
        hold for hold in holds if str(hold.get("status") or "").upper() in {"ACTIVE", "PENDING_APPROVAL"}
    ]
    if active_holds:
        hold_sla = sla_context.get("LEGAL_HOLD_REVIEW") or {}
        if str(hold_sla.get("state") or "").upper() == "BREACHED":
            candidates.append(
                _factor(
                    RiskFactor.LEGAL_HOLD_REVIEW_OVERDUE.value,
                    points=_points(model, RiskFactor.LEGAL_HOLD_REVIEW_OVERDUE.value),
                    reason=(
                        f"{len(active_holds)} legal hold(s) are past the operational review SLA "
                        f"(target version {hold_sla.get('target_version') or 'unknown'})."
                    ),
                    source_refs=tuple(
                        f"governance_legal_hold:{hold.get('hold_id')}" for hold in active_holds
                    ),
                    data_status=FactorDataStatus.CONFIRMED.value,
                )
            )

    expired_refs: list[str] = []
    expiring_refs: list[str] = []
    for approval in export_approvals:
        approval_id = str(approval.get("approval_id") or "unknown")
        status = str(approval.get("status") or "").upper()
        expires_at = _as_utc(approval.get("expires_at"))
        if status == "EXPIRED" or (expires_at is not None and expires_at < moment):
            expired_refs.append(f"governance_export_approval:{approval_id}")
        elif expires_at is not None and expires_at <= moment + timedelta(days=7):
            expiring_refs.append(f"governance_export_approval:{approval_id}")
    if expired_refs:
        candidates.append(
            _factor(
                RiskFactor.EXPORT_APPROVAL_EXPIRED.value,
                points=_points(model, RiskFactor.EXPORT_APPROVAL_EXPIRED.value),
                reason=f"{len(expired_refs)} export approval(s) are expired.",
                source_refs=tuple(expired_refs),
                data_status=FactorDataStatus.CONFIRMED.value,
            )
        )
    elif expiring_refs:
        candidates.append(
            _factor(
                RiskFactor.EXPORT_APPROVAL_EXPIRING.value,
                points=_points(model, RiskFactor.EXPORT_APPROVAL_EXPIRING.value),
                reason=f"{len(expiring_refs)} export approval(s) expire within 7 days.",
                source_refs=tuple(expiring_refs),
                data_status=FactorDataStatus.CONFIRMED.value,
            )
        )

    if policy is None:
        missing.append(
            _missing(
                "governance_policy",
                FactorDataStatus.UNAVAILABLE.value,
                "No enabled governance policy applies to this case; policy risk is unassessed.",
            )
        )
        candidates.append(
            _factor(
                RiskFactor.POLICY_MISSING_OR_DISABLED.value,
                points=_points(model, RiskFactor.POLICY_MISSING_OR_DISABLED.value),
                reason="No enabled governance policy applies to this case.",
                source_refs=("governance_policy:none",),
                data_status=FactorDataStatus.CONFIRMED.value,
            )
        )
    else:
        policy_id = _text(policy.get("policy_id") or "unknown", 64)
        policy_version = policy.get("version") or policy.get("policy_version") or "unknown"
        if str(policy.get("state") or "").upper() != "ENABLED":
            candidates.append(
                _factor(
                    RiskFactor.POLICY_MISSING_OR_DISABLED.value,
                    points=_points(model, RiskFactor.POLICY_MISSING_OR_DISABLED.value),
                    reason="The applicable governance policy is not enabled.",
                    source_refs=(f"governance_policy:{policy_id}@{policy_version}",),
                    data_status=FactorDataStatus.CONFIRMED.value,
                )
            )

    if incident_error:
        missing.append(
            _missing(
                "incident",
                FactorDataStatus.UNAVAILABLE.value,
                "The linked incident could not be read; incident context is unassessed.",
            )
        )
    elif incident is not None:
        incident_status = str(incident.get("status") or "").upper()
        if incident_status not in _EVENT_TERMINAL_STATUSES:
            candidates.append(
                _factor(
                    RiskFactor.LINKED_OPEN_INCIDENT.value,
                    points=_points(model, RiskFactor.LINKED_OPEN_INCIDENT.value),
                    reason=f"The linked security incident is {incident_status or 'open'}.",
                    source_refs=(f"incident:{incident.get('incident_id') or incident.get('id')}",),
                    data_status=FactorDataStatus.CONFIRMED.value,
                )
            )

    severity = str(case.get("severity") or "").upper()
    if severity == "CRITICAL":
        candidates.append(
            _factor(
                RiskFactor.CASE_SEVERITY_CRITICAL.value,
                points=_points(model, RiskFactor.CASE_SEVERITY_CRITICAL.value),
                reason="The forensic case severity is CRITICAL.",
                source_refs=(f"forensic_case:{case_id}",),
                data_status=FactorDataStatus.CONFIRMED.value,
            )
        )
    elif severity == "HIGH":
        candidates.append(
            _factor(
                RiskFactor.CASE_SEVERITY_HIGH.value,
                points=_points(model, RiskFactor.CASE_SEVERITY_HIGH.value),
                reason="The forensic case severity is HIGH.",
                source_refs=(f"forensic_case:{case_id}",),
                data_status=FactorDataStatus.CONFIRMED.value,
            )
        )
    elif not severity:
        missing.append(
            _missing(
                "forensic_case",
                FactorDataStatus.INCOMPLETE.value,
                "Case severity is unavailable; severity risk is unassessed.",
            )
        )

    # Correlation suppression: keep the highest-points factor per group.
    by_id = {factor["factor_id"]: factor for factor in candidates}
    for group, members in CORRELATION_GROUPS.items():
        present = [by_id[item] for item in members if item in by_id]
        if len(present) <= 1:
            continue
        winner = sorted(
            present,
            key=lambda item: (-int(item["points"]), FACTOR_ORDER.index(item["factor_id"])),
        )[0]
        for item in present:
            if item is winner:
                continue
            item["suppressed"] = True
            item["suppressed_by"] = winner["factor_id"]
            item["suppression_reason"] = f"Correlated with {winner['factor_id']}; not counted twice."

    # A blocked disposition caused by an integrity problem is already covered
    # by the integrity factor and must not add a second penalty.
    blocked = by_id.get(RiskFactor.DISPOSITION_BLOCKED.value)
    integrity_selected = [
        by_id[item]
        for item in _INTEGRITY_ORDER
        if item in by_id
        and not by_id[item]["suppressed"]
        and by_id[item]["data_status"] in {"CONFIRMED", "INCOMPLETE"}
    ]
    if blocked is not None and integrity_selected and not blocked["suppressed"]:
        codes = {str(code).upper() for code in (disposition or {}).get("blocked_reason_codes") or []}
        if codes & DISPOSITION_BLOCKED_INTEGRITY_CODES:
            winner = integrity_selected[0]
            blocked["suppressed"] = True
            blocked["suppressed_by"] = winner["factor_id"]
            blocked["suppression_reason"] = (
                f"Blocked disposition is caused by {winner['factor_id']}; not counted twice."
            )

    ordered = sorted(
        candidates,
        key=lambda item: (
            item["suppressed"],
            FACTOR_ORDER.index(item["factor_id"]),
        ),
    )
    score = min(
        MAX_TOTAL_SCORE,
        sum(int(item["points"]) for item in ordered if not item["suppressed"]),
    )
    thresholds = _thresholds(model)
    completeness = DataCompleteness.COMPLETE.value if not missing else DataCompleteness.PARTIAL.value
    score_available = evaluation is not None or verification is not None or bool(active_holds)
    if not score_available:
        completeness = DataCompleteness.UNAVAILABLE.value

    policy_snapshot = evaluation.get("policy_snapshot") if evaluation else None
    policy_context: dict[str, Any] = {
        "policy_id": None,
        "policy_version": None,
        "state": "UNAVAILABLE",
        "case_type": case.get("case_type"),
        "evidence_category": None,
    }
    if isinstance(policy_snapshot, Mapping) and policy_snapshot:
        policy_context.update(
            {
                "policy_id": policy_snapshot.get("policy_id"),
                "policy_version": policy_snapshot.get("version"),
                "state": policy_snapshot.get("state"),
                "case_type": policy_snapshot.get("case_type") or case.get("case_type"),
                "evidence_category": policy_snapshot.get("evidence_category"),
            }
        )
    if policy is not None:
        policy_context.update(
            {
                "policy_id": policy.get("policy_id"),
                "policy_version": policy.get("version") or policy.get("policy_version"),
                "state": policy.get("state"),
                "case_type": policy.get("case_type") or case.get("case_type"),
                "evidence_category": policy.get("evidence_category"),
            }
        )

    return {
        "case_id": case_id,
        "case_number": case.get("case_number"),
        "case_status": case.get("status"),
        "case_severity": case.get("severity"),
        "score": score,
        "risk_level": risk_level_for(score, thresholds),
        "score_available": score_available,
        "data_completeness": completeness,
        "model_id": model.get("model_id"),
        "model_version": model.get("version"),
        "policy_context": policy_context,
        "factors": ordered,
        "missing_data": sorted(missing, key=lambda item: (item["source"], item["status"])),
        "calculated_at": _iso(moment),
    }


__all__ = ["score_case"]
