"""Deterministic V38 executive health model (``EXEC_HEALTH_V1``).

The model is intentionally small and explainable:

* Every configured signal names one executive KPI, one comparison operator, one
  threshold, and one status.
* A signal is evaluated only when its KPI is applicable, available, and has a
  numeric value. An unavailable KPI is a coverage gap, not a zero and not a
  passing signal.
* The overall status is the highest triggered severity. If no signal triggers,
  complete coverage yields ``HEALTHY`` and partial coverage yields
  ``ATTENTION_REQUIRED``. If no applicable KPI is available at all, the result
  is ``UNAVAILABLE``.
* Nothing is averaged. The coverage block always states which KPIs were
  unavailable or partial.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from backend.app.governance.executive.constants import (
    COVERAGE_COMPLETE,
    COVERAGE_PARTIAL,
    COVERAGE_UNAVAILABLE,
    EXECUTIVE_ASSURANCE,
    EXECUTIVE_LIMITATIONS,
    EXECUTIVE_NON_CLAIMS,
    HEALTH_ATTENTION_REQUIRED,
    HEALTH_HEALTHY,
    HEALTH_MODEL_VERSION,
    HEALTH_SIGNAL_RULES,
    HEALTH_STATUS_RANK,
    HEALTH_UNAVAILABLE,
    KPI_AVAILABLE,
    KPI_PARTIAL,
    KPI_UNAVAILABLE,
)

_OPERATORS = {
    "gte": lambda observed, threshold: observed >= threshold,
    "gt": lambda observed, threshold: observed > threshold,
    "lte": lambda observed, threshold: observed <= threshold,
    "lt": lambda observed, threshold: observed < threshold,
    "eq": lambda observed, threshold: observed == threshold,
    "ne": lambda observed, threshold: observed != threshold,
}


def _iso(value: datetime) -> str:
    moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _kpi_map(kpis: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    return {str(kpi.get("kpi_id")): kpi for kpi in kpis}


def _coverage(kpis: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    applicable = [kpi for kpi in kpis if bool(kpi.get("applicable", True))]
    available = [
        kpi
        for kpi in applicable
        if str(kpi.get("availability")) == KPI_AVAILABLE
        and str((kpi.get("completeness") or {}).get("status")) != "UNAVAILABLE"
    ]
    partial = [
        kpi
        for kpi in applicable
        if str(kpi.get("availability")) == KPI_PARTIAL
        or str((kpi.get("completeness") or {}).get("status")) == "PARTIAL"
    ]
    unavailable = [kpi for kpi in applicable if str(kpi.get("availability")) == KPI_UNAVAILABLE]
    partial_ids = sorted(
        {str(kpi.get("kpi_id")) for kpi in partial if str(kpi.get("availability")) != KPI_UNAVAILABLE}
    )
    unavailable_ids = sorted({str(kpi.get("kpi_id")) for kpi in unavailable})
    if not applicable or not available:
        status = COVERAGE_UNAVAILABLE
        message = (
            "No applicable executive KPI source could be read; the health status is "
            "UNAVAILABLE rather than a fabricated healthy value."
        )
    elif partial_ids or unavailable_ids:
        status = COVERAGE_PARTIAL
        message = (
            "At least one applicable executive KPI source is partial or unavailable; "
            "the health status is explicitly qualified."
        )
    else:
        status = COVERAGE_COMPLETE
        message = "Every applicable executive KPI source was available and complete."
    return {
        "status": status,
        "message": message,
        "applicable_kpis": len(applicable),
        "available_kpis": len(available),
        "partial_kpis": len(partial_ids),
        "unavailable_kpis": len(unavailable_ids),
        "partial_kpi_ids": partial_ids,
        "unavailable_kpi_ids": unavailable_ids,
    }


def _evaluate_signal(rule: Mapping[str, Any], kpi: Mapping[str, Any] | None) -> dict[str, Any]:
    code = str(rule["code"])
    kpi_id = str(rule["kpi_id"])
    operator = str(rule["operator"])
    threshold = rule["threshold"]
    status = str(rule["status"])
    base = {
        "code": code,
        "label": str(rule.get("label") or code),
        "kpi_id": kpi_id,
        "operator": operator,
        "threshold": threshold,
        "status": status,
        "observed_value": None,
        "evaluated": False,
        "triggered": False,
        "explanation": str(rule.get("explanation") or ""),
        "source_availability": None,
    }
    if kpi is None:
        base["explanation"] = f"KPI {kpi_id} is not present in this calculation."
        return base
    base["source_availability"] = kpi.get("availability")
    if not bool(kpi.get("applicable", True)):
        base["explanation"] = (
            f"KPI {kpi_id} is not applicable for this calculation; the signal is not evaluated."
        )
        return base
    availability = str(kpi.get("availability"))
    if availability == KPI_UNAVAILABLE:
        base["explanation"] = (
            f"KPI {kpi_id} is unavailable; the signal is not evaluated and is reported as "
            "a coverage gap, never as a passing zero."
        )
        return base
    value = kpi.get("value")
    if value is None or isinstance(value, bool):
        base["explanation"] = f"KPI {kpi_id} has no numeric value; the signal is not evaluated."
        return base
    try:
        observed = float(value)
        limit = float(threshold)
    except (TypeError, ValueError):
        base["explanation"] = f"KPI {kpi_id} value is not numeric; the signal is not evaluated."
        return base
    comparator = _OPERATORS.get(operator)
    if comparator is None:
        base["explanation"] = f"Unknown signal operator {operator}; the signal is not evaluated."
        return base
    base["observed_value"] = observed
    base["evaluated"] = True
    base["triggered"] = bool(comparator(observed, limit))
    return base


def evaluate_health(
    kpis: Sequence[Mapping[str, Any]],
    *,
    calculated_at: datetime,
    model_version: str = HEALTH_MODEL_VERSION,
) -> dict[str, Any]:
    """Evaluate the deterministic health model over already-computed KPIs."""
    indexed = _kpi_map(kpis)
    signals = [_evaluate_signal(rule, indexed.get(str(rule["kpi_id"]))) for rule in HEALTH_SIGNAL_RULES]
    coverage = _coverage(kpis)
    triggered = [signal for signal in signals if signal["triggered"]]
    highest_rank = max(
        (HEALTH_STATUS_RANK.get(str(signal["status"]), 0) for signal in triggered),
        default=0,
    )
    if coverage["status"] == COVERAGE_UNAVAILABLE:
        overall = HEALTH_UNAVAILABLE
        status_reason = coverage["message"]
    elif highest_rank > 0:
        overall = next(status for status, rank in HEALTH_STATUS_RANK.items() if rank == highest_rank)
        codes = ", ".join(str(signal["code"]) for signal in triggered if signal["status"] == overall)
        status_reason = f"Highest triggered severity is {overall} from: {codes}."
        if coverage["status"] == COVERAGE_PARTIAL:
            status_reason += " Source coverage is partial."
    elif coverage["status"] == COVERAGE_COMPLETE:
        overall = HEALTH_HEALTHY
        status_reason = "No configured signal triggered and source coverage is complete."
    else:
        overall = HEALTH_ATTENTION_REQUIRED
        status_reason = (
            "No configured signal triggered, but source coverage is partial; a healthy "
            "status cannot be asserted."
        )

    return {
        "overall_status": overall,
        "status_reason": status_reason,
        "model_version": model_version,
        "calculated_at": _iso(calculated_at),
        "coverage": coverage,
        "signals": signals,
        "triggered_signals": [str(signal["code"]) for signal in triggered],
        "evaluated_signal_count": sum(1 for signal in signals if signal["evaluated"]),
        "triggered_signal_count": len(triggered),
        "thresholds": {
            "model_version": model_version,
            "fixed": True,
            "signals": [
                {
                    "code": rule["code"],
                    "kpi_id": rule["kpi_id"],
                    "operator": rule["operator"],
                    "threshold": rule["threshold"],
                    "status": rule["status"],
                }
                for rule in HEALTH_SIGNAL_RULES
            ],
        },
        "averaged_score_used": False,
        "assurance": EXECUTIVE_ASSURANCE,
        "non_claims": list(EXECUTIVE_NON_CLAIMS),
        "limitations": list(EXECUTIVE_LIMITATIONS),
    }


__all__ = ["evaluate_health"]
