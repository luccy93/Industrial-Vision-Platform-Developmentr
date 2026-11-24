"""Deterministic V39 SLA wrapper over the reusable V37 calculation engine.

V37 remains the single operational SLA engine. V39 synthesizes a due-date-derived
target version for a workflow item, calls ``calculate_sla()``, and maps the V37
state vocabulary into the V39 workflow states. Missing due dates never mean zero
time, and blocked or cancelled items are reported explicitly rather than as a
healthy state.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any

from backend.app.governance.intelligence.constants import (
    MAX_SLA_HOURS,
    MIN_SLA_HOURS,
)
from backend.app.governance.intelligence.sla import calculate_sla
from backend.app.governance.workflows.constants import (
    DEFAULT_SLA_WARNING_HOURS,
    SLA_NON_CLAIM,
    SLA_TARGET_KEY_WORKFLOW,
    V37_SLA_STATE_TO_WORKFLOW,
    WorkflowSlaState,
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


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _hours(start: datetime, end: datetime) -> float:
    return round(max(0.0, (end - start).total_seconds() / 3600.0), 3)


def _empty(
    *,
    entity_type: str,
    entity_id: str,
    now: datetime,
    state: str,
    reason: str,
    due_at: datetime | None = None,
) -> dict[str, Any]:
    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "state": state,
        "reason": reason,
        "sla_kind": "OPERATIONAL",
        "target_key": SLA_TARGET_KEY_WORKFLOW,
        "v37_state": None,
        "target_version": None,
        "target_hours": None,
        "warning_hours": None,
        "start_at": None,
        "due_at": _iso(due_at),
        "warning_at": None,
        "resolution_at": None,
        "elapsed_hours": None,
        "open_age_hours": None,
        "duration_hours": None,
        "resolved": False,
        "computed_at": _iso(now),
        "non_claim": SLA_NON_CLAIM,
    }


def evaluate_sla(
    *,
    entity_type: str,
    entity_id: str,
    status: str,
    due_at: Any,
    start_at: Any,
    resolved_at: Any,
    now: datetime,
    blocked: bool = False,
    cancelled: bool = False,
    applicable: bool = True,
    warning_hours: int = DEFAULT_SLA_WARNING_HOURS,
) -> dict[str, Any]:
    """Evaluate one workflow item against a due-date-derived operational target."""
    moment = _as_utc(now) or datetime.now(UTC)
    due = _as_utc(due_at)
    start = _as_utc(start_at)
    resolution = _as_utc(resolved_at)

    if not applicable:
        return _empty(
            entity_type=entity_type,
            entity_id=entity_id,
            now=moment,
            state=WorkflowSlaState.NOT_APPLICABLE.value,
            reason="The item has not entered an operational state; no SLA clock is running.",
            due_at=due,
        )
    if cancelled or str(status).upper() == "CANCELLED":
        return _empty(
            entity_type=entity_type,
            entity_id=entity_id,
            now=moment,
            state=WorkflowSlaState.NOT_APPLICABLE.value,
            reason="Cancelled items have no operational SLA.",
            due_at=due,
        )
    if blocked or str(status).upper() == "BLOCKED":
        return _empty(
            entity_type=entity_type,
            entity_id=entity_id,
            now=moment,
            state=WorkflowSlaState.PAUSED.value,
            reason="The item is blocked; its operational SLA clock is paused.",
            due_at=due,
        )
    if due is None:
        return _empty(
            entity_type=entity_type,
            entity_id=entity_id,
            now=moment,
            state=WorkflowSlaState.NOT_APPLICABLE.value,
            reason="No due date is configured; a missing due date never means zero time.",
        )
    if start is None:
        result = _empty(
            entity_type=entity_type,
            entity_id=entity_id,
            now=moment,
            state=WorkflowSlaState.UNAVAILABLE.value,
            reason="Item start time is unavailable; no SLA duration is invented.",
            due_at=due,
        )
        return result

    if due <= start:
        if resolution is not None:
            state = WorkflowSlaState.ON_TRACK.value if resolution <= due else WorkflowSlaState.OVERDUE.value
            reason = (
                "The item was resolved within the configured due time."
                if state == WorkflowSlaState.ON_TRACK.value
                else "The item was resolved after the configured due time."
            )
        else:
            state = WorkflowSlaState.OVERDUE.value
            reason = "The configured due time is at or before the item start time."
        return {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "state": state,
            "reason": reason,
            "sla_kind": "OPERATIONAL",
            "target_key": SLA_TARGET_KEY_WORKFLOW,
            "v37_state": None,
            "target_version": 1,
            "target_hours": MIN_SLA_HOURS,
            "warning_hours": 1,
            "start_at": _iso(start),
            "due_at": _iso(due),
            "warning_at": None,
            "resolution_at": _iso(resolution),
            "elapsed_hours": _hours(start, resolution) if resolution else _hours(start, moment),
            "open_age_hours": None if resolution else _hours(start, moment),
            "duration_hours": _hours(start, resolution) if resolution else None,
            "resolved": resolution is not None,
            "computed_at": _iso(moment),
            "non_claim": SLA_NON_CLAIM,
        }

    target_hours = max(
        MIN_SLA_HOURS,
        min(MAX_SLA_HOURS, int(math.ceil((due - start).total_seconds() / 3600.0))),
    )
    bounded_warning = max(1, min(int(warning_hours), max(1, target_hours - 1)))
    versions = [
        {
            "version": 1,
            "target_hours": target_hours,
            "warning_hours": bounded_warning,
            "effective_from": start,
        }
    ]
    calculated = calculate_sla(
        target_key=SLA_TARGET_KEY_WORKFLOW,
        versions=versions,
        item_start=start,
        resolved_at=resolution,
        now=moment,
        applicable=True,
        source_ref=entity_id,
    )
    v37_state = str(calculated.get("state") or "UNKNOWN").upper()
    state = V37_SLA_STATE_TO_WORKFLOW.get(v37_state, WorkflowSlaState.UNAVAILABLE.value)
    reason = str(calculated.get("reason") or "")
    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "state": state,
        "reason": reason,
        "sla_kind": "OPERATIONAL",
        "target_key": SLA_TARGET_KEY_WORKFLOW,
        "v37_state": v37_state,
        "target_version": calculated.get("target_version"),
        "target_hours": calculated.get("target_hours"),
        "warning_hours": calculated.get("warning_hours"),
        "start_at": calculated.get("start_at"),
        "due_at": calculated.get("due_at"),
        "warning_at": calculated.get("warning_at"),
        "resolution_at": calculated.get("resolution_at"),
        "elapsed_hours": calculated.get("elapsed_hours"),
        "open_age_hours": calculated.get("open_age_hours"),
        "duration_hours": calculated.get("duration_hours"),
        "resolved": bool(calculated.get("resolved")),
        "computed_at": _iso(moment),
        "non_claim": SLA_NON_CLAIM,
    }


def sla_state_counts(states: list[str]) -> dict[str, int]:
    """Bounded deterministic SLA counts; unknown labels are counted separately."""
    from backend.app.governance.workflows.constants import WORKFLOW_SLA_STATE_VALUES

    counts = {state: 0 for state in WORKFLOW_SLA_STATE_VALUES}
    counts["UNKNOWN"] = 0
    for state in states:
        normalized = str(state).upper()
        if normalized in counts:
            counts[normalized] += 1
        else:
            counts["UNKNOWN"] += 1
    return counts


__all__ = ["evaluate_sla", "sla_state_counts"]
