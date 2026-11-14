"""Versioned operational SLA calculations (V37).

SLA targets are organization-configurable and versioned. A calculation resolves
the target version effective at the item's start time, so later target changes
never rewrite history. Unresolved items expose only an open age; a duration is
reported only after resolution. These are operational targets, not legal or
regulatory deadlines.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from backend.app.governance.intelligence.constants import (
    SLA_KIND_OPERATIONAL,
    SLA_NON_CLAIM,
    SlaState,
    validate_sla_target,
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


def _normalized_versions(versions: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in versions:
        effective = _as_utc(row.get("effective_from"))
        if effective is None:
            continue
        try:
            target, warning = validate_sla_target(row.get("target_hours"), row.get("warning_hours"))
        except ValueError:
            continue
        try:
            version = int(row.get("version"))
        except (TypeError, ValueError):
            continue
        rows.append(
            {
                "version": version,
                "target_hours": target,
                "warning_hours": warning,
                "effective_from": effective,
                "actor_id": row.get("actor_id"),
                "actor_role": row.get("actor_role"),
                "reason": row.get("reason"),
            }
        )
    rows.sort(key=lambda item: (item["effective_from"], item["version"]))
    return rows


def resolve_target_version(
    versions: Sequence[Mapping[str, Any]], item_start: datetime
) -> dict[str, Any] | None:
    """Return the target version effective at ``item_start``."""
    start = item_start.replace(tzinfo=UTC) if item_start.tzinfo is None else item_start.astimezone(UTC)
    selected: dict[str, Any] | None = None
    for row in _normalized_versions(versions):
        if row["effective_from"] <= start:
            selected = row
    return selected


def calculate_sla(
    *,
    target_key: str,
    versions: Sequence[Mapping[str, Any]],
    item_start: Any,
    resolved_at: Any = None,
    now: datetime,
    applicable: bool = True,
    source_ref: str | None = None,
) -> dict[str, Any]:
    """Calculate one operational SLA state deterministically."""
    moment = now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)
    base: dict[str, Any] = {
        "target_key": str(target_key).upper(),
        "sla_kind": SLA_KIND_OPERATIONAL,
        "source_ref": source_ref,
        "computed_at": _iso(moment),
        "non_claim": SLA_NON_CLAIM,
        "target_version": None,
        "target_hours": None,
        "warning_hours": None,
        "target_effective_from": None,
        "start_at": None,
        "due_at": None,
        "warning_at": None,
        "resolution_at": None,
        "elapsed_hours": None,
        "open_age_hours": None,
        "duration_hours": None,
        "resolved": False,
        "state": SlaState.UNKNOWN.value,
        "reason": "",
    }
    if not applicable:
        base["state"] = SlaState.NOT_APPLICABLE.value
        base["reason"] = "No operational SLA applies to this item."
        return base

    start = _as_utc(item_start)
    if start is None:
        base["reason"] = "Item start time is unavailable; no SLA duration is invented."
        return base
    base["start_at"] = _iso(start)

    target = resolve_target_version(versions, start)
    if target is None:
        base["reason"] = "No SLA target version was effective at the item start time."
        return base

    target_hours = int(target["target_hours"])
    warning_hours = int(target["warning_hours"])
    due = start + timedelta(hours=target_hours)
    warning_at = due - timedelta(hours=warning_hours)
    base.update(
        {
            "target_version": int(target["version"]),
            "target_hours": target_hours,
            "warning_hours": warning_hours,
            "target_effective_from": _iso(target["effective_from"]),
            "due_at": _iso(due),
            "warning_at": _iso(warning_at),
        }
    )

    resolution = _as_utc(resolved_at)
    if resolution is not None:
        if resolution < start:
            base["reason"] = "Resolution time precedes the item start time; SLA state is unknown."
            return base
        duration = _hours(start, resolution)
        base.update(
            {
                "resolution_at": _iso(resolution),
                "elapsed_hours": duration,
                "duration_hours": duration,
                "resolved": True,
                "state": (SlaState.MET.value if duration <= target_hours else SlaState.MISSED.value),
                "reason": (
                    "The item was resolved within the operational target."
                    if duration <= target_hours
                    else "The item was resolved after the operational target."
                ),
            }
        )
        return base

    if moment < start:
        base["reason"] = "Item start time is in the future; SLA state is unknown."
        return base
    elapsed = _hours(start, moment)
    if elapsed > target_hours:
        state = SlaState.BREACHED.value
        reason = "The unresolved item is past the operational target."
    elif elapsed >= target_hours - warning_hours:
        state = SlaState.AT_RISK.value
        reason = "The unresolved item is inside the operational warning window."
    else:
        state = SlaState.WITHIN_TARGET.value
        reason = "The unresolved item is within the operational target."
    base.update(
        {
            "elapsed_hours": elapsed,
            "open_age_hours": elapsed,
            "resolved": False,
            "state": state,
            "reason": reason,
        }
    )
    return base


__all__ = ["calculate_sla", "resolve_target_version"]
