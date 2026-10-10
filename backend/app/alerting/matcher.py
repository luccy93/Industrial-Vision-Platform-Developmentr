"""Deterministic rule matching — pure, no I/O (V15).

A candidate is a normalized source occurrence::

    {
        "domain": "SAFETY",            # upper-case source domain
        "event_type": "CROWD_WARNING", # unified type or transition type
        "severity": "HIGH",            # may be UNKNOWN
        "priority": "P1",              # may be UNKNOWN
        "camera_id": "cam-01" | None,
        "new_state": "RESOLVED" | None # transitions only
    }

Empty rule filter lists deliberately match all (documented). Unknown
candidate values never satisfy a set minimum. Disabled rules never
match (evaluators must also pre-filter enabled rules).
"""

from __future__ import annotations

from typing import Any

from backend.app.alerting.schemas import AlertRule
from backend.app.intelligence.schemas import SEVERITY_RANK, UnifiedSeverity

_PRIORITY_ORDER = ("P0", "P1", "P2", "P3", "P4")


def severity_rank(value: Any) -> float:
    """Rank 0.0–1.0; UNKNOWN and garbage rank below everything (-1.0)."""
    try:
        severity = UnifiedSeverity(str(value).strip().upper())
    except ValueError:
        return -1.0
    if severity is UnifiedSeverity.UNKNOWN:
        return -1.0
    return float(SEVERITY_RANK.get(severity, -1.0))


def priority_rank(value: Any) -> int:
    """Rank 0 (P0, most urgent) to 4 (P4); unknown ranks above everything."""
    normalized = str(value or "").strip().upper()
    if normalized not in _PRIORITY_ORDER:
        return len(_PRIORITY_ORDER)
    return _PRIORITY_ORDER.index(normalized)


def rule_matches(rule: AlertRule, candidate: dict[str, Any]) -> bool:
    """True when the candidate satisfies every configured rule filter."""
    if not rule.enabled:
        return False
    domain = str(candidate.get("domain") or "").strip().upper()
    event_type = str(candidate.get("event_type") or "").strip().upper()
    if rule.domains and domain not in [str(d).upper() for d in rule.domains]:
        return False
    if rule.event_types and event_type not in [str(t).upper() for t in rule.event_types]:
        return False
    if rule.min_severity:
        if severity_rank(candidate.get("severity")) < severity_rank(rule.min_severity):
            return False
    if rule.min_priority:
        if priority_rank(candidate.get("priority")) > priority_rank(rule.min_priority):
            return False
    if rule.camera_ids:
        camera_id = candidate.get("camera_id")
        if camera_id is None or str(camera_id) not in [str(c) for c in rule.camera_ids]:
            return False
    if rule.incident_statuses:
        new_state = candidate.get("new_state")
        if new_state is None or str(new_state).upper() not in [
            str(s).upper() for s in rule.incident_statuses
        ]:
            return False
    return True


__all__ = ["priority_rank", "rule_matches", "severity_rank"]
