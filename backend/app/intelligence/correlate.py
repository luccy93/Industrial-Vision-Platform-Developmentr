"""Correlation matching — pure, deterministic cluster-link predicates.

Link rules (all must hold to link an event to a cluster):

1. Same camera (clusters never span cameras; cross-camera identity is
   unknown without explicit identity metadata).
2. Shared identity: at least one track ID or object ID in common, OR shared
   location key with type affinity inside the time window.
3. Temporal overlap: event activity within ``window_seconds`` of cluster
   activity.

Same camera alone never links. Type affinity is a tiebreak signal, not a
hard gate beyond the location rule.
"""

from __future__ import annotations

from datetime import datetime

from backend.app.intelligence.schemas import UnifiedEvent, UnifiedEventType

# Event-type affinity groups: types that describe the same operational story.
AFFINITY_GROUPS: tuple[frozenset[UnifiedEventType], ...] = (
    frozenset(
        {
            UnifiedEventType.PERSON_VEHICLE_PROXIMITY,
            UnifiedEventType.RESTRICTED_ZONE_ENTRY,
            UnifiedEventType.RESTRICTED_ZONE_EXIT,
            UnifiedEventType.RESTRICTED_ZONE_DWELL,
            UnifiedEventType.COLLISION_RISK,
            UnifiedEventType.OBJECT_APPROACH,
            UnifiedEventType.OBJECT_CROSSING,
            UnifiedEventType.LANE_DEPARTURE_RISK,
            UnifiedEventType.FALL_RISK,
        }
    ),
    frozenset(
        {
            UnifiedEventType.QUALITY_FAIL,
            UnifiedEventType.QUALITY_REVIEW,
            UnifiedEventType.QUALITY_ERROR,
            UnifiedEventType.DEFECT_DETECTED,
        }
    ),
    frozenset(
        {
            UnifiedEventType.CROWD_WARNING,
            UnifiedEventType.CROWD_CRITICAL,
            UnifiedEventType.STATIONARY_OBJECT,
        }
    ),
)


def same_affinity(first: UnifiedEventType, second: UnifiedEventType) -> bool:
    """True when two types belong to one affinity group (or are equal)."""
    if first is second:
        return True
    return any(first in group and second in group for group in AFFINITY_GROUPS)


def shared_identity(first: UnifiedEvent, second: UnifiedEvent) -> bool:
    """True when two events share a track ID or an object ID."""
    if set(first.track_ids) & set(second.track_ids):
        return True
    first_objects = {o for o in first.object_ids if o}
    second_objects = {o for o in second.object_ids if o}
    return bool(first_objects & second_objects)


def within_window(first: datetime, second: datetime, window_seconds: float) -> bool:
    """True when two timestamps are within the window (clock-skew safe)."""
    try:
        return abs((first - second).total_seconds()) <= max(0.0, window_seconds)
    except (TypeError, OverflowError):
        return False


def link_events(
    candidate: UnifiedEvent,
    member: UnifiedEvent,
    window_seconds: float,
) -> tuple[bool, list[str]]:
    """Decide whether a candidate links to a cluster member + why not/why.

    Returns ``(linked, reasons)`` where reasons explain the verdict for
    debugging and tests. Same camera alone never links.
    """
    if candidate.camera_id != member.camera_id:
        return False, ["different cameras never correlate"]
    if shared_identity(candidate, member):
        return True, ["shared track/object identity"]
    if (
        candidate.location
        and member.location
        and candidate.location == member.location
        and same_affinity(candidate.event_type, member.event_type)
        and within_window(candidate.last_seen, member.last_seen, window_seconds)
    ):
        return True, ["shared location with type affinity inside window"]
    return False, ["no shared identity or co-located affinity inside window"]


def cluster_match_score(
    candidate: UnifiedEvent,
    members: list[UnifiedEvent],
    window_seconds: float,
) -> tuple[float, int]:
    """Score a candidate against cluster members: (link_fraction, link_count).

    Fraction of members linked, used to pick the best cluster when several
    match. Deterministic for fixed inputs.
    """
    if not members:
        return 0.0, 0
    linked = sum(1 for m in members if link_events(candidate, m, window_seconds)[0])
    return linked / len(members), linked
