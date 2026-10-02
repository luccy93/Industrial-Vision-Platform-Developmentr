"""V06 spatial safety rules — thin adapters over the spatial runtime.

The runtime (``SpatialEngine``) owns the mutable per-camera state; these rules
convert its observations into ``EventDraft``s so zone and proximity events use
the *same* V05 lifecycle as every other rule: one stable ``event_id`` per
continuing condition, dedup by key, grace-period resolution, and suppression.
"""

from __future__ import annotations

from backend.app.safety.base import EventDraft, SafetyRule, SceneState
from backend.app.safety.schemas import SafetyEventType
from backend.app.spatial.engine import ProximityDetection, SpatialEngine, ZoneTransitionEvent
from backend.app.spatial.schemas import ProximityRelationship, ZoneTransition

# Relationship -> (event type, severity from configuration is applied per pair)
_RELATIONSHIP_EVENTS: dict[ProximityRelationship, SafetyEventType] = {
    ProximityRelationship.PERSON_VEHICLE: SafetyEventType.PERSON_VEHICLE_PROXIMITY,
    ProximityRelationship.PERSON_PERSON: SafetyEventType.PERSON_PERSON_PROXIMITY,
    ProximityRelationship.VEHICLE_VEHICLE: SafetyEventType.VEHICLE_VEHICLE_PROXIMITY,
}


class ZoneRule(SafetyRule):
    """Restricted/danger/warning zone entry, exit, and dwell transitions."""

    def __init__(self, spatial: SpatialEngine) -> None:
        super().__init__("restricted_zone")
        self._spatial = spatial

    @property
    def event_type(self) -> SafetyEventType:
        # Concrete type varies per transition; the ABC requires one default.
        return SafetyEventType.RESTRICTED_ZONE_ENTRY

    def evaluate(self, scene: SceneState) -> list[EventDraft]:
        transitions = self._spatial.process_zones(
            scene.camera_id,
            scene.tracks,
            scene.frame_width,
            scene.frame_height,
            scene.timestamp,
        )
        drafts: list[EventDraft] = []
        for transition in transitions:
            draft = _zone_draft(scene.camera_id, transition)
            if draft is not None:
                drafts.append(draft)
        return drafts


def _zone_draft(camera_id: str, transition: ZoneTransitionEvent) -> EventDraft | None:
    if transition.transition == ZoneTransition.ENTRY:
        event_type = SafetyEventType.RESTRICTED_ZONE_ENTRY
        prefix = "zone_entry"
        message = (
            f"{transition.class_name} #{transition.track_id} entered {transition.zone_name} "
            f"({transition.zone_type.value})"
        )
    elif transition.transition == ZoneTransition.EXIT:
        event_type = SafetyEventType.RESTRICTED_ZONE_EXIT
        prefix = "zone_exit"
        message = (
            f"{transition.class_name} #{transition.track_id} left {transition.zone_name} "
            f"after {transition.dwell_seconds:.1f}s"
        )
    elif transition.transition == ZoneTransition.STATIONARY_INSIDE:
        event_type = SafetyEventType.ZONE_DWELL
        prefix = "zone_dwell"
        message = (
            f"{transition.class_name} #{transition.track_id} inside {transition.zone_name} "
            f"for {transition.dwell_seconds:.1f}s"
        )
    else:
        return None
    return EventDraft(
        dedupe_key=f"{prefix}:{camera_id}:{transition.zone_id}:{transition.track_id}",
        event_type=event_type,
        severity=transition.severity,
        track_ids=[transition.track_id],
        confidence=_zone_confidence(transition),
        message=message,
        evidence={
            **transition.evidence,
            "zone_id": transition.zone_id,
            "zone_name": transition.zone_name,
            "zone_type": transition.zone_type.value,
            "transition": transition.transition.value,
            "reason": transition.reason,
            "dwell_seconds": round(transition.dwell_seconds, 2),
        },
    )


def _zone_confidence(transition: ZoneTransitionEvent) -> float:
    """Deterministic rule-strength score (not a calibrated probability)."""
    base = 0.75 if transition.transition != ZoneTransition.EXIT else 0.6
    if transition.reason == "track_disappeared":
        base = 0.5
    dwell = min(0.2, transition.dwell_seconds / 100.0)
    return round(min(0.95, base + dwell), 3)


class ProximityRule(SafetyRule):
    """Advanced proximity across person/vehicle, person/person, vehicle/vehicle."""

    def __init__(self, spatial: SpatialEngine) -> None:
        super().__init__("proximity_relationships")
        self._spatial = spatial

    @property
    def event_type(self) -> SafetyEventType:
        # Concrete type depends on the relationship; ABC requires one default.
        return SafetyEventType.PERSON_VEHICLE_PROXIMITY

    def evaluate(self, scene: SceneState) -> list[EventDraft]:
        detections = self._spatial.process_proximity(
            scene.camera_id,
            scene.tracks,
            scene.frame_width,
            scene.frame_height,
            scene.timestamp,
        )
        return [
            EventDraft(
                # Ordered track-ID pair keeps one event per continuing pair.
                dedupe_key=f"proximity:{d.pair_key}:{d.relationship.value}",
                event_type=_RELATIONSHIP_EVENTS[d.relationship],
                severity=d.severity,
                track_ids=[d.track_a, d.track_b],
                confidence=d.confidence,
                message=_proximity_message(d),
                evidence=dict(d.evidence),
            )
            for d in detections
        ]


def _proximity_message(detection: ProximityDetection) -> str:
    label = detection.relationship.value.replace("_", " ").lower()
    return (
        f"{label} proximity {detection.class_a} #{detection.track_a} ↔ "
        f"{detection.class_b} #{detection.track_b} ({detection.basis})"
    )


def spatial_rules(spatial: SpatialEngine) -> list[SafetyRule]:
    """Standard V06 rule set bound to a spatial runtime."""
    return [ZoneRule(spatial), ProximityRule(spatial)]


__all__ = ["ProximityRule", "ZoneRule", "spatial_rules"]
