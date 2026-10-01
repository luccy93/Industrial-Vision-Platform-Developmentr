"""V05 safety rules — deterministic geometry over V04 tracked objects.

No neural networks, no pose estimation, no appearance embeddings. All
thresholds come from ``Settings`` (SAFETY_*). Confidence values are rule
strength scores, not calibrated probabilities.
"""

from __future__ import annotations

import logging
import math

from backend.app.core.config import Settings
from backend.app.safety.base import EventDraft, SafetyRule, SceneState
from backend.app.safety.schemas import SafetyEventType, SafetySeverity
from backend.app.tracking.schemas import TrackedObject, TrackState

logger = logging.getLogger("industrial-vision.safety")

_PERSON = "person"
_VEHICLES = frozenset({"car", "truck", "bus", "motorcycle", "bicycle", "forklift", "vehicle", "van"})


def _aspect(track: TrackedObject) -> float:
    box = track.bounding_box
    height = max(box.y2 - box.y1, 1e-6)
    return (box.x2 - box.x1) / height


def _confirmed(track: TrackedObject) -> bool:
    return track.state == TrackState.CONFIRMED


class FallRiskRule(SafetyRule):
    """Possible-fall posture from bounding-box geometry.

    A standing/walking person box is taller than wide; a horizontal box
    (width/height above threshold) held for ``persistence_frames`` consecutive
    history entries suggests a fall-like/abnormal posture. NOT a medical
    fall detector — terminology stays at possible_fall/fall_risk.
    """

    def __init__(self, aspect_threshold: float = 1.2, persistence_frames: int = 5) -> None:
        super().__init__("fall_risk")
        self.aspect_threshold = aspect_threshold
        self.persistence_frames = persistence_frames

    @property
    def event_type(self) -> SafetyEventType:
        return SafetyEventType.POSSIBLE_FALL

    def _horizontal_streak(self, track: TrackedObject) -> int:
        # V04 history already ends with the current observation; only fall
        # back to the live box when history is empty (hand-built tracks).
        boxes = [entry.bounding_box for entry in track.history] or [track.bounding_box]
        streak = 0
        for box in reversed(boxes):
            height = max(box.y2 - box.y1, 1e-6)
            if (box.x2 - box.x1) / height >= self.aspect_threshold:
                streak += 1
            else:
                break
        return streak

    def evaluate(self, scene: SceneState) -> list[EventDraft]:
        drafts: list[EventDraft] = []
        for track in scene.persons():
            if not _confirmed(track):
                continue
            streak = self._horizontal_streak(track)
            if streak < self.persistence_frames:
                continue
            extra = streak - self.persistence_frames
            geometry = min(0.9, 0.6 + 0.05 * extra)
            confidence = round(min(0.9, (geometry + track.confidence) / 2.0), 3)
            drafts.append(
                EventDraft(
                    dedupe_key=f"fall:{scene.camera_id}:{track.track_id}",
                    event_type=self.event_type,
                    severity=SafetySeverity.MEDIUM,
                    track_ids=[track.track_id],
                    confidence=confidence,
                    message=(
                        f"Possible fall posture (person #{track.track_id}): "
                        f"bbox aspect {_aspect(track):.2f} for {streak} frames"
                    ),
                    evidence={
                        "aspect_ratio": round(_aspect(track), 3),
                        "horizontal_frames": streak,
                        "track_confidence": track.confidence,
                    },
                )
            )
        return drafts


class CrowdDensityRule(SafetyRule):
    """Camera-local people counting with WARNING/CRITICAL thresholds."""

    def __init__(self, warning_count: int = 5, critical_count: int = 10) -> None:
        super().__init__("crowd_density")
        self.warning_count = warning_count
        self.critical_count = critical_count

    @property
    def event_type(self) -> SafetyEventType:
        # Concrete type chosen per evaluation; ABC requires one default.
        return SafetyEventType.CROWD_WARNING

    def evaluate(self, scene: SceneState) -> list[EventDraft]:
        persons = [t for t in scene.persons() if _confirmed(t)]
        count = len(persons)
        if count >= self.critical_count:
            level: SafetyEventType = SafetyEventType.CROWD_CRITICAL
            severity = SafetySeverity.CRITICAL
            confidence = min(0.95, 0.8 + 0.05 * (count - self.critical_count))
            message = f"Crowd critical: {count} persons in scene (≥ {self.critical_count})"
        elif count >= self.warning_count:
            level = SafetyEventType.CROWD_WARNING
            severity = SafetySeverity.MEDIUM
            span = max(1, self.critical_count - self.warning_count)
            confidence = min(0.9, 0.6 + 0.3 * (count - self.warning_count + 1) / span)
            message = f"Crowd warning: {count} persons in scene (≥ {self.warning_count})"
        else:
            return []
        return [
            EventDraft(
                dedupe_key=f"crowd:{scene.camera_id}",
                event_type=level,
                severity=severity,
                track_ids=sorted(t.track_id for t in persons),
                confidence=round(confidence, 3),
                message=message,
                evidence={"person_count": count},
            )
        ]


def _iou(a: TrackedObject, b: TrackedObject) -> float:
    ax1, ay1, ax2, ay2 = a.bounding_box.x1, a.bounding_box.y1, a.bounding_box.x2, a.bounding_box.y2
    bx1, by1, bx2, by2 = b.bounding_box.x1, b.bounding_box.y1, b.bounding_box.x2, b.bounding_box.y2
    inter = max(0.0, min(ax2, bx2) - max(ax1, bx1)) * max(0.0, min(ay2, by2) - max(ay1, by1))
    union = (ax2 - ax1) * (ay2 - ay1) + (bx2 - bx1) * (by2 - by1) - inter
    return inter / union if union > 0 else 0.0


def _center_distance_ratio(a: TrackedObject, b: TrackedObject) -> float:
    acx, acy = (a.bounding_box.x1 + a.bounding_box.x2) / 2, (a.bounding_box.y1 + a.bounding_box.y2) / 2
    bcx, bcy = (b.bounding_box.x1 + b.bounding_box.x2) / 2, (b.bounding_box.y1 + b.bounding_box.y2) / 2
    dist = math.hypot(acx - bcx, acy - bcy)
    scale = (
        math.hypot(a.bounding_box.x2 - a.bounding_box.x1, a.bounding_box.y2 - a.bounding_box.y1)
        + math.hypot(b.bounding_box.x2 - b.bounding_box.x1, b.bounding_box.y2 - b.bounding_box.y1)
    ) / 2.0
    return dist / scale if scale > 0 else float("inf")


class PersonVehicleProximityRule(SafetyRule):
    """Image-space proximity risk between persons and vehicles.

    Proximity signal only — never meters. A pair triggers on box overlap
    (IoU) or close centers relative to object size.
    """

    def __init__(self, iou_threshold: float = 0.05, center_distance_ratio: float = 0.3) -> None:
        super().__init__("person_vehicle_proximity")
        self.iou_threshold = iou_threshold
        self.center_distance_ratio = center_distance_ratio

    @property
    def event_type(self) -> SafetyEventType:
        return SafetyEventType.PERSON_VEHICLE_PROXIMITY

    def evaluate(self, scene: SceneState) -> list[EventDraft]:
        persons = [t for t in scene.persons() if _confirmed(t)]
        vehicles = [t for t in scene.tracks if t.class_name.lower() in _VEHICLES and _confirmed(t)]
        drafts: list[EventDraft] = []
        for person in persons:
            for vehicle in vehicles:
                iou = _iou(person, vehicle)
                ratio = _center_distance_ratio(person, vehicle)
                if iou >= self.iou_threshold:
                    strength = min(1.0, iou * 5.0)
                    basis = f"image overlap IoU {iou:.2f}"
                elif ratio <= self.center_distance_ratio:
                    strength = 1.0 - ratio / max(self.center_distance_ratio, 1e-6)
                    basis = f"center-distance ratio {ratio:.2f}"
                else:
                    continue
                confidence = round(min(0.95, 0.6 + 0.4 * strength), 3)
                drafts.append(
                    EventDraft(
                        dedupe_key=f"prox:{scene.camera_id}:{person.track_id}:{vehicle.track_id}",
                        event_type=self.event_type,
                        severity=SafetySeverity.HIGH,
                        track_ids=[person.track_id, vehicle.track_id],
                        confidence=confidence,
                        message=(
                            f"Person #{person.track_id} and {vehicle.class_name} "
                            f"#{vehicle.track_id} proximity risk ({basis})"
                        ),
                        evidence={"iou": round(iou, 3), "center_distance_ratio": round(ratio, 3)},
                    )
                )
        return drafts


class StationaryObjectRule(SafetyRule):
    """Flags persons/vehicles nearly motionless for a configured duration.

    Uses V04 image-space speed over the track's bounded history span:
    duration covered AND total center displacement within
    ``speed_threshold × duration``.
    """

    def __init__(self, speed_threshold: float = 15.0, duration_seconds: float = 10.0) -> None:
        super().__init__("stationary_object")
        self.speed_threshold = speed_threshold
        self.duration_seconds = duration_seconds

    @property
    def event_type(self) -> SafetyEventType:
        return SafetyEventType.PROLONGED_STATIONARY

    def evaluate(self, scene: SceneState) -> list[EventDraft]:
        drafts: list[EventDraft] = []
        for track in scene.tracks:
            if track.class_name.lower() not in (_VEHICLES | {_PERSON}):
                continue
            if not _confirmed(track):
                continue
            history = list(track.history)
            if len(history) < 2:
                continue
            span = (history[-1].timestamp - history[0].timestamp).total_seconds()
            if span < self.duration_seconds:
                continue
            displacement = math.hypot(
                history[-1].center_x - history[0].center_x,
                history[-1].center_y - history[0].center_y,
            )
            if displacement > self.speed_threshold * max(span, 1e-6):
                continue
            over = span / max(self.duration_seconds, 1e-6)
            confidence = round(min(0.9, 0.5 + 0.2 * min(over, 2.0)), 3)
            drafts.append(
                EventDraft(
                    dedupe_key=f"stationary:{scene.camera_id}:{track.track_id}",
                    event_type=self.event_type,
                    severity=SafetySeverity.LOW,
                    track_ids=[track.track_id],
                    confidence=confidence,
                    message=(
                        f"{track.class_name} #{track.track_id} stationary for {span:.0f}s (image-space)"
                    ),
                    evidence={
                        "span_seconds": round(span, 1),
                        "displacement_px": round(displacement, 1),
                    },
                )
            )
        return drafts


def default_rules(settings: Settings) -> list[SafetyRule]:
    """Build the standard V05 rule set from configuration."""
    return [
        FallRiskRule(
            aspect_threshold=settings.safety_fall_aspect_ratio_threshold,
            persistence_frames=settings.safety_fall_persistence_frames,
        ),
        CrowdDensityRule(
            warning_count=settings.safety_crowd_warning_count,
            critical_count=settings.safety_crowd_critical_count,
        ),
        PersonVehicleProximityRule(
            iou_threshold=settings.safety_proximity_iou_threshold,
            center_distance_ratio=settings.safety_proximity_center_distance_ratio,
        ),
        StationaryObjectRule(
            speed_threshold=settings.safety_stationary_speed_threshold,
            duration_seconds=settings.safety_stationary_duration_seconds,
        ),
    ]
