"""Spatial engine — V06 zone + proximity runtime (in-memory, per camera).

Responsibilities:
  - hold the *configuration* snapshot of a camera's zones (loaded from
    PostgreSQL by the API layer, never read here);
  - compute image-space membership (bbox bottom-center vs normalized polygon),
    entry/exit transitions, and dwell duration;
  - compute image-space proximity pairs per configured relationship.

Everything is image-space. Distances are fractions of the frame, never meters.

State is bounded and per camera: ``(camera_id, zone_id, track_id)`` keys are
pruned on disappearance (``spatial_state_grace_seconds``) and capped, so a
stalled stream can never leak memory.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from backend.app.core.config import Settings, get_settings
from backend.app.domain.common import utcnow
from backend.app.safety.schemas import SafetySeverity
from backend.app.spatial import geometry
from backend.app.spatial.schemas import (
    ProximityRelationship,
    ProximityStrategy,
    SafetyZone,
    ZoneMembership,
    ZoneTrackState,
    ZoneTransition,
    ZoneType,
)
from backend.app.tracking.schemas import TrackedObject, TrackState

logger = logging.getLogger("industrial-vision.spatial")

_PERSON = "person"
_VEHICLE_CLASSES = frozenset({"car", "truck", "bus", "motorcycle", "bicycle", "forklift", "vehicle", "van"})
# Zone membership applies to people and vehicles by default; a zone may
# override the class set with metadata={"classes": ["person", "forklift"]}.
ZONE_TRACK_CLASSES = frozenset({_PERSON}) | _VEHICLE_CLASSES

# Upper bound on evaluated pairs per relationship per camera (performance guard).
MAX_PAIRS_PER_RELATIONSHIP = 2000


class ZoneTransitionEvent(BaseModel):
    """One zone transition/observation produced by the spatial runtime."""

    camera_id: str
    zone_id: str
    zone_name: str
    zone_type: ZoneType
    track_id: int
    class_name: str
    transition: ZoneTransition
    reason: str = "observed"
    severity: SafetySeverity = SafetySeverity.MEDIUM
    dwell_seconds: float = 0.0
    timestamp: datetime
    evidence: dict[str, Any] = Field(default_factory=dict)

    def to_websocket(self) -> dict[str, Any]:
        return {
            "camera_id": self.camera_id,
            "zone_id": self.zone_id,
            "zone_name": self.zone_name,
            "zone_type": self.zone_type.value,
            "track_id": self.track_id,
            "class_name": self.class_name,
            "transition": self.transition.value,
            "reason": self.reason,
            "severity": self.severity.value,
            "dwell_seconds": round(self.dwell_seconds, 2),
            "timestamp": self.timestamp.isoformat(),
            "evidence": dict(self.evidence),
        }


class ProximityDetection(BaseModel):
    """One image-space proximity pair (unordered, canonical track-ID order)."""

    camera_id: str
    relationship: ProximityRelationship
    track_a: int
    track_b: int
    class_a: str
    class_b: str
    severity: SafetySeverity = SafetySeverity.MEDIUM
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    center_distance_ratio: float = 0.0
    iou: float = 0.0
    basis: str = ""
    timestamp: datetime
    evidence: dict[str, Any] = Field(default_factory=dict)

    @property
    def pair_key(self) -> str:
        low, high = sorted((self.track_a, self.track_b))
        return f"{self.camera_id}:{low}:{high}"

    def to_websocket(self) -> dict[str, Any]:
        return {
            "camera_id": self.camera_id,
            "relationship": self.relationship.value,
            "track_ids": [self.track_a, self.track_b],
            "class_names": [self.class_a, self.class_b],
            "severity": self.severity.value,
            "confidence": self.confidence,
            "center_distance_ratio": round(self.center_distance_ratio, 3),
            "iou": round(self.iou, 3),
            "basis": self.basis,
            "timestamp": self.timestamp.isoformat(),
            "evidence": dict(self.evidence),
        }


def _box(track: TrackedObject) -> tuple[float, float, float, float]:
    b = track.bounding_box
    return (b.x1, b.y1, b.x2, b.y2)


def _confirmed(track: TrackedObject) -> bool:
    return track.state == TrackState.CONFIRMED


class SpatialEngine:
    """Zone registry + zone/proximity runtime with per-camera isolation."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        # Reentrant: runtime helpers (e.g. ``_state``) are called from inside
        # locked sections while updating state.
        self._lock = threading.RLock()
        self._zones: dict[str, dict[str, SafetyZone]] = {}
        self._states: dict[tuple[str, str, int], ZoneTrackState] = {}
        self._last_evaluation: dict[str, float] = {}
        self._latency_ms = 0.0
        self._evaluations = 0

    @property
    def enabled(self) -> bool:
        return self._settings.spatial_enabled

    # ------------------------------------------------------------------
    # Zone configuration (mirrors the PostgreSQL ``zones`` table)
    # ------------------------------------------------------------------
    def set_zones(self, camera_id: str, zones: list[SafetyZone]) -> None:
        with self._lock:
            self._zones[camera_id] = {zone.zone_id: zone for zone in zones}
            self._prune_states(camera_id, {zone.zone_id for zone in zones})

    def reset_camera(self, camera_id: str) -> None:
        with self._lock:
            self._zones.pop(camera_id, None)
            for key in [k for k in self._states if k[0] == camera_id]:
                del self._states[key]
            self._last_evaluation.pop(camera_id, None)

    def remove_camera(self, camera_id: str) -> None:
        """Alias of :meth:`reset_camera` (camera deleted or re-attached)."""
        self.reset_camera(camera_id)

    def remove_zone(self, camera_id: str, zone_id: str) -> None:
        with self._lock:
            self._zones.get(camera_id, {}).pop(zone_id, None)
            for key in [k for k in self._states if k[0] == camera_id and k[1] == zone_id]:
                del self._states[key]

    def zones_for(self, camera_id: str, enabled_only: bool = True) -> list[SafetyZone]:
        with self._lock:
            zones = list(self._zones.get(camera_id, {}).values())
        if enabled_only:
            zones = [zone for zone in zones if zone.enabled]
        return sorted(zones, key=lambda z: z.zone_id)

    def camera_count(self) -> int:
        with self._lock:
            return len(self._zones)

    def zone_count(self) -> int:
        with self._lock:
            return sum(len(zones) for zones in self._zones.values())

    # ------------------------------------------------------------------
    # Membership primitives
    # ------------------------------------------------------------------
    @staticmethod
    def anchor_point(
        box: tuple[float, float, float, float], frame_width: float, frame_height: float
    ) -> tuple[float, float]:
        """Bottom-center in *normalized* coordinates (ground-contact heuristic)."""
        cx, bottom = geometry.bbox_bottom_center(box)
        width = frame_width if frame_width > 0 else 1.0
        height = frame_height if frame_height > 0 else 1.0
        return (min(1.0, max(0.0, cx / width)), min(1.0, max(0.0, bottom / height)))

    @staticmethod
    def is_inside(zone: SafetyZone, point: tuple[float, float]) -> bool:
        polygon = [(p.x, p.y) for p in zone.polygon]
        return geometry.point_in_polygon(point[0], point[1], polygon)

    def classify_transition(self, was_inside: bool, is_inside: bool) -> ZoneTransition:
        if not was_inside and is_inside:
            return ZoneTransition.ENTRY
        if was_inside and not is_inside:
            return ZoneTransition.EXIT
        if is_inside:
            return ZoneTransition.STATIONARY_INSIDE
        return ZoneTransition.STATIONARY_OUTSIDE

    @staticmethod
    def zone_classes(zone: SafetyZone) -> frozenset[str]:
        raw = zone.metadata.get("classes")
        if isinstance(raw, list) and raw:
            names = {str(item).lower() for item in raw}
            return frozenset(name for name in names if name) or ZONE_TRACK_CLASSES
        return ZONE_TRACK_CLASSES

    def _dwell_threshold(self, zone: SafetyZone) -> float:
        if zone.dwell_threshold_seconds is not None:
            return zone.dwell_threshold_seconds
        return self._settings.spatial_default_dwell_seconds

    # ------------------------------------------------------------------
    # Zone runtime
    # ------------------------------------------------------------------
    def process_zones(
        self,
        camera_id: str,
        tracks: list[TrackedObject],
        frame_width: float,
        frame_height: float,
        timestamp: datetime,
    ) -> list[ZoneTransitionEvent]:
        """Return ENTRY/EXIT/DWELL transitions for one frame.

        Tracks that disappear are reported as EXIT after
        ``spatial_state_grace_seconds`` so a detection dropout does not churn
        events and never leaves a dwell event stuck.
        """
        if not self.enabled:
            return []
        zones = [zone for zone in self.zones_for(camera_id) if zone.zone_type != ZoneType.SAFE]
        if not zones and not self._states:
            return []

        events: list[ZoneTransitionEvent] = []
        seen: set[tuple[str, str, int]] = set()
        for zone in zones:
            classes = self.zone_classes(zone)
            polygon = [(p.x, p.y) for p in zone.polygon]
            threshold = self._dwell_threshold(zone)
            for track in tracks:
                if track.class_name.lower() not in classes or not _confirmed(track):
                    continue
                key = (camera_id, zone.zone_id, track.track_id)
                point = self.anchor_point(_box(track), frame_width, frame_height)
                inside = geometry.point_in_polygon(point[0], point[1], polygon)
                state = self._state(key)
                seen.add(key)
                with self._lock:
                    if state is None:
                        state = ZoneTrackState(
                            camera_id=camera_id, zone_id=zone.zone_id, track_id=track.track_id
                        )
                        self._states[key] = state
                    was_inside = state.inside
                    prev_x, prev_y = state.previous_x, state.previous_y
                    if prev_x is not None and prev_y is not None:
                        state.movement_x = point[0] - prev_x
                        state.movement_y = point[1] - prev_y
                    if inside and not was_inside:
                        state.inside = True
                        state.entered_at = timestamp
                        state.dwell_notified = False
                    elif not inside and was_inside:
                        state.inside = False
                    dwell = (
                        (timestamp - state.entered_at).total_seconds()
                        if inside and state.entered_at is not None
                        else 0.0
                    )
                    state.last_seen = timestamp
                    state.previous_x, state.previous_y = point
                vector = (state.movement_x, state.movement_y)
                if not was_inside and inside:
                    events.append(
                        self._zone_event(
                            camera_id,
                            zone,
                            track,
                            ZoneTransition.ENTRY,
                            timestamp,
                            reason="anchor_entered",
                            point=point,
                            dwell=0.0,
                            vector=vector,
                        )
                    )
                elif was_inside and not inside:
                    events.append(
                        self._zone_event(
                            camera_id,
                            zone,
                            track,
                            ZoneTransition.EXIT,
                            timestamp,
                            reason="anchor_exited",
                            point=point,
                            dwell=dwell,
                            vector=vector,
                        )
                    )
                if inside and threshold >= 0 and dwell >= threshold:
                    # Emitted while the condition persists so the V05 lifecycle
                    # keeps the dwell event ACTIVE and refreshed; the first
                    # emission is flagged so clients can alert once.
                    first = not state.dwell_notified
                    state.dwell_notified = True
                    events.append(
                        self._zone_event(
                            camera_id,
                            zone,
                            track,
                            ZoneTransition.STATIONARY_INSIDE,
                            timestamp,
                            reason="dwell_threshold",
                            point=point,
                            dwell=dwell,
                            vector=vector,
                            first_observation=first,
                        )
                    )
        events.extend(self._expire_missing(camera_id, seen, timestamp))
        return events

    def _expire_missing(
        self,
        camera_id: str,
        seen: set[tuple[str, str, int]],
        timestamp: datetime,
    ) -> list[ZoneTransitionEvent]:
        """Purge states for vanished tracks/zones after the grace window."""
        grace = self._settings.spatial_state_grace_seconds
        expired: list[ZoneTransitionEvent] = []
        with self._lock:
            stale = [
                key
                for key, state in self._states.items()
                if key[0] == camera_id
                and key not in seen
                and (state.last_seen is None or (timestamp - state.last_seen).total_seconds() > grace)
            ]
            for key in stale:
                state = self._states.pop(key, None)
                if state is None or not state.inside:
                    continue
                zone = self.zones_for(camera_id, enabled_only=False)
                match = next((z for z in zone if z.zone_id == state.zone_id), None)
                if match is None:
                    continue
                dwell = (
                    (timestamp - state.entered_at).total_seconds() if state.entered_at is not None else 0.0
                )
                expired.append(
                    ZoneTransitionEvent(
                        camera_id=camera_id,
                        zone_id=state.zone_id,
                        zone_name=match.name,
                        zone_type=match.zone_type,
                        track_id=state.track_id,
                        class_name=_PERSON,
                        transition=ZoneTransition.EXIT,
                        reason="track_disappeared",
                        severity=match.severity,
                        dwell_seconds=dwell,
                        timestamp=timestamp,
                        evidence={"dwell_seconds": round(dwell, 2), "grace_seconds": grace},
                    )
                )
        return expired

    def _zone_event(
        self,
        camera_id: str,
        zone: SafetyZone,
        track: TrackedObject,
        transition: ZoneTransition,
        timestamp: datetime,
        *,
        reason: str,
        point: tuple[float, float],
        dwell: float,
        vector: tuple[float, float] = (0.0, 0.0),
        first_observation: bool = True,
    ) -> ZoneTransitionEvent:
        return ZoneTransitionEvent(
            camera_id=camera_id,
            zone_id=zone.zone_id,
            zone_name=zone.name,
            zone_type=zone.zone_type,
            track_id=track.track_id,
            class_name=track.class_name,
            transition=transition,
            reason=reason,
            severity=zone.severity,
            dwell_seconds=dwell,
            timestamp=timestamp,
            evidence={
                "anchor_x": round(point[0], 4),
                "anchor_y": round(point[1], 4),
                "movement_x": round(vector[0], 5),
                "movement_y": round(vector[1], 5),
                "dwell_threshold_seconds": self._dwell_threshold(zone),
                "first_observation": first_observation,
                "image_space": True,
            },
        )

    def _state(self, key: tuple[str, str, int]) -> ZoneTrackState | None:
        with self._lock:
            return self._states.get(key)

    def _prune_states(self, camera_id: str, zone_ids: set[str]) -> None:
        for key in [k for k in self._states if k[0] == camera_id and (not zone_ids or k[1] not in zone_ids)]:
            del self._states[key]

    def membership_snapshot(self, camera_id: str, limit: int = 100) -> list[ZoneMembership]:
        now = utcnow()
        with self._lock:
            states = [s for k, s in self._states.items() if k[0] == camera_id and s.inside]
        states.sort(key=lambda s: (s.zone_id, s.track_id))
        return [
            ZoneMembership(
                camera_id=camera_id,
                zone_id=s.zone_id,
                track_id=s.track_id,
                inside=True,
                entered_at=s.entered_at,
                dwell_seconds=round((now - s.entered_at).total_seconds(), 2)
                if s.entered_at is not None
                else 0.0,
            )
            for s in states[: max(1, limit)]
        ]

    def state_count(self) -> int:
        with self._lock:
            return len(self._states)

    # ------------------------------------------------------------------
    # Proximity runtime
    # ------------------------------------------------------------------
    def _relationship_config(
        self, relationship: ProximityRelationship
    ) -> tuple[bool, float, SafetySeverity, str]:
        s = self._settings
        if relationship == ProximityRelationship.PERSON_VEHICLE:
            return (
                s.spatial_person_vehicle_enabled,
                s.spatial_person_vehicle_threshold,
                SafetySeverity(s.spatial_person_vehicle_severity),
                "person_vehicle",
            )
        if relationship == ProximityRelationship.PERSON_PERSON:
            return (
                s.spatial_person_person_enabled,
                s.spatial_person_person_threshold,
                SafetySeverity(s.spatial_person_person_severity),
                "person_person",
            )
        return (
            s.spatial_vehicle_vehicle_enabled,
            s.spatial_vehicle_vehicle_threshold,
            SafetySeverity(s.spatial_vehicle_vehicle_severity),
            "vehicle_vehicle",
        )

    def _pairs_for(
        self, relationship: ProximityRelationship, tracks: list[TrackedObject]
    ) -> list[tuple[TrackedObject, TrackedObject]]:
        confirmed = [t for t in tracks if _confirmed(t)]
        if relationship == ProximityRelationship.PERSON_PERSON:
            pool = [t for t in confirmed if t.class_name.lower() == _PERSON]
        elif relationship == ProximityRelationship.VEHICLE_VEHICLE:
            pool = [t for t in confirmed if t.class_name.lower() in _VEHICLE_CLASSES]
        else:
            left = [t for t in confirmed if t.class_name.lower() == _PERSON]
            right = [t for t in confirmed if t.class_name.lower() in _VEHICLE_CLASSES]
            return _bounded_pairs(left, right)
        return _bounded_pairs(pool, pool)

    def process_proximity(
        self,
        camera_id: str,
        tracks: list[TrackedObject],
        frame_width: float,
        frame_height: float,
        timestamp: datetime,
    ) -> list[ProximityDetection]:
        if not self.enabled:
            return []
        strategy = ProximityStrategy(self._settings.spatial_proximity_strategy)
        iou_threshold = self._settings.spatial_proximity_iou_threshold
        detections: list[ProximityDetection] = []
        for relationship in ProximityRelationship:
            enabled, threshold, severity, _label = self._relationship_config(relationship)
            if not enabled:
                continue
            for a, b in self._pairs_for(relationship, tracks):
                box_a, box_b = _box(a), _box(b)
                iou = geometry.bbox_iou(box_a, box_b)
                overlap = geometry.bbox_overlap_ratio(box_a, box_b)
                ratio = self._center_ratio(box_a, box_b, frame_width, frame_height)
                strength, basis = _evaluate_pair(strategy, threshold, iou_threshold, ratio, iou, overlap)
                if strength <= 0.0:
                    continue
                low, high = sorted((a.track_id, b.track_id))
                first, second = (a, b) if a.track_id == low else (b, a)
                detections.append(
                    ProximityDetection(
                        camera_id=camera_id,
                        relationship=relationship,
                        track_a=low,
                        track_b=high,
                        class_a=first.class_name,
                        class_b=second.class_name,
                        severity=severity,
                        confidence=round(min(0.95, 0.6 + 0.4 * strength), 3),
                        center_distance_ratio=ratio,
                        iou=iou,
                        basis=basis,
                        timestamp=timestamp,
                        evidence={
                            "strategy": strategy.value,
                            "iou": round(iou, 3),
                            "overlap_ratio": round(overlap, 3),
                            "center_distance_ratio": round(ratio, 3),
                            "threshold": threshold,
                            "frame_width": frame_width,
                            "frame_height": frame_height,
                            "image_space": True,
                        },
                    )
                )
        detections.sort(key=lambda d: (d.relationship.value, d.track_a, d.track_b))
        return detections

    @staticmethod
    def _center_ratio(
        a: tuple[float, float, float, float],
        b: tuple[float, float, float, float],
        frame_width: float,
        frame_height: float,
    ) -> float:
        """Center distance normalized by frame size (fraction of frame)."""
        ax, ay = geometry.bbox_center(a)
        bx, by = geometry.bbox_center(b)
        width = frame_width if frame_width > 0 else max(a[2], b[2], 1.0)
        height = frame_height if frame_height > 0 else max(a[3], b[3], 1.0)
        return geometry.distance_between_points(
            (ax / width, ay / height),
            (bx / width, by / height),
        )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        started = time.perf_counter()
        relationships = []
        for relationship in ProximityRelationship:
            enabled, threshold, severity, _label = self._relationship_config(relationship)
            relationships.append(
                {
                    "relationship": relationship.value,
                    "enabled": enabled,
                    "threshold": threshold,
                    "severity": severity.value,
                }
            )
        latency = round((time.perf_counter() - started) * 1000.0, 3)
        self._latency_ms = latency
        with self._lock:
            cameras = sorted(self._zones.keys())
            per_camera = {
                camera_id: {
                    "zones": len(self._zones[camera_id]),
                    "active_states": sum(1 for k in self._states if k[0] == camera_id),
                }
                for camera_id in cameras
            }
            evaluations = self._evaluations
        return {
            "enabled": self.enabled,
            "engine_status": "READY" if self.enabled else "DISABLED",
            "coordinate_space": "normalized_image_space",
            "membership_heuristic": "bounding_box_bottom_center",
            "default_dwell_seconds": self._settings.spatial_default_dwell_seconds,
            "state_grace_seconds": self._settings.spatial_state_grace_seconds,
            "proximity_strategy": self._settings.spatial_proximity_strategy,
            "proximity_iou_threshold": self._settings.spatial_proximity_iou_threshold,
            "relationships": relationships,
            "zone_count": sum(info["zones"] for info in per_camera.values()),
            "camera_count": len(per_camera),
            "active_state_count": sum(info["active_states"] for info in per_camera.values()),
            "evaluations": evaluations,
            "latency_ms": latency,
            "cameras": per_camera,
        }

    def record_evaluation(self, camera_id: str) -> None:
        with self._lock:
            self._last_evaluation[camera_id] = time.perf_counter()
            self._evaluations += 1


def _bounded_pairs(
    left: list[TrackedObject], right: list[TrackedObject]
) -> list[tuple[TrackedObject, TrackedObject]]:
    """Deterministic, bounded pair enumeration (sorted, capped, no duplicates)."""
    same_pool = left is right
    left = sorted(left, key=lambda t: t.track_id)
    right = sorted(right, key=lambda t: t.track_id)
    pairs: list[tuple[TrackedObject, TrackedObject]] = []
    seen: set[tuple[int, int]] = set()
    for a in left:
        for b in right:
            if same_pool and a is b:
                continue
            key = (min(a.track_id, b.track_id), max(a.track_id, b.track_id))
            if key in seen:
                continue
            seen.add(key)
            pairs.append((a, b))
            if len(pairs) >= MAX_PAIRS_PER_RELATIONSHIP:
                logger.warning(
                    "proximity pair cap reached (%s pairs); image-space scan truncated",
                    MAX_PAIRS_PER_RELATIONSHIP,
                )
                return pairs
    return pairs


def _evaluate_pair(
    strategy: ProximityStrategy,
    threshold: float,
    iou_threshold: float,
    ratio: float,
    iou: float,
    overlap: float,
) -> tuple[float, str]:
    """Return (strength 0..1, basis label) for one pair; 0.0 means no trigger."""
    if strategy == ProximityStrategy.CENTER_DISTANCE:
        if ratio <= threshold:
            return (1.0 - ratio / max(threshold, 1e-6), f"center distance ratio {ratio:.2f}")
        return (0.0, "")
    if strategy == ProximityStrategy.IOU:
        if iou >= iou_threshold or overlap >= 0.5:
            basis = (
                f"image overlap IoU {iou:.2f}"
                if iou >= iou_threshold
                else f"containment overlap {overlap:.2f}"
            )
            return (min(1.0, max(iou, overlap * 0.5) * 5.0), basis)
        return (0.0, "")
    # HYBRID: either signal triggers; the stronger one sets the score.
    if iou >= iou_threshold or overlap >= 0.5:
        basis = (
            f"image overlap IoU {iou:.2f}" if iou >= iou_threshold else f"containment overlap {overlap:.2f}"
        )
        return (min(1.0, max(iou, overlap * 0.5) * 5.0), basis)
    if ratio <= threshold:
        return (1.0 - ratio / max(threshold, 1e-6), f"center distance ratio {ratio:.2f}")
    return (0.0, "")
