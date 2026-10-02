"""Spatial engine interfaces — zone registry + stateless membership queries.

Runtime transition/dwell/proximity processing lands in Commit 02; this module
establishes the per-camera isolated state containers and the pure membership
primitives the runtime builds on.
"""

from __future__ import annotations

import logging
import threading

from backend.app.spatial import geometry
from backend.app.spatial.schemas import (
    SafetyZone,
    ZoneMembership,
    ZoneTrackState,
    ZoneTransition,
)

logger = logging.getLogger("industrial-vision.spatial")


# Tracked-object protocol: anything with bounding_box.x1/y1/x2/y2 + track_id.
class SpatialEngine:
    """Camera-isolated zone registry with pure membership queries."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._zones: dict[str, dict[str, SafetyZone]] = {}
        self._states: dict[tuple[str, str, int], ZoneTrackState] = {}

    # -- zone registry (mirrors DB configuration) -------------------------
    def set_zones(self, camera_id: str, zones: list[SafetyZone]) -> None:
        with self._lock:
            self._zones[camera_id] = {zone.zone_id: zone for zone in zones}

    def remove_camera(self, camera_id: str) -> None:
        with self._lock:
            self._zones.pop(camera_id, None)
            for key in [k for k in self._states if k[0] == camera_id]:
                del self._states[key]

    def remove_zone(self, camera_id: str, zone_id: str) -> None:
        with self._lock:
            self._zones.get(camera_id, {}).pop(zone_id, None)
            for key in [k for k in self._states if k[0] == camera_id and k[1] == zone_id]:
                del self._states[key]

    def zones_for(self, camera_id: str, enabled_only: bool = True) -> list[SafetyZone]:
        with self._lock:
            zones = list(self._zones.get(camera_id, {}).values())
        if enabled_only:
            zones = [z for z in zones if z.enabled]
        return zones

    def camera_count(self) -> int:
        with self._lock:
            return len(self._zones)

    def zone_count(self) -> int:
        with self._lock:
            return sum(len(zones) for zones in self._zones.values())

    # -- pure membership ---------------------------------------------------
    @staticmethod
    def anchor_point(
        box: tuple[float, float, float, float], frame_width: float, frame_height: float
    ) -> tuple[float, float]:
        """Bottom-center in *normalized* coordinates (ground-contact heuristic)."""
        cx, bottom = geometry.bbox_bottom_center(box)
        return (
            min(1.0, max(0.0, cx / frame_width)) if frame_width > 0 else 0.0,
            min(1.0, max(0.0, bottom / frame_height)) if frame_height > 0 else 0.0,
        )

    @staticmethod
    def is_inside(zone: SafetyZone, point: tuple[float, float]) -> bool:
        polygon = [(p.x, p.y) for p in zone.polygon]
        return geometry.point_in_polygon(point[0], point[1], polygon)

    def membership(
        self,
        camera_id: str,
        zone_id: str,
        track_id: int,
        inside: bool,
    ) -> ZoneMembership:
        return ZoneMembership(camera_id=camera_id, zone_id=zone_id, track_id=track_id, inside=inside)

    def classify_transition(self, was_inside: bool, is_inside: bool) -> ZoneTransition:
        if not was_inside and is_inside:
            return ZoneTransition.ENTRY
        if was_inside and not is_inside:
            return ZoneTransition.EXIT
        if is_inside:
            return ZoneTransition.STATIONARY_INSIDE
        return ZoneTransition.STATIONARY_OUTSIDE

    def state_count(self) -> int:
        with self._lock:
            return len(self._states)
