"""Tracking manager — one isolated tracker per camera + runtime metrics."""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from uuid import UUID

from backend.app.core.config import Settings
from backend.app.inference.schemas import InferenceDetection
from backend.app.tracking.base import Tracker
from backend.app.tracking.bytetrack import ByteTrackConfig, ByteTrackTracker
from backend.app.tracking.schemas import TrackedObject

logger = logging.getLogger("industrial-vision.tracking")


def _ema(previous: float, sample: float, alpha: float = 0.2) -> float:
    return sample if previous <= 0 else (1.0 - alpha) * previous + alpha * sample


class TrackingManager:
    """Owns per-camera trackers; state never leaks across cameras."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._trackers: dict[str, Tracker] = {}
        self._latency_ms = 0.0
        self._fps = 0.0
        self._updates = 0
        self._errors = 0
        self._last_error: str | None = None

    def _config(self) -> ByteTrackConfig:
        settings = self._settings
        return ByteTrackConfig(
            min_hits=settings.track_min_hits,
            max_age=settings.track_max_age,
            iou_threshold=settings.track_iou_threshold,
            history_size=settings.track_history_size,
            high_confidence=settings.track_high_conf,
        )

    def tracker_for(self, camera_id: str) -> Tracker:
        with self._lock:
            tracker = self._trackers.get(camera_id)
            if tracker is None:
                tracker = ByteTrackTracker(camera_id, self._config())
                self._trackers[camera_id] = tracker
            return tracker

    def reset_camera(self, camera_id: str) -> None:
        """Drop a camera's tracker state (stream restart → IDs restart at 1)."""
        with self._lock:
            tracker = self._trackers.pop(camera_id, None)
        if tracker is not None:
            try:
                tracker.reset()
            except Exception:
                logger.debug("tracker reset failed for %s", camera_id, exc_info=True)

    def update(
        self,
        camera_id: str,
        detections: list[InferenceDetection],
        frame_id: UUID,
        timestamp: datetime,
    ) -> list[TrackedObject]:
        """Associate one frame; tracking failures are isolated and reported."""
        started = time.perf_counter()
        try:
            tracks = self.tracker_for(camera_id).update(detections, frame_id, timestamp)
        except Exception as exc:
            with self._lock:
                self._errors += 1
                self._last_error = f"{type(exc).__name__}: {exc}"
            logger.warning("tracking failed for %s: %s", camera_id, exc)
            return []
        latency_ms = (time.perf_counter() - started) * 1000.0
        with self._lock:
            self._updates += 1
            self._latency_ms = _ema(self._latency_ms, latency_ms)
            self._fps = 1000.0 / self._latency_ms if self._latency_ms > 0 else 0.0
        return tracks

    def active_tracks(self, camera_id: str) -> list[TrackedObject]:
        tracker = self._trackers.get(camera_id)
        return tracker.active_tracks() if tracker else []

    def status(self) -> dict:
        with self._lock:
            cameras = list(self._trackers.keys())
            updates, errors = self._updates, self._errors
            fps, latency, last_error = self._fps, self._latency_ms, self._last_error
        active = confirmed = tentative = lost = created = removed = 0
        ages: list[float] = []
        processed = 0
        for camera_id in cameras:
            stats = self._trackers[camera_id].stats
            active += stats["active_tracks"]
            confirmed += stats["confirmed_tracks"]
            tentative += stats["tentative_tracks"]
            lost += stats["lost_tracks"]
            created += stats["created_tracks"]
            removed += stats["removed_tracks"]
            processed += stats["detections_processed"]
            ages.append(stats["average_track_age"])
        return {
            "tracker": "bytetrack-native",
            "algorithm": "ByteTrack-compatible (IoU + Hungarian, NumPy/SciPy, CPU)",
            "active_cameras": len(cameras),
            "active_tracks": active,
            "confirmed_tracks": confirmed,
            "tentative_tracks": tentative,
            "lost_tracks": lost,
            "created_tracks": created,
            "removed_tracks": removed,
            "average_track_age": round(sum(ages) / len(ages), 2) if ages else 0.0,
            "detections_processed": processed,
            "tracking_updates": updates,
            "tracking_fps": round(fps, 2),
            "average_latency_ms": round(latency, 2),
            "errors": errors,
            "last_error": last_error,
        }
