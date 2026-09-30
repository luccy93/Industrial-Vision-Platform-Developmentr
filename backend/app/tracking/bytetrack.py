"""Native ByteTrack-compatible tracker (NumPy + SciPy, CPU-only, no new deps).

Documented behavior and intentional differences from upstream ByteTrack:
- Two-stage association (high-confidence, then low-confidence for unmatched
  tracks) with IoU cost + Hungarian assignment — the core ByteTrack idea.
- Differences: no Kalman filter (constant-position prediction = last box);
  IoU-only matching without class gating (track adopts matched class);
  no appearance/ReID embeddings; per-camera independent ID spaces.
"""

from __future__ import annotations

import logging
import math
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import numpy as np
from scipy.optimize import linear_sum_assignment

from backend.app.inference.schemas import InferenceBoundingBox, InferenceDetection
from backend.app.tracking.base import Tracker
from backend.app.tracking.schemas import (
    TrackedObject,
    TrackHistoryEntry,
    TrackState,
    TrackVelocity,
)

logger = logging.getLogger("industrial-vision.tracking")


@dataclass
class ByteTrackConfig:
    min_hits: int = 3
    max_age: int = 30
    iou_threshold: float = 0.3
    history_size: int = 30
    high_confidence: float = 0.5


def iou_matrix(tracks: np.ndarray, detections: np.ndarray) -> np.ndarray:
    """Pairwise IoU for boxes in x1,y1,x2,y2 rows. Empty-safe."""
    if tracks.shape[0] == 0 or detections.shape[0] == 0:
        return np.zeros((tracks.shape[0], detections.shape[0]))
    top_left = np.maximum(tracks[:, None, :2], detections[None, :, :2])
    bottom_right = np.minimum(tracks[:, None, 2:], detections[None, :, 2:])
    wh = np.clip(bottom_right - top_left, 0.0, None)
    inter = wh[:, :, 0] * wh[:, :, 1]
    area_t = (tracks[:, 2] - tracks[:, 0]) * (tracks[:, 3] - tracks[:, 1])
    area_d = (detections[:, 2] - detections[:, 0]) * (detections[:, 3] - detections[:, 1])
    union = area_t[:, None] + area_d[None, :] - inter
    with np.errstate(divide="ignore", invalid="ignore"):
        iou = np.where(union > 0, inter / union, 0.0)
    return iou


def _associate(cost: np.ndarray, iou_threshold: float) -> tuple[list[tuple[int, int]], list[int], list[int]]:
    """Hungarian matching; pairs below the IoU threshold are rejected."""
    if cost.size == 0:
        return [], list(range(cost.shape[0])), list(range(cost.shape[1]))
    row_ind, col_ind = linear_sum_assignment(cost)
    matches: list[tuple[int, int]] = []
    matched_rows = set()
    matched_cols = set()
    for row, col in zip(row_ind.tolist(), col_ind.tolist()):
        if 1.0 - cost[row, col] >= iou_threshold:
            matches.append((row, col))
            matched_rows.add(row)
            matched_cols.add(col)
    unmatched_rows = [r for r in range(cost.shape[0]) if r not in matched_rows]
    unmatched_cols = [c for c in range(cost.shape[1]) if c not in matched_cols]
    return matches, unmatched_rows, unmatched_cols


class _Track:
    __slots__ = (
        "id",
        "class_id",
        "class_name",
        "bbox",
        "confidence",
        "state",
        "age",
        "hits",
        "time_since_update",
        "was_confirmed",
        "center",
        "last_timestamp",
        "last_frame_id",
        "velocity",
        "history",
        "history_size",
    )

    def __init__(self, track_id: int, detection: InferenceDetection, history_size: int) -> None:
        box = detection.bounding_box
        self.id = track_id
        self.class_id = detection.class_id
        self.class_name = detection.class_name
        self.bbox = (box.x1, box.y1, box.x2, box.y2)
        self.confidence = detection.confidence
        self.state = TrackState.TENTATIVE
        self.age = 1
        self.hits = 1
        self.time_since_update = 0
        self.was_confirmed = False
        self.center = ((box.x1 + box.x2) / 2.0, (box.y1 + box.y2) / 2.0)
        self.last_timestamp = detection.timestamp
        self.last_frame_id = detection.frame_id
        self.velocity = TrackVelocity()
        self.history_size = history_size
        self.history: deque[TrackHistoryEntry] = deque(maxlen=history_size)
        self._push_history(detection)

    def _push_history(self, detection: InferenceDetection) -> None:
        box = detection.bounding_box
        self.history.append(
            TrackHistoryEntry(
                timestamp=detection.timestamp,
                frame_id=detection.frame_id,
                bounding_box=InferenceBoundingBox(x1=box.x1, y1=box.y1, x2=box.x2, y2=box.y2),
                confidence=detection.confidence,
                center_x=(box.x1 + box.x2) / 2.0,
                center_y=(box.y1 + box.y2) / 2.0,
            )
        )

    def update(self, detection: InferenceDetection, min_hits: int) -> None:
        box = detection.bounding_box
        new_center = ((box.x1 + box.x2) / 2.0, (box.y1 + box.y2) / 2.0)
        try:
            dt = (detection.timestamp - self.last_timestamp).total_seconds()
        except Exception:
            dt = 0.0
        if dt > 0:
            vx = (new_center[0] - self.center[0]) / dt
            vy = (new_center[1] - self.center[1]) / dt
            self.velocity = TrackVelocity(x=vx, y=vy, speed=math.hypot(vx, vy))
        self.bbox = (box.x1, box.y1, box.x2, box.y2)
        self.confidence = detection.confidence
        self.class_id = detection.class_id
        self.class_name = detection.class_name
        self.center = new_center
        self.last_timestamp = detection.timestamp
        self.last_frame_id = detection.frame_id
        self.hits += 1
        self.time_since_update = 0
        if self.was_confirmed or self.hits >= min_hits:
            self.state = TrackState.CONFIRMED
            self.was_confirmed = True
        else:
            self.state = TrackState.TENTATIVE
        self._push_history(detection)

    def snapshot(self, camera_id: str, frame_id: UUID, timestamp: datetime) -> TrackedObject:
        x1, y1, x2, y2 = self.bbox
        return TrackedObject(
            track_id=self.id,
            camera_id=camera_id,
            class_id=self.class_id,
            class_name=self.class_name,
            confidence=self.confidence,
            bounding_box=InferenceBoundingBox(x1=x1, y1=y1, x2=x2, y2=y2),
            timestamp=timestamp,
            frame_id=frame_id,
            state=self.state,
            age=self.age,
            hits=self.hits,
            time_since_update=self.time_since_update,
            velocity=self.velocity,
            history=list(self.history),
        )


class ByteTrackTracker(Tracker):
    """Two-stage IoU association tracker with explicit track lifecycle."""

    def __init__(self, camera_id: str, config: ByteTrackConfig | None = None) -> None:
        super().__init__("bytetrack-native", camera_id)
        self.config = config or ByteTrackConfig()
        self._tracks: dict[int, _Track] = {}
        self._next_id = 1
        self._created = 0
        self._removed = 0
        self._processed = 0

    def reset(self) -> None:
        self._tracks.clear()
        self._next_id = 1

    def _live(self) -> list[_Track]:
        return [t for t in self._tracks.values() if t.state != TrackState.REMOVED]

    def update(
        self,
        detections: list[InferenceDetection],
        frame_id: UUID,
        timestamp: datetime,
    ) -> list[TrackedObject]:
        cfg = self.config
        self._processed += len(detections)
        live = self._live()
        for track in live:
            track.age += 1
            track.time_since_update += 1

        high = [d for d in detections if d.confidence >= cfg.high_confidence]
        low = [d for d in detections if d.confidence < cfg.high_confidence]
        track_boxes = np.array([t.bbox for t in live], dtype=float) if live else np.zeros((0, 4))

        def _boxes(dets: list[InferenceDetection]) -> np.ndarray:
            if not dets:
                return np.zeros((0, 4))
            return np.array(
                [[d.bounding_box.x1, d.bounding_box.y1, d.bounding_box.x2, d.bounding_box.y2] for d in dets],
                dtype=float,
            )

        # Stage 1: high-confidence detections ↔ all live tracks.
        cost = 1.0 - iou_matrix(track_boxes, _boxes(high))
        matches, unmatched_tracks, unmatched_high = _associate(cost, cfg.iou_threshold)

        # Stage 2: low-confidence detections ↔ still-unmatched tracks.
        low_candidates = [live[i] for i in unmatched_tracks]
        low_boxes = (
            np.array([t.bbox for t in low_candidates], dtype=float) if low_candidates else np.zeros((0, 4))
        )
        cost2 = 1.0 - iou_matrix(low_boxes, _boxes(low))
        matches2, still_unmatched, _leftover_low = _associate(cost2, cfg.iou_threshold)

        for track_idx, det_idx in matches:
            live[track_idx].update(high[det_idx], cfg.min_hits)
        for local_idx, det_idx in matches2:
            low_candidates[local_idx].update(low[det_idx], cfg.min_hits)

        # New tracks from unmatched HIGH-confidence detections only.
        matched_high = {det_idx for _, det_idx in matches}
        for det_idx in unmatched_high:
            if det_idx in matched_high:
                continue
            detection = high[det_idx]
            track = _Track(self._next_id, detection, cfg.history_size)
            self._next_id += 1
            self._created += 1
            if track.hits >= cfg.min_hits:
                track.state = TrackState.CONFIRMED
                track.was_confirmed = True
            self._tracks[track.id] = track

        # Missed tracks → LOST → REMOVED past max_age.
        missed_ids = {unmatched_tracks[i] for i in still_unmatched}
        for idx in missed_ids:
            track = live[idx]
            # time_since_update already bumped above; mark LOST once more is harmless.
            if track.state in (TrackState.TENTATIVE, TrackState.CONFIRMED):
                track.state = TrackState.LOST
            if track.time_since_update > cfg.max_age:
                track.state = TrackState.REMOVED
                self._removed += 1
        self._tracks = {tid: t for tid, t in self._tracks.items() if t.state != TrackState.REMOVED}

        return [
            t.snapshot(self.camera_id, frame_id, timestamp)
            for t in self._tracks.values()
            if t.state != TrackState.REMOVED
        ]

    def active_tracks(self) -> list[TrackedObject]:
        return [t.snapshot(self.camera_id, t.last_frame_id, t.last_timestamp) for t in self._live()]

    @property
    def stats(self) -> dict:
        live = self._live()
        confirmed = sum(1 for t in live if t.state == TrackState.CONFIRMED)
        tentative = sum(1 for t in live if t.state == TrackState.TENTATIVE)
        lost = sum(1 for t in live if t.state == TrackState.LOST)
        ages = [t.age for t in live]
        return {
            "active_tracks": len(live),
            "confirmed_tracks": confirmed,
            "tentative_tracks": tentative,
            "lost_tracks": lost,
            "created_tracks": self._created,
            "removed_tracks": self._removed,
            "average_track_age": round(sum(ages) / len(ages), 2) if ages else 0.0,
            "detections_processed": self._processed,
        }
