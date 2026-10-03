"""Autonomous perception engine — scene, motion, lanes, depth, risk, BEV.

The engine reads V04 tracks and frames and produces relative scene
understanding. It never writes to PostgreSQL, never depends on the safety
or quality engines, and degrades every subsystem independently: an
unconfigured model reports unavailable while the rest of perception
continues. One effective profile per camera (first enabled, else global
defaults); runtime snapshots come from ``set_profiles``.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from backend.app.autonomous import motion
from backend.app.autonomous.bev import build_bev
from backend.app.autonomous.collision import MAX_COLLISION_PAIRS, CollisionRiskEngine, canonical_pair
from backend.app.autonomous.depth import DepthEstimator
from backend.app.autonomous.lanes import LaneDetector
from backend.app.autonomous.scene import SceneClassifier
from backend.app.autonomous.schemas import (
    AutonomousPerceptionEvent,
    AutonomousPerceptionResult,
    AutonomousProfile,
    AutonomousScene,
    CollisionRisk,
    DepthReading,
    EgoState,
    Lane,
    NormalizedPoint,
    PerceivedObject,
    PerceivedObjectState,
    PerceptionEventStatus,
    PerceptionEventType,
    RiskLevel,
    SceneHypothesis,
    SceneType,
    Trajectory,
)
from backend.app.autonomous.trajectory import TrajectoryEstimator
from backend.app.core.config import Settings
from backend.app.domain.frame import IngestionFrame
from backend.app.spatial.geometry import pixel_to_normalized
from backend.app.tracking.schemas import TrackedObject, TrackState

logger = logging.getLogger("industrial-vision.autonomous")


def _ema(previous: float, sample: float, alpha: float = 0.2) -> float:
    return previous + alpha * (sample - previous)


class _CameraAutonomousState:
    """Per-camera runtime state (memory only, bounded)."""

    def __init__(self, settings: Settings) -> None:
        self.profiles: dict[str, AutonomousProfile] = {}
        self.active: dict[str, AutonomousPerceptionEvent] = {}
        self.recent: deque[AutonomousPerceptionEvent] = deque(
            maxlen=settings.autonomous_max_events_per_camera
        )
        self.results: deque[AutonomousPerceptionResult] = deque(
            maxlen=settings.autonomous_max_results_per_camera
        )
        self.perceptions = 0
        self.frames_skipped = 0
        self.queue_depth = 0
        self.tracked_objects = 0
        self.last_scene_type: SceneType | None = None
        self.last_perception_at: datetime | None = None
        self.latency_ms = 0.0


class AutonomousPerceptionEngine:
    """One engine for all cameras; per-camera state stays isolated."""

    def __init__(
        self,
        settings: Settings,
        scene_classifier: SceneClassifier | None = None,
        lane_detector: LaneDetector | None = None,
        depth_estimator: DepthEstimator | None = None,
    ) -> None:
        self._settings = settings
        self._scene_classifier = scene_classifier
        self._lane_detector = lane_detector
        self._depth_estimator = depth_estimator
        self._collision = CollisionRiskEngine(risk_threshold=settings.autonomous_collision_risk_threshold)
        self._trajectory = TrajectoryEstimator(
            horizon_seconds=settings.autonomous_trajectory_horizon_seconds,
            history_points=settings.autonomous_trajectory_history_points,
        )
        self._lock = threading.RLock()
        self._cameras: dict[str, _CameraAutonomousState] = {}
        self._perception_times: deque[float] = deque(maxlen=50)

    @property
    def enabled(self) -> bool:
        return self._settings.autonomous_enabled

    @property
    def inspection_interval(self) -> int:
        return max(1, int(self._settings.autonomous_perception_interval_frames))

    def set_profiles(self, camera_id: str, profiles: list[AutonomousProfile]) -> None:
        state = self._camera_state(camera_id)
        with self._lock:
            state.profiles = {p.profile_id: p for p in profiles}

    def _camera_state(self, camera_id: str) -> _CameraAutonomousState:
        with self._lock:
            state = self._cameras.get(camera_id)
            if state is None:
                state = _CameraAutonomousState(self._settings)
                self._cameras[camera_id] = state
            return state

    def _effective_profile(self, camera_id: str, state: _CameraAutonomousState) -> AutonomousProfile:
        with self._lock:
            enabled = sorted((p for p in state.profiles.values() if p.enabled), key=lambda p: p.profile_id)
        if enabled:
            return enabled[0]
        settings = self._settings
        return AutonomousProfile(
            profile_id="default",
            camera_id=camera_id,
            name="Global defaults",
            enabled=True,
            scene_type=SceneType.UNKNOWN,
            lane_detection_enabled=settings.autonomous_lane_detection_enabled,
            depth_enabled=settings.autonomous_depth_enabled,
            trajectory_enabled=settings.autonomous_trajectory_enabled,
            collision_risk_enabled=settings.autonomous_collision_risk_enabled,
            bev_enabled=settings.autonomous_bev_enabled,
            trajectory_horizon_seconds=settings.autonomous_trajectory_horizon_seconds,
            collision_risk_threshold=settings.autonomous_collision_risk_threshold,
            collision_grace_seconds=settings.autonomous_collision_grace_seconds,
        )

    # ------------------------------------------------------------------
    # Perception pass
    # ------------------------------------------------------------------
    def process(
        self,
        camera_id: str,
        tracks: list[TrackedObject],
        frame: IngestionFrame,
        timestamp: datetime,
        frame_id: UUID | None,
    ) -> AutonomousPerceptionResult:
        """Perceive one frame. Never raises — a failed subsystem degrades."""
        started = time.perf_counter()
        state = self._camera_state(camera_id)
        scene_id = uuid4()
        profile = self._effective_profile(camera_id, state)
        width, height = self._frame_dimensions(frame)

        live = [t for t in tracks if t.state is not TrackState.REMOVED]
        live = live[: self._settings.autonomous_max_objects_per_scene]

        objects = [self._perceive_object(track, width, height) for track in live]
        by_id = {obj.object_id: obj for obj in objects}
        tracks_by_id = {track.track_id: track for track in live}

        hypothesis = self._classify(camera_id, objects, profile)
        lanes = self._detect_lanes(camera_id, frame, frame_id, profile)
        depth = self._estimate_depth(camera_id, frame, frame_id, list(by_id), profile)
        for object_id, reading in depth.items():
            obj = by_id.get(object_id)
            if obj is not None and reading.depth is not None:
                obj.relative_depth = reading.depth
                obj.depth_source = reading.source

        trajectories = (
            self._predict(tracks_by_id, objects, profile, width, height) if profile.trajectory_enabled else []
        )
        risks = self._assess_collision(objects, timestamp) if profile.collision_risk_enabled else []
        bev = build_bev(objects, lanes, trajectories, risks, timestamp) if profile.bev_enabled else None
        scene = AutonomousScene(
            scene_id=scene_id,
            camera_id=camera_id,
            frame_id=str(frame_id) if frame_id is not None else None,
            timestamp=timestamp,
            scene_type=hypothesis.scene_type,
            scene_confidence=hypothesis.confidence,
            objects=objects,
            lanes=lanes,
            ego_state=EgoState(timestamp=timestamp),
            environment={},
            metadata={"scene_reason": hypothesis.reason},
        )
        result = AutonomousPerceptionResult(
            scene_id=scene_id,
            camera_id=camera_id,
            frame_id=str(frame_id) if frame_id is not None else None,
            timestamp=timestamp,
            scene=scene,
            objects=objects,
            lanes=lanes,
            trajectories=trajectories,
            collision_risks=risks,
            bev=bev,
            processing_time_ms=round((time.perf_counter() - started) * 1000.0, 3),
            model_metadata=self._model_metadata(),
            metadata={"profile_id": profile.profile_id},
        )
        self._record(state, profile, timestamp, result, hypothesis.scene_type)
        return result

    def _frame_dimensions(self, frame: IngestionFrame) -> tuple[int, int]:
        try:
            width, height = int(frame.width), int(frame.height)
        except Exception:
            return (0, 0)
        return (width, height) if width > 0 and height > 0 else (0, 0)

    def _model_metadata(self) -> dict[str, Any]:
        def status(model: Any) -> str:
            if model is None:
                return "NOT_CONFIGURED"
            return model.state.value

        return {
            "scene_classifier": status(self._scene_classifier),
            "lane_detector": status(self._lane_detector),
            "depth_estimator": status(self._depth_estimator),
        }

    # ------------------------------------------------------------------
    # Objects + motion
    # ------------------------------------------------------------------
    def _perceive_object(self, track: TrackedObject, width: int, height: int) -> PerceivedObject:
        object_id = f"track-{track.track_id}"
        box = track.bounding_box
        center: tuple[float, float] | None = None
        bottom: tuple[float, float] | None = None
        if width > 0 and height > 0:
            try:
                center = pixel_to_normalized((box.x1 + box.x2) / 2.0, (box.y1 + box.y2) / 2.0, width, height)
                bottom = pixel_to_normalized((box.x1 + box.x2) / 2.0, box.y2, width, height)
            except ValueError:
                center = bottom = None

        velocity: motion.Velocity | None = None
        acceleration: motion.Velocity | None = None
        history = list(track.history or [])[-self._settings.autonomous_trajectory_history_points :]
        if len(history) >= 2 and width > 0 and height > 0:
            pairs = [((entry.center_x, entry.center_y), entry.timestamp) for entry in history]
            smoothed: motion.Velocity | None = None
            for (earlier_c, earlier_t), (later_c, later_t) in zip(pairs, pairs[1:]):
                sample = motion.center_velocity(earlier_c, earlier_t, later_c, later_t)
                smoothed = motion.ema_velocity(smoothed, sample)
            if smoothed is not None:
                velocity = (smoothed[0] / width, smoothed[1] / height)
            if len(pairs) >= 4:
                mid = len(pairs) // 2
                first_v: motion.Velocity | None = None
                for (earlier_c, earlier_t), (later_c, later_t) in zip(pairs[:mid], pairs[1:mid]):
                    first_v = motion.ema_velocity(
                        first_v, motion.center_velocity(earlier_c, earlier_t, later_c, later_t)
                    )
                second_v: motion.Velocity | None = None
                for (earlier_c, earlier_t), (later_c, later_t) in zip(pairs[mid:], pairs[mid + 1 :]):
                    second_v = motion.ema_velocity(
                        second_v, motion.center_velocity(earlier_c, earlier_t, later_c, later_t)
                    )
                if first_v is not None and second_v is not None:
                    raw_accel = motion.acceleration(first_v, pairs[0][1], second_v, pairs[-1][1])
                    if raw_accel is not None:
                        acceleration = (raw_accel[0] / width, raw_accel[1] / height)

        norm_speed = motion.speed(velocity)
        threshold = self._settings.autonomous_motion_speed_threshold
        if norm_speed <= threshold:
            object_state = PerceivedObjectState.STATIONARY
        elif velocity is not None and abs(velocity[0]) >= 2.0 * abs(velocity[1]):
            object_state = PerceivedObjectState.CROSSING
        else:
            areas = [
                max(0.0, (e.bounding_box.x2 - e.bounding_box.x1))
                * max(0.0, (e.bounding_box.y2 - e.bounding_box.y1))
                for e in history[-2:]
            ]
            verdict = motion.approach_state(
                areas[0] if len(areas) == 2 else None,
                areas[1] if len(areas) == 2 else None,
                None,
                None,
                norm_speed,
                threshold,
                self._settings.autonomous_approach_area_ratio,
            )
            object_state = (
                PerceivedObjectState[verdict]
                if verdict in PerceivedObjectState.__members__
                else PerceivedObjectState.UNKNOWN
            )
            if velocity is None and verdict == "MOVING":
                object_state = PerceivedObjectState.UNKNOWN

        heading = motion.movement_direction((velocity[0] * width, velocity[1] * height) if velocity else None)
        return PerceivedObject(
            object_id=object_id,
            track_id=track.track_id,
            class_id=track.class_id,
            class_name=track.class_name,
            confidence=min(1.0, max(0.0, float(track.confidence))),
            bounding_box=(
                (
                    min(1.0, max(0.0, box.x1 / width)),
                    min(1.0, max(0.0, box.y1 / height)),
                    min(1.0, max(0.0, box.x2 / width)),
                    min(1.0, max(0.0, box.y2 / height)),
                )
                if width > 0 and height > 0
                else None
            ),
            center=center,
            bottom_center=bottom,
            velocity=velocity,
            acceleration=acceleration,
            relative_position=bottom,
            heading=heading,
            object_state=object_state,
        )

    # ------------------------------------------------------------------
    # Subsystems (each degrades independently)
    # ------------------------------------------------------------------
    def _classify(
        self, camera_id: str, objects: list[PerceivedObject], profile: AutonomousProfile
    ) -> SceneHypothesis:
        classifier = self._scene_classifier
        if classifier is None:
            return SceneHypothesis(reason="no scene classifier configured")
        if profile.scene_type is not SceneType.UNKNOWN:
            return SceneHypothesis(scene_type=profile.scene_type, confidence=1.0, reason="profile override")
        try:
            if not classifier.is_ready:
                classifier.load()
            return classifier.classify(
                camera_id=camera_id,
                object_classes=[o.class_name for o in objects],
                object_count=len(objects),
                lane_count=0,
                metadata=None,
            )
        except Exception as exc:
            logger.warning("scene classification failed for %s: %s", camera_id, exc)
            return SceneHypothesis(reason=f"classifier error: {type(exc).__name__}")

    def _detect_lanes(
        self,
        camera_id: str,
        frame: IngestionFrame,
        frame_id: UUID | None,
        profile: AutonomousProfile,
    ) -> list[Lane]:
        if not profile.lane_detection_enabled:
            return []
        detector = self._lane_detector
        if detector is None:
            return []
        try:
            if not detector.is_ready:
                detector.load()
            raw_lanes = detector.detect(frame.image, camera_id=camera_id, frame_id=frame_id)
        except Exception as exc:
            logger.warning("lane detection failed for %s: %s", camera_id, exc)
            return []
        lanes: list[Lane] = []
        for index, raw in enumerate(raw_lanes):
            points = [NormalizedPoint(x=x, y=y) for x, y in raw.points]
            if len(points) < 2:
                continue
            lanes.append(
                Lane(
                    lane_id=f"lane-{index + 1}",
                    points=points,
                    confidence=min(1.0, max(0.0, float(raw.confidence))),
                    lane_type=raw.lane_type,
                    side=raw.side,
                    metadata=dict(raw.metadata),
                )
            )
        return lanes

    def _estimate_depth(
        self,
        camera_id: str,
        frame: IngestionFrame,
        frame_id: UUID | None,
        object_ids: list[str],
        profile: AutonomousProfile,
    ) -> dict[str, DepthReading]:
        estimator = self._depth_estimator
        if not profile.depth_enabled or estimator is None:
            return {oid: DepthReading() for oid in object_ids}
        try:
            if not estimator.is_ready:
                estimator.load()
            result = estimator.estimate(frame.image, object_ids, camera_id=camera_id, frame_id=frame_id)
            readings = dict(result.readings)
            for oid in object_ids:
                readings.setdefault(oid, DepthReading(source=result.source))
            return readings
        except Exception as exc:
            logger.warning("depth estimation failed for %s: %s", camera_id, exc)
            return {oid: DepthReading() for oid in object_ids}

    def _predict(
        self,
        tracks_by_id: dict[int, TrackedObject],
        objects: list[PerceivedObject],
        profile: AutonomousProfile,
        width: int,
        height: int,
    ) -> list[Trajectory]:
        estimator = TrajectoryEstimator(
            horizon_seconds=profile.trajectory_horizon_seconds,
            history_points=self._settings.autonomous_trajectory_history_points,
        )
        trajectories: list[Trajectory] = []
        for obj in objects:
            if obj.track_id is None:
                continue
            track = tracks_by_id.get(obj.track_id)
            if track is None:
                continue
            history = list(track.history or [])[-estimator.history_points :]
            if len(history) < 2 or width <= 0 or height <= 0:
                continue
            trajectory = estimator.estimate(
                obj.object_id,
                [(entry.center_x, entry.center_y) for entry in history],
                [entry.timestamp for entry in history],
                float(width),
                float(height),
            )
            if trajectory is not None:
                trajectories.append(trajectory)
        return trajectories

    def _assess_collision(self, objects: list[PerceivedObject], timestamp: datetime) -> list[CollisionRisk]:
        confirmed = [o for o in objects if o.track_id is not None]
        pairs: list[tuple[PerceivedObject, PerceivedObject]] = []
        for i, first in enumerate(confirmed):
            for second in confirmed[i + 1 :]:
                pairs.append((first, second))
                if len(pairs) >= MAX_COLLISION_PAIRS:
                    break
            if len(pairs) >= MAX_COLLISION_PAIRS:
                break
        risks: list[CollisionRisk] = []
        for first, second in pairs:
            depth_a = first.relative_depth
            depth_b = second.relative_depth
            risks.append(
                self._collision.assess_pair(
                    first.object_id,
                    second.object_id,
                    first.center,
                    second.center,
                    first.velocity,
                    second.velocity,
                    depth_a,
                    depth_b,
                    True,
                    True,
                    timestamp,
                )
            )
        return risks

    # ------------------------------------------------------------------
    # Recording: results, events, counters
    # ------------------------------------------------------------------
    def _record(
        self,
        state: _CameraAutonomousState,
        profile: AutonomousProfile,
        timestamp: datetime,
        result: AutonomousPerceptionResult,
        scene_type: SceneType,
    ) -> None:
        with self._lock:
            state.perceptions += 1
            state.tracked_objects = len(result.objects)
            state.last_perception_at = timestamp
            state.latency_ms = _ema(state.latency_ms, result.processing_time_ms)
            state.results.append(result)
            self._perception_times.append(time.monotonic())
            result.events = self._process_events(state, profile, timestamp, result, scene_type)
            state.last_scene_type = scene_type

    def _process_events(
        self,
        state: _CameraAutonomousState,
        profile: AutonomousProfile,
        timestamp: datetime,
        result: AutonomousPerceptionResult,
        scene_type: SceneType,
    ) -> list[AutonomousPerceptionEvent]:
        grace = profile.collision_grace_seconds
        touched: set[str] = set()

        for risk in result.collision_risks:
            if risk.risk_score < profile.collision_risk_threshold:
                continue
            first, second = canonical_pair(*risk.object_ids)
            key = f"COLLISION_RISK|{first}|{second}"
            touched.add(key)
            event = state.active.get(key)
            message = f"{risk.risk_level.value} collision risk {first}↔{second}: {risk.reason}"
            if risk.time_to_collision is not None:
                message += f" (TTC ~{risk.time_to_collision:.1f}s estimate)"
            if event is None:
                state.active[key] = AutonomousPerceptionEvent(
                    scene_id=result.scene_id,
                    camera_id=result.camera_id,
                    event_type=PerceptionEventType.COLLISION_RISK,
                    risk_level=risk.risk_level,
                    object_ids=[first, second],
                    confidence=risk.confidence,
                    timestamp=timestamp,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    message=message,
                    evidence={"risk_score": risk.risk_score},
                    metadata={"profile_id": profile.profile_id},
                )
            else:
                event.touch(timestamp)
                event.risk_level = risk.risk_level
                event.confidence = max(event.confidence, risk.confidence)
                event.message = message

        for obj in result.objects:
            if obj.object_state is PerceivedObjectState.APPROACHING:
                event_type = PerceptionEventType.OBJECT_APPROACH
            elif obj.object_state is PerceivedObjectState.CROSSING:
                event_type = PerceptionEventType.OBJECT_CROSSING
            else:
                continue
            key = f"{event_type.value}|{obj.object_id}"
            touched.add(key)
            if key not in state.active:
                state.active[key] = AutonomousPerceptionEvent(
                    scene_id=result.scene_id,
                    camera_id=result.camera_id,
                    event_type=event_type,
                    risk_level=RiskLevel.LOW,
                    object_ids=[obj.object_id],
                    confidence=obj.confidence,
                    timestamp=timestamp,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    message=f"{obj.class_name} {obj.object_id} {obj.object_state.value.lower()}",
                    metadata={"profile_id": profile.profile_id},
                )
            else:
                state.active[key].touch(timestamp)

        if state.last_scene_type is not None and scene_type is not state.last_scene_type:
            key = "SCENE_CHANGE"
            touched.add(key)
            if key not in state.active:
                state.active[key] = AutonomousPerceptionEvent(
                    scene_id=result.scene_id,
                    camera_id=result.camera_id,
                    event_type=PerceptionEventType.SCENE_CHANGE,
                    risk_level=RiskLevel.NONE,
                    confidence=result.scene.scene_confidence if result.scene else 0.0,
                    timestamp=timestamp,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    message=f"scene changed {state.last_scene_type.value}→{scene_type.value}",
                    metadata={"profile_id": profile.profile_id},
                )
            else:
                state.active[key].touch(timestamp)

        for key in [k for k in state.active if k not in touched]:
            event = state.active[key]
            idle = (timestamp - event.last_seen).total_seconds()
            if idle >= grace:
                event.status = PerceptionEventStatus.RESOLVED
                event.touch(event.last_seen)
                state.recent.append(event)
                del state.active[key]

        return [state.active[key] for key in touched if key in state.active]

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def latest_result(self, camera_id: str) -> AutonomousPerceptionResult | None:
        state = self._cameras.get(camera_id)
        if state is None:
            return None
        with self._lock:
            return state.results[-1] if state.results else None

    def recent_results(self, camera_id: str, limit: int = 10) -> list[AutonomousPerceptionResult]:
        state = self._cameras.get(camera_id)
        if state is None:
            return []
        with self._lock:
            return list(state.results)[-max(1, limit) :]

    def active_events(self, camera_id: str, limit: int = 50) -> list[AutonomousPerceptionEvent]:
        state = self._cameras.get(camera_id)
        if state is None:
            return []
        with self._lock:
            return list(state.active.values())[: max(1, limit)]

    def recent_events(self, camera_id: str, limit: int = 10) -> list[AutonomousPerceptionEvent]:
        state = self._cameras.get(camera_id)
        if state is None:
            return []
        with self._lock:
            return list(state.recent)[-max(1, limit) :]

    def note_skipped(self, camera_id: str) -> None:
        state = self._camera_state(camera_id)
        with self._lock:
            state.frames_skipped += 1

    def note_queue_depth(self, camera_id: str, depth: int) -> None:
        state = self._camera_state(camera_id)
        with self._lock:
            state.queue_depth = max(0, int(depth))

    def reset_camera(self, camera_id: str) -> None:
        with self._lock:
            self._cameras.pop(camera_id, None)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        with self._lock:
            cameras: dict[str, Any] = {}
            perceptions = 0
            skipped = 0
            for camera_id, state in sorted(self._cameras.items()):
                cameras[camera_id] = {
                    "profiles": len(state.profiles),
                    "perceptions": state.perceptions,
                    "last_scene_type": (state.last_scene_type.value if state.last_scene_type else None),
                    "last_perception_at": (
                        state.last_perception_at.isoformat() if state.last_perception_at else None
                    ),
                    "frames_skipped": state.frames_skipped,
                    "queue_depth": state.queue_depth,
                }
                perceptions += state.perceptions
                skipped += state.frames_skipped

            def model_status(model: Any) -> str:
                if model is None:
                    return "NOT_CONFIGURED"
                return model.state.value

            latest_at = max(
                (s.last_perception_at for s in self._cameras.values() if s.last_perception_at),
                default=None,
            )
            times = self._perception_times
            fps = 0.0
            if len(times) >= 2:
                span = times[-1] - times[0]
                if span > 0:
                    fps = round((len(times) - 1) / span, 2)
            total_latency = sum(s.latency_ms for s in self._cameras.values() if s.perceptions)
            counted = sum(1 for s in self._cameras.values() if s.perceptions)
            return {
                "enabled": self.enabled,
                "engine_status": "READY" if self.enabled else "DISABLED",
                "scene_classifier_status": model_status(self._scene_classifier),
                "lane_detector_status": model_status(self._lane_detector),
                "depth_status": model_status(self._depth_estimator),
                "trajectory_status": "READY" if self.enabled else "DISABLED",
                "collision_status": "READY" if self.enabled else "DISABLED",
                "bev_status": "READY" if self.enabled else "DISABLED",
                "active_profiles": sum(len(s.profiles) for s in self._cameras.values()),
                "active_cameras": len(self._cameras),
                "tracked_objects": sum(s.tracked_objects for s in self._cameras.values()),
                "perception_count": perceptions,
                "average_perception_ms": round(total_latency / counted, 3) if counted else 0.0,
                "last_perception_timestamp": latest_at.isoformat() if latest_at else None,
                "frames_skipped": skipped,
                "perception_fps": fps,
                "cameras": cameras,
            }
