"""Inference worker — per-camera thread turning frames into detections.

Backpressure strategy (documented choice): the worker pulls the *latest*
frame from the V02 stream buffer and pushes it into a small bounded queue
(``drop_oldest`` on overflow). When inference is slower than capture, stale
frames are discarded and only the freshest image is analyzed — recent frames
win over stale ones, and queue memory stays constant. A failed inference
increments ``errors`` and never terminates the stream or the worker.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from backend.app.domain.frame import IngestionFrame
from backend.app.inference.base import ModelError
from backend.app.inference.manager import ModelManager
from backend.app.inference.schemas import InferenceResult
from backend.app.safety.engine import SafetyEngine
from backend.app.tracking.manager import TrackingManager

logger = logging.getLogger("industrial-vision.inference")

FrameSource = Callable[[], IngestionFrame | None]


class InferenceWorker:
    """One worker thread per camera: queue → model → results ring.

    V04 adds an inline tracking stage after each inference result. Tracking
    runs in the same worker thread (sub-millisecond vs millisecond-scale
    inference) rather than a separate thread pool — no extra queues, no extra
    threads, still never on the FastAPI event loop.
    """

    def __init__(
        self,
        camera_id: str,
        model_manager: ModelManager,
        frame_source: FrameSource,
        queue_size: int = 4,
        poll_interval: float = 0.05,
        results_size: int = 30,
        tracking_manager: TrackingManager | None = None,
        safety_engine: SafetyEngine | None = None,
        quality_engine: Any = None,
        autonomous_engine: Any = None,
        intelligence_engine: Any = None,
        incident_manager: Any = None,
        event_bus: Any = None,
    ) -> None:
        self.camera_id = camera_id
        self._model_manager = model_manager
        self._frame_source = frame_source
        self._tracking_manager = tracking_manager
        self._safety_engine = safety_engine
        self._quality_engine = quality_engine
        self._autonomous_engine = autonomous_engine
        self._intelligence_engine = intelligence_engine
        self._incident_manager = incident_manager
        self._event_bus = event_bus
        # V12 bus publish state: (event identity → last published status),
        # mirroring the WS delta dictionaries. Bounded; pruned on growth.
        self._bus_published: dict[str, str] = {}
        self._bus_origin = f"worker:{camera_id}"
        self._queue: queue.Queue[IngestionFrame] = queue.Queue(maxsize=queue_size)
        self._poll_interval = poll_interval
        self._results: deque[InferenceResult] = deque(maxlen=results_size)
        self._tracks: list = []
        self._tracked_frame_id: object = None
        self._frame_width: float = 0.0
        self._frame_height: float = 0.0
        self._safety_new: list = []
        self._safety_active: list = []
        self._quality_latest: list = []
        self._quality_frames = 0
        self._quality_skipped = 0
        self._autonomous_latest: object = None
        self._autonomous_frames = 0
        self._autonomous_skipped = 0
        self._intelligence_latest: object = None
        self._incident_syncs = 0
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._running = False
        self._queued = 0
        self._dropped = 0
        self._errors = 0
        self._last_error: str | None = None
        self._load_retry_at = 0.0
        # V11 supervision: monotonic heartbeat (stale detection) + tz-aware
        # exposure derived from it (never wall-clock comparisons).
        self._heartbeat_monotonic: float | None = None

    @property
    def running(self) -> bool:
        with self._lock:
            return self._running

    def start(self) -> bool:
        with self._lock:
            if self._running:
                return True
            self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name=f"infer-{self.camera_id}", daemon=True)
        self._thread.start()
        return True

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            self._running = False
        self._stop_event.set()
        thread, self._thread = self._thread, None
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=timeout)
        with self._lock:
            self._running = False

    def submit(self, frame: IngestionFrame) -> bool:
        """Non-blocking enqueue; False when a stale frame was dropped."""
        with self._lock:
            self._queued += 1
        try:
            self._queue.put_nowait(frame)
            return True
        except queue.Full:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            with self._lock:
                self._dropped += 1
            try:
                self._queue.put_nowait(frame)
            except queue.Full:
                return False
            return False

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._heartbeat_monotonic = time.monotonic()
            try:
                frame = self._frame_source()
            except Exception:
                logger.debug("frame source failed for %s", self.camera_id, exc_info=True)
                self._sleep(self._poll_interval)
                continue
            if frame is None:
                self._sleep(self._poll_interval)
                continue
            self.submit(frame)
            try:
                item = self._queue.get(timeout=self._poll_interval)
            except queue.Empty:
                continue
            self._infer(item)

    def _infer(self, frame: IngestionFrame) -> None:
        try:
            result = self._model_manager.infer(frame.image, camera_id=self.camera_id, frame_id=frame.frame_id)
        except ModelError as exc:
            with self._lock:
                self._errors += 1
                self._last_error = f"{type(exc).__name__}: {exc}"
            logger.warning("inference failed for %s: %s", self.camera_id, exc)
            # Back off on persistent load failures (e.g. missing weights).
            now = time.time()
            if now >= self._load_retry_at:
                self._load_retry_at = now + 5.0
            self._sleep(0.5)
            return
        except Exception as exc:
            with self._lock:
                self._errors += 1
                self._last_error = f"{type(exc).__name__}: {exc}"
            logger.exception("unexpected inference failure for %s", self.camera_id)
            return
        with self._lock:
            self._results.append(result)
            self._last_error = None
        self._track(result, frame)

    def _track(self, result: InferenceResult, frame: IngestionFrame) -> None:
        """V04 stage: associate detections into tracks (isolated failures)."""
        manager = self._tracking_manager
        if manager is None:
            return
        try:
            tracks = manager.update(self.camera_id, result.detections, result.frame_id, result.timestamp)
        except Exception as exc:
            logger.warning("tracking failed for %s: %s", self.camera_id, exc)
            return
        with self._lock:
            self._tracks = tracks
            self._tracked_frame_id = result.frame_id
            # V06 spatial reasoning needs a reference frame size to map pixel
            # boxes into normalized zone space.
            height, width = frame.image.shape[:2]
            self._frame_width = float(width)
            self._frame_height = float(height)
        self._analyze_safety(tracks, result)
        self._analyze_quality(frame, result)
        self._analyze_autonomous(tracks, frame, result)
        self._analyze_intelligence(result)
        self._sync_incidents(result)

    def _analyze_safety(self, tracks: list, result: InferenceResult) -> None:
        """V05 stage: tracking output → safety events (isolated failures)."""
        engine = self._safety_engine
        if engine is None:
            return
        try:
            with self._lock:
                width, height = self._frame_width, self._frame_height
            analysis = engine.process(
                self.camera_id, tracks, result.timestamp, frame_width=width, frame_height=height
            )
        except Exception as exc:
            logger.warning("safety analysis failed for %s: %s", self.camera_id, exc)
            return
        with self._lock:
            self._safety_new = list(analysis.new_events)
            self._safety_active = list(analysis.active_events)
        self._publish_safety_events(list(analysis.new_events) + list(analysis.active_events))

    def _analyze_quality(self, frame: IngestionFrame, result: InferenceResult) -> None:
        """V07 stage: frame → quality inspection (sampled, isolated failures).

        Inspection runs on the same worker thread as tracking/safety but only
        every Nth frame (``QUALITY_INSPECTION_INTERVAL_FRAMES``) so it can
        never block the pipeline; skipped frames are counted, never queued.
        """
        engine = self._quality_engine
        if engine is None or not engine.enabled:
            return
        try:
            with self._lock:
                self._quality_frames += 1
                interval = engine.inspection_interval
                due = self._quality_frames % interval == 0
            if not due:
                with self._lock:
                    self._quality_skipped += 1
                engine.note_skipped(self.camera_id)
                return
            results = engine.process(self.camera_id, frame, result.timestamp, frame.frame_id)
            engine.note_queue_depth(self.camera_id, self._queue.qsize())
        except Exception as exc:
            logger.warning("quality inspection failed for %s: %s", self.camera_id, exc)
            return
        with self._lock:
            self._quality_latest = list(results)
        self._publish_quality_events(list(results))

    def _analyze_autonomous(self, tracks: list, frame: IngestionFrame, result: InferenceResult) -> None:
        """V08 stage: tracks + frame → autonomous perception (sampled, isolated).

        Perception runs on the same worker thread but only every Nth frame
        (``AUTONOMOUS_PERCEPTION_INTERVAL_FRAMES``); skipped frames are
        counted, never queued. A failed subsystem degrades inside the engine —
        this stage only isolates engine-level failures from the pipeline.
        """
        engine = self._autonomous_engine
        if engine is None or not engine.enabled:
            return
        try:
            with self._lock:
                self._autonomous_frames += 1
                interval = engine.inspection_interval
                due = self._autonomous_frames % interval == 0
            if not due:
                with self._lock:
                    self._autonomous_skipped += 1
                engine.note_skipped(self.camera_id)
                return
            perceived = engine.process(self.camera_id, tracks, frame, result.timestamp, frame.frame_id)
            engine.note_queue_depth(self.camera_id, self._queue.qsize())
        except Exception as exc:
            logger.warning("autonomous perception failed for %s: %s", self.camera_id, exc)
            return
        with self._lock:
            self._autonomous_latest = perceived
        self._publish_autonomous_events()

    def _analyze_intelligence(self, result: InferenceResult) -> None:
        """V09 stage: domain events → unified intelligence (isolated failures).

        Correlation and scoring run on the same worker thread over the
        already-produced domain event state — no frames, models, or queues.
        """
        engine = self._intelligence_engine
        if engine is None or not engine.enabled:
            return
        try:
            intel = engine.process(self.camera_id, result.timestamp)
        except Exception as exc:
            logger.warning("intelligence analysis failed for %s: %s", self.camera_id, exc)
            return
        with self._lock:
            self._intelligence_latest = intel
        self._publish_intelligence_events(intel)

    # ------------------------------------------------------------------
    # V12 event-bus publication (additive, isolated, never blocking).
    #
    # Only new or status-changed genuine events publish — never frames,
    # detections, tracks, or telemetry. With no bus (or a local bus with
    # no subscribers) every hook returns after two attribute reads.
    # ------------------------------------------------------------------
    def _bus_active(self) -> bool:
        bus = self._event_bus
        if bus is None:
            return False
        try:
            if not bus.is_distributed and bus.subscription_count() == 0:
                return False
        except Exception:
            return False
        return True

    def _publish_resolved(self, resolved: list[tuple[str, str, str, str, Any, dict[str, Any]]]) -> None:
        """Publish pre-resolved (key, status, type, domain, ts, payload)."""
        try:
            from backend.app.domain.common import utcnow as _utcnow
            from backend.app.events.envelope import EventEnvelope

            bus = self._event_bus
            if bus is None:
                return
            for key, status, message_type, domain, timestamp, payload in resolved:
                marker = f"{key}:{status}"
                if self._bus_published.get(marker) == message_type:
                    continue
                self._bus_published[marker] = message_type
                envelope = EventEnvelope(
                    event_id=marker,
                    event_type=message_type,
                    domain=domain,
                    camera_id=self.camera_id,
                    timestamp=timestamp or _utcnow(),
                    origin=self._bus_origin,
                    payload=dict(payload),
                )
                bus.publish(envelope)
            if len(self._bus_published) > 2000:
                oldest = list(self._bus_published)[:1000]
                for stale in oldest:
                    self._bus_published.pop(stale, None)
        except Exception as exc:
            logger.warning("event bus publish failed for %s: %s", self.camera_id, exc)

    @staticmethod
    def _event_status(event: Any) -> str:
        status = getattr(event, "status", None)
        return str(getattr(status, "value", status or "ACTIVE"))

    @staticmethod
    def _event_timestamp(event: Any) -> Any:
        return getattr(event, "timestamp", None)

    def _publish_safety_events(self, events: list) -> None:
        """V05/V06 safety + spatial events (rule-routed wire types)."""
        if not self._bus_active():
            return
        resolved: list[tuple[str, str, str, str, Any, dict[str, Any]]] = []
        for event in events:
            try:
                rule = str((getattr(event, "metadata", None) or {}).get("rule", ""))
                if rule == "restricted_zone":
                    message_type, domain = "zone_event", "SPATIAL"
                elif rule == "proximity_relationships":
                    message_type, domain = "proximity_event", "SPATIAL"
                else:
                    message_type, domain = "safety_event", "SAFETY"
                payload = event.to_websocket()
                if not isinstance(payload, dict):
                    continue
                resolved.append(
                    (
                        f"SAFETY:{event.event_id}",
                        self._event_status(event),
                        message_type,
                        domain,
                        self._event_timestamp(event),
                        payload,
                    )
                )
            except Exception:
                continue
        self._publish_resolved(resolved)

    def _publish_quality_events(self, results: list) -> None:
        """V07 quality decisions (events + new inspection results)."""
        if not self._bus_active():
            return
        try:
            from backend.app.quality.ws import (
                quality_event_message,
                quality_result_message,
            )
        except Exception:
            return
        engine = self._quality_engine
        resolved: list[tuple[str, str, str, str, Any, dict[str, Any]]] = []
        for result in results:
            try:
                key = f"QUALITY:{result.inspection_id}"
                payload = quality_result_message(self.camera_id, result)
                resolved.append((key, "RESULT", "quality_result", "QUALITY", None, payload))
            except Exception:
                continue
        if engine is not None:
            try:
                candidates = list(engine.active_events(self.camera_id, 50)) + list(
                    engine.recent_events(self.camera_id, 10)
                )
            except Exception:
                candidates = []
            for event in candidates:
                try:
                    payload = quality_event_message(self.camera_id, event)
                    resolved.append(
                        (
                            f"QUALITY:{event.event_id}",
                            self._event_status(event),
                            "quality_event",
                            "QUALITY",
                            self._event_timestamp(event),
                            payload,
                        )
                    )
                except Exception:
                    continue
        self._publish_resolved(resolved)

    def _publish_autonomous_events(self) -> None:
        """V08 collision-risk + lane events (scene summaries excluded)."""
        if not self._bus_active():
            return
        try:
            from backend.app.autonomous.ws import collision_risk_message, lane_event_message
        except Exception:
            return
        engine = self._autonomous_engine
        if engine is None:
            return
        try:
            candidates = list(engine.active_events(self.camera_id, 50)) + list(
                engine.recent_events(self.camera_id, 10)
            )
        except Exception:
            return
        resolved: list[tuple[str, str, str, str, Any, dict[str, Any]]] = []
        for event in candidates:
            try:
                if str(getattr(getattr(event, "event_type", None), "value", "")) == "COLLISION_RISK":
                    message_type = "collision_risk"
                    payload = collision_risk_message(self.camera_id, event)
                else:
                    message_type = "lane_event"
                    payload = lane_event_message(self.camera_id, event)
                resolved.append(
                    (
                        f"AUTONOMOUS:{event.event_id}",
                        self._event_status(event),
                        message_type,
                        "AUTONOMOUS",
                        self._event_timestamp(event),
                        payload,
                    )
                )
            except Exception:
                continue
        self._publish_resolved(resolved)

    def _publish_intelligence_events(self, intel: Any) -> None:
        """V09 unified events + cluster updates + risk summary changes."""
        if not self._bus_active():
            return
        try:
            from backend.app.intelligence.ws import (
                intelligence_event_message,
                risk_cluster_message,
                risk_update_message,
            )
        except Exception:
            return
        resolved: list[tuple[str, str, str, str, Any, dict[str, Any]]] = []
        for event in list(getattr(intel, "events", []) or []):
            try:
                domain = str(getattr(getattr(event, "source_domain", None), "value", "INTELLIGENCE"))
                resolved.append(
                    (
                        f"INTELLIGENCE:{event.event_id}",
                        self._event_status(event),
                        "intelligence_event",
                        domain,
                        self._event_timestamp(event),
                        intelligence_event_message(self.camera_id, event),
                    )
                )
            except Exception:
                continue
        for cluster in list(getattr(intel, "clusters", []) or []):
            try:
                assessment = cluster.risk_assessment
                version = f"{cluster.status.value}:{assessment.risk_level.value}"
                resolved.append(
                    (
                        f"CLUSTER:{cluster.cluster_id}:{version}",
                        cluster.status.value,
                        "risk_cluster",
                        "INTELLIGENCE",
                        getattr(cluster, "last_seen", None),
                        risk_cluster_message(self.camera_id, cluster),
                    )
                )
            except Exception:
                continue
        try:
            highest = getattr(intel, "highest_risk", None)
            priority = getattr(intel, "highest_priority", None)
            if highest is not None and priority is not None:
                signature = f"{highest.risk_level.value}:{priority.value}"
                stamp = getattr(intel, "timestamp", None)
                stamp_text = stamp.isoformat() if isinstance(stamp, datetime) else str(stamp or "")
                payload = risk_update_message(self.camera_id, highest, priority, stamp_text)
                resolved.append(("RISK:summary", signature, "risk_update", "INTELLIGENCE", None, payload))
        except Exception:
            pass
        self._publish_resolved(resolved)

    def _sync_incidents(self, result: InferenceResult) -> None:
        """V10 stage: V09 intelligence → incident sync (isolated failures).

        IncidentManager debounces internally (skips cameras with no new
        intelligence output) and writes only on meaningful change, so this
        stage never becomes a high-frequency database writer.
        """
        manager = self._incident_manager
        if manager is None or not manager.enabled:
            return
        try:
            manager.sync_camera(self.camera_id, result.timestamp)
        except Exception as exc:
            logger.warning("incident sync failed for %s: %s", self.camera_id, exc)
            return
        with self._lock:
            self._incident_syncs += 1

    def _sleep(self, seconds: float) -> None:
        self._stop_event.wait(seconds)

    def latest(self) -> InferenceResult | None:
        with self._lock:
            return self._results[-1] if self._results else None

    def latest_tracked(self) -> tuple[object, list]:
        """(frame_id, tracks) of the most recently tracked result."""
        with self._lock:
            return self._tracked_frame_id, list(self._tracks)

    def latest_safety(self) -> tuple[list, list]:
        """(new_events, active_events) from the latest safety pass."""
        with self._lock:
            return list(self._safety_new), list(self._safety_active)

    def latest_quality(self) -> list:
        """Inspection results from the latest quality pass."""
        with self._lock:
            return list(self._quality_latest)

    def latest_perception(self) -> object:
        """Perception result from the latest autonomous pass (or None)."""
        with self._lock:
            return self._autonomous_latest

    def latest_intelligence(self) -> object:
        """Risk intelligence from the latest V09 pass (or None)."""
        with self._lock:
            return self._intelligence_latest

    def recent(self, limit: int = 10) -> list[InferenceResult]:
        with self._lock:
            items = list(self._results)[-max(1, limit) :]
            return list(items)

    def stats(self) -> dict:
        with self._lock:
            return {
                "camera_id": self.camera_id,
                "running": self._running,
                "queued": self._queued,
                "dropped": self._dropped,
                "errors": self._errors,
                "results_held": len(self._results),
                "last_error": self._last_error,
                "quality_frames": self._quality_frames,
                "quality_skipped": self._quality_skipped,
                "quality_results_held": len(self._quality_latest),
                "autonomous_frames": self._autonomous_frames,
                "autonomous_skipped": self._autonomous_skipped,
                "autonomous_result_held": self._autonomous_latest is not None,
                "intelligence_result_held": self._intelligence_latest is not None,
                "incident_syncs": self._incident_syncs,
            }

    def health_snapshot(self) -> dict:
        """V11 supervision snapshot (additive; existing behavior unchanged)."""
        from backend.app.domain.common import utcnow

        with self._lock:
            running = self._running
            heartbeat = self._heartbeat_monotonic
            last_error = self._last_error
        state = "RUNNING" if running else "STOPPED"
        last_heartbeat = None
        if heartbeat is not None:
            age = max(0.0, time.monotonic() - heartbeat)
            last_heartbeat = utcnow() - timedelta(seconds=age)
        return {
            "name": f"inference:{self.camera_id}",
            "state": state,
            "running": running,
            "last_heartbeat": last_heartbeat.isoformat() if last_heartbeat else None,
            "last_error": last_error,
        }


class InferenceSupervisor:
    """Coordinates one inference worker per camera."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._workers: dict[str, InferenceWorker] = {}

    def attach(
        self,
        camera_id: str,
        model_manager: ModelManager,
        frame_source: FrameSource,
        **kwargs: object,
    ) -> InferenceWorker:
        with self._lock:
            existing = self._workers.get(camera_id)
            if existing is not None:
                return existing
            worker = InferenceWorker(
                camera_id,
                model_manager,
                frame_source,
                **kwargs,  # type: ignore[arg-type]
            )
            self._workers[camera_id] = worker
            return worker

    def get(self, camera_id: str) -> InferenceWorker | None:
        with self._lock:
            return self._workers.get(camera_id)

    def detach(self, camera_id: str) -> bool:
        with self._lock:
            worker = self._workers.pop(camera_id, None)
        if worker is None:
            return False
        try:
            worker.stop()
        except Exception:
            logger.debug("worker stop failed during detach", exc_info=True)
        return True

    def worker_count(self) -> int:
        with self._lock:
            return len(self._workers)

    def health_snapshots(self) -> dict[str, dict]:
        """V11 supervision snapshots keyed by camera_id (additive)."""
        with self._lock:
            workers = dict(self._workers)
        snapshots: dict[str, dict] = {}
        for camera_id, worker in workers.items():
            try:
                snapshots[camera_id] = worker.health_snapshot()
            except Exception:
                snapshots[camera_id] = {"name": f"inference:{camera_id}", "state": "UNKNOWN"}
        return snapshots

    def stop_all(self) -> None:
        with self._lock:
            workers = list(self._workers.values())
        for worker in workers:
            try:
                worker.stop()
            except Exception:
                logger.debug("worker stop failed", exc_info=True)
