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
    ) -> None:
        self.camera_id = camera_id
        self._model_manager = model_manager
        self._frame_source = frame_source
        self._tracking_manager = tracking_manager
        self._safety_engine = safety_engine
        self._quality_engine = quality_engine
        self._autonomous_engine = autonomous_engine
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
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._running = False
        self._queued = 0
        self._dropped = 0
        self._errors = 0
        self._last_error: str | None = None
        self._load_retry_at = 0.0

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

    def _analyze_autonomous(
        self, tracks: list, frame: IngestionFrame, result: InferenceResult
    ) -> None:
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
            perceived = engine.process(
                self.camera_id, tracks, frame, result.timestamp, frame.frame_id
            )
            engine.note_queue_depth(self.camera_id, self._queue.qsize())
        except Exception as exc:
            logger.warning("autonomous perception failed for %s: %s", self.camera_id, exc)
            return
        with self._lock:
            self._autonomous_latest = perceived

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

    def stop_all(self) -> None:
        with self._lock:
            workers = list(self._workers.values())
        for worker in workers:
            try:
                worker.stop()
            except Exception:
                logger.debug("worker stop failed", exc_info=True)
