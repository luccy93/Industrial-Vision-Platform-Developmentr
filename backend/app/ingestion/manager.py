"""Stream manager — per-camera capture worker with lifecycle + metrics.

Concurrency model: each ``StreamManager`` owns exactly one worker
``threading.Thread`` running blocking OpenCV capture. The FastAPI event
loop is never blocked — the API only inspects snapshots (``status()``,
``latest_frame()``). One failed camera cannot crash the backend: exceptions
in a worker transition that stream to ``ERROR``/``RECONNECTING`` only.

``StreamSupervisor`` coordinates many managers (Camera 01 → worker, ...).
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

import numpy as np

from backend.app.domain.camera import Camera
from backend.app.domain.frame import IngestionFrame
from backend.app.domain.stream import StreamMetrics, StreamState
from backend.app.ingestion.buffer import FrameBuffer
from backend.app.ingestion.preprocessing import Preprocessor
from backend.app.ingestion.sampling import FrameSampler
from backend.app.ingestion.sources import VideoSource, create_source

logger = logging.getLogger("industrial-vision.ingestion")

SourceFactory = Callable[[Camera], VideoSource]


def _ema(previous: float, sample: float, alpha: float = 0.2) -> float:
    if previous <= 0:
        return sample
    return (1.0 - alpha) * previous + alpha * sample


class StreamManager:
    """Owns the capture loop, state machine, and metrics for one camera."""

    def __init__(
        self,
        camera: Camera,
        buffer_size: int = 30,
        target_processing_fps: float = 10.0,
        frame_skip: int = 0,
        source_secret: str | None = None,
        source_factory: SourceFactory = create_source,
        preprocessor: Preprocessor | None = None,
        backoff_initial: float = 1.0,
        backoff_max: float = 30.0,
    ) -> None:
        self.camera = camera
        self.buffer = FrameBuffer(capacity=buffer_size)
        self.sampler = FrameSampler(target_processing_fps=target_processing_fps, frame_skip=frame_skip)
        self.preprocessor = preprocessor or Preprocessor()
        self._source_factory = source_factory
        self._source_secret = source_secret
        self._backoff_initial = backoff_initial
        self._backoff_max = backoff_max

        self._lock = threading.Lock()
        self._state = StreamState.DISCONNECTED
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        self._frames_received = 0
        self._frames_processed = 0
        self._source_fps = 0.0
        self._processing_fps = 0.0
        self._latency_ms = 0.0
        self._last_capture_at: float | None = None
        self._last_process_at: float | None = None
        self._started_at: float | None = None
        self._reconnect_count = 0
        self._width: int | None = camera.width
        self._height: int | None = camera.height
        self._last_error: str | None = None
        # V11 supervision: monotonic heartbeat for stale detection.
        self._heartbeat_monotonic: float | None = None

    # -- state -----------------------------------------------------------
    @property
    def state(self) -> StreamState:
        with self._lock:
            return self._state

    def _transition(self, target: StreamState) -> bool:
        with self._lock:
            if target == self._state:
                return True
            if not self._state.can_transition_to(target):
                logger.warning(
                    "camera %s: invalid stream transition %s -> %s",
                    self.camera.camera_id,
                    self._state.value,
                    target.value,
                )
                return False
            logger.info(
                "camera %s: stream %s -> %s",
                self.camera.camera_id,
                self._state.value,
                target.value,
            )
            self._state = target
            return True

    def _effective_camera(self) -> Camera:
        """Camera with RTSP credentials injected (never logged)."""
        if not self._source_secret or self.camera.source_type.value != "rtsp":
            return self.camera
        source = self.camera.source
        if "://" in source and "@" not in source:
            scheme, rest = source.split("://", 1)
            source = f"{scheme}://{self._source_secret}@{rest}"
        updated = self.camera.model_copy(update={"source": source})
        return updated

    # -- lifecycle -------------------------------------------------------
    def start(self) -> bool:
        if self.state in (StreamState.RUNNING, StreamState.CONNECTING, StreamState.CONNECTED):
            return True
        self._stop_event.clear()
        self._transition(StreamState.CONNECTING)
        self._started_at = time.time()
        self._thread = threading.Thread(
            target=self._run,
            name=f"stream-{self.camera.camera_id}",
            daemon=True,
        )
        self._thread.start()
        return True

    def stop(self, timeout: float = 5.0) -> None:
        self._transition(StreamState.STOPPING)
        self._stop_event.set()
        thread, self._thread = self._thread, None
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=timeout)
        self._transition(StreamState.STOPPED)

    # -- capture loop ----------------------------------------------------
    def _run(self) -> None:
        backoff = self._backoff_initial
        source = self._source_factory(self._effective_camera())
        try:
            while not self._stop_event.is_set():
                self._heartbeat_monotonic = time.monotonic()
                if not source.is_open():
                    self._transition(StreamState.CONNECTING)
                    if not source.open():
                        self._on_connection_failed(source, backoff)
                        backoff = min(backoff * 2, self._backoff_max)
                        continue
                    backoff = self._backoff_initial
                    self._transition(StreamState.CONNECTED)
                self._transition(StreamState.RUNNING)
                if not self._pump(source):
                    # End of stream / read failure.
                    source.close()
                    if self._stop_event.is_set():
                        break
                    self._transition(StreamState.ERROR)
                    if not self.camera.reconnect_enabled:
                        break
                    self._transition(StreamState.RECONNECTING)
                    with self._lock:
                        self._reconnect_count += 1
                    self._sleep(backoff)
                    backoff = min(backoff * 2, self._backoff_max)
        except Exception as exc:
            with self._lock:
                self._last_error = f"{type(exc).__name__}: {exc}"
            logger.exception("camera %s: worker crashed", self.camera.camera_id)
            self._transition(StreamState.ERROR)
        finally:
            try:
                source.close()
            except Exception:
                logger.debug("source close failed", exc_info=True)
            if self._stop_event.is_set():
                self._transition(StreamState.STOPPED)

    def _on_connection_failed(self, source: VideoSource, backoff: float) -> None:
        with self._lock:
            self._last_error = f"cannot open source {source.label}"
        self._transition(StreamState.ERROR)
        if self.camera.reconnect_enabled and not self._stop_event.is_set():
            self._transition(StreamState.RECONNECTING)
            with self._lock:
                self._reconnect_count += 1
            self._sleep(backoff)

    def _pump(self, source: VideoSource) -> bool:
        """Read → sample → preprocess → buffer. False on stream failure."""
        raw = source.read()
        now = time.time()
        if raw is None:
            return False
        with self._lock:
            self._frames_received += 1
            if self._last_capture_at is not None:
                dt = now - self._last_capture_at
                if dt > 0:
                    self._source_fps = _ema(self._source_fps, 1.0 / dt)
            self._last_capture_at = now
            self._width, self._height = raw.width, raw.height
        if not self.sampler.should_process(now):
            return True
        processed = self.preprocessor.process(raw.image)
        height, width = processed.shape[0], processed.shape[1]
        frame = IngestionFrame(
            camera_id=self.camera.camera_id,
            frame_number=self._frames_received,
            width=width,
            height=height,
            fps=self._source_fps,
            image=processed if isinstance(processed, np.ndarray) else np.asarray(processed),
        )
        accepted = self.buffer.put(frame)
        with self._lock:
            self._frames_processed += 1
            if self._last_process_at is not None:
                dt = now - self._last_process_at
                if dt > 0:
                    self._processing_fps = _ema(self._processing_fps, 1.0 / dt)
            self._last_process_at = now
            self._latency_ms = (time.time() - now) * 1000.0
            _ = accepted
        return True

    def _sleep(self, seconds: float) -> None:
        self._stop_event.wait(seconds)

    # -- inspection ------------------------------------------------------
    def latest_frame(self) -> IngestionFrame | None:
        return self.buffer.peek_latest()

    def status(self) -> StreamMetrics:
        with self._lock:
            uptime = (time.time() - self._started_at) if self._started_at else 0.0
            return StreamMetrics(
                camera_id=self.camera.camera_id,
                state=self._state,
                source_fps=round(self._source_fps, 2),
                processing_fps=round(self._processing_fps, 2),
                frames_received=self._frames_received,
                frames_processed=self._frames_processed,
                frames_dropped=self.buffer.dropped,
                latency_ms=round(self._latency_ms, 2),
                width=self._width,
                height=self._height,
                uptime_seconds=round(uptime, 2),
                reconnect_count=self._reconnect_count,
            )

    def health_snapshot(self) -> dict:
        """V11 supervision snapshot (additive; existing behavior unchanged)."""
        from datetime import timedelta

        from backend.app.domain.common import utcnow

        with self._lock:
            state = self._state
            heartbeat = self._heartbeat_monotonic
            last_error = self._last_error
        running = state in (StreamState.CONNECTED, StreamState.RUNNING)
        last_heartbeat = None
        if heartbeat is not None:
            age = max(0.0, time.monotonic() - heartbeat)
            last_heartbeat = utcnow() - timedelta(seconds=age)
        return {
            "name": f"stream:{self.camera.camera_id}",
            "state": "RUNNING" if running else state.value,
            "running": running,
            "last_heartbeat": last_heartbeat.isoformat() if last_heartbeat else None,
            "last_error": last_error,
        }

    @property
    def last_error(self) -> str | None:
        with self._lock:
            return self._last_error


class StreamSupervisor:
    """Coordinates one worker per camera; isolates per-camera failures."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._managers: dict[str, StreamManager] = {}

    def register(
        self,
        camera: Camera,
        source_secret: str | None = None,
        source_factory: SourceFactory = create_source,
        **kwargs: object,
    ) -> StreamManager:
        with self._lock:
            existing = self._managers.get(camera.camera_id)
            if existing is not None:
                return existing
            manager = StreamManager(
                camera,
                source_secret=source_secret,
                source_factory=source_factory,
                **kwargs,  # type: ignore[arg-type]
            )
            self._managers[camera.camera_id] = manager
            return manager

    def get(self, camera_id: str) -> StreamManager | None:
        with self._lock:
            return self._managers.get(camera_id)

    def remove(self, camera_id: str) -> bool:
        with self._lock:
            manager = self._managers.pop(camera_id, None)
        if manager is None:
            return False
        try:
            manager.stop()
        except Exception:
            logger.debug("stop failed during remove", exc_info=True)
        return True

    def stop_all(self) -> None:
        with self._lock:
            managers = list(self._managers.values())
        for manager in managers:
            try:
                manager.stop()
            except Exception:
                logger.debug("stop_all failed for a stream", exc_info=True)

    def statuses(self) -> dict[str, StreamMetrics]:
        with self._lock:
            managers = dict(self._managers)
        return {camera_id: manager.status() for camera_id, manager in managers.items()}

    def health_snapshots(self) -> dict[str, dict]:
        """V11 supervision snapshots keyed by camera_id (additive)."""
        with self._lock:
            managers = dict(self._managers)
        snapshots: dict[str, dict] = {}
        for camera_id, manager in managers.items():
            try:
                snapshots[camera_id] = manager.health_snapshot()
            except Exception:
                snapshots[camera_id] = {"name": f"stream:{camera_id}", "state": "UNKNOWN"}
        return snapshots
