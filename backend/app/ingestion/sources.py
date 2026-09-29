"""Video source abstraction — OpenCV details stay behind this interface.

Pipeline stages depend only on ``VideoSource``; the ``cv2.VideoCapture``
mechanics (device index vs RTSP URL vs file path, reconnection, timeouts)
are encapsulated in the three implementations below.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

import cv2
import numpy as np

from backend.app.domain.camera import Camera
from backend.app.domain.stream import SourceType, redact_source

logger = logging.getLogger("industrial-vision.ingestion")


@dataclass
class RawFrame:
    """Capture output: image array plus capture-time metadata."""

    image: np.ndarray
    width: int
    height: int
    captured_at: float = field(default_factory=time.time)


class VideoSource(ABC):
    """Interface every camera source must implement."""

    def __init__(self, camera: Camera) -> None:
        self.camera = camera
        self._capture: cv2.VideoCapture | None = None

    @property
    @abstractmethod
    def kind(self) -> SourceType: ...

    @abstractmethod
    def _target(self) -> int | str:
        """OpenCV open target: device index (USB) or URL/path (RTSP/file)."""

    @property
    def label(self) -> str:
        """Human/log-safe identifier — credentials always redacted."""
        target = self._target()
        return redact_source(str(target))

    def open(self) -> bool:
        self.close()
        target = self._target()
        logger.info("opening %s source: %s", self.kind.value, self.label)
        capture = cv2.VideoCapture(target)
        if not capture.isOpened():
            logger.warning("failed to open %s source: %s", self.kind.value, self.label)
            return False
        if self.camera.width:
            capture.set(cv2.CAP_PROP_FRAME_WIDTH, self.camera.width)
        if self.camera.height:
            capture.set(cv2.CAP_PROP_FRAME_HEIGHT, self.camera.height)
        if self.camera.target_fps:
            capture.set(cv2.CAP_PROP_FPS, self.camera.target_fps)
        self._capture = capture
        return True

    def is_open(self) -> bool:
        return self._capture is not None and self._capture.isOpened()

    def read(self) -> RawFrame | None:
        if not self.is_open():
            return None
        assert self._capture is not None
        ok, image = self._capture.read()
        if not ok or image is None:
            return None
        height, width = image.shape[0], image.shape[1]
        return RawFrame(image=image, width=width, height=height)

    def close(self) -> None:
        if self._capture is not None:
            try:
                self._capture.release()
            except Exception:
                logger.debug("error releasing %s source", self.kind.value, exc_info=True)
            finally:
                self._capture = None

    def __enter__(self) -> VideoSource:
        self.open()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class USBVideoSource(VideoSource):
    """USB / platform camera opened by device index (``source="0"``)."""

    @property
    def kind(self) -> SourceType:
        return SourceType.usb

    def _target(self) -> int | str:
        try:
            return int(self.camera.source)
        except (TypeError, ValueError):
            # Fall back to index 0 for "/dev/video0"-style strings.
            digits = "".join(ch for ch in self.camera.source if ch.isdigit())
            return int(digits[-1]) if digits else 0


class RTSPVideoSource(VideoSource):
    """RTSP/IP camera. Timeouts and reconnect live in the stream manager."""

    connect_timeout_ms: int = 5000

    @property
    def kind(self) -> SourceType:
        return SourceType.rtsp

    def _target(self) -> int | str:
        return self.camera.source

    def open(self) -> bool:
        # Reduce silent hangs on unreachable hosts: best-effort timeout hint.
        # (Honored by the FFMPEG backend; harmless otherwise.)
        import os

        os.environ.setdefault("OPENCV_FFMPEG_CAPTURE_OPTIONS", "rtsp_transport;tcp|stimeout;5000000")
        return super().open()


class FileVideoSource(VideoSource):
    """Local video file — deterministic source for dev/test without hardware."""

    loop: bool = True

    @property
    def kind(self) -> SourceType:
        return SourceType.file

    def _target(self) -> int | str:
        return self.camera.source

    def read(self) -> RawFrame | None:
        frame = super().read()
        if frame is None and self.loop and self._capture is not None:
            # Rewind and retry once so file sources run indefinitely.
            try:
                self._capture.set(cv2.CAP_PROP_POS_FRAMES, 0)
            except Exception:
                logger.debug("rewind failed for %s", self.label, exc_info=True)
            frame = super().read()
        return frame


def create_source(camera: Camera) -> VideoSource:
    """Factory: build the concrete source for a camera's ``source_type``."""
    if camera.source_type == SourceType.usb:
        return USBVideoSource(camera)
    if camera.source_type == SourceType.rtsp:
        return RTSPVideoSource(camera)
    return FileVideoSource(camera)
