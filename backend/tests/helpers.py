"""Shared V02 test helpers — synthetic video, fake sources (no hardware)."""

from __future__ import annotations

import cv2
import numpy as np

from backend.app.domain.camera import Camera
from backend.app.domain.stream import SourceType
from backend.app.ingestion.sources import RawFrame, VideoSource


def make_camera(**overrides) -> Camera:  # type: ignore[no-untyped-def]
    params = {
        "name": "Test camera",
        "camera_id": "cam-test",
        "source_type": SourceType.file,
        "source": "sample.mp4",
    }
    params.update(overrides)
    return Camera(**params)  # type: ignore[arg-type]


def synthetic_image(width: int = 320, height: int = 240, value: int = 128) -> np.ndarray:
    return np.full((height, width, 3), value, dtype=np.uint8)


def write_sample_video(path: str, frames: int = 30, fps: float = 30.0) -> str:
    writer = cv2.VideoWriter(path, cv2.VideoWriter_fourcc(*"mp4v"), fps, (320, 240))  # type: ignore[attr-defined]
    for i in range(frames):
        writer.write(synthetic_image(value=(i * 7) % 256))
    writer.release()
    return path


class FakeVideoSource(VideoSource):
    """In-memory source emitting synthetic frames, then EOF."""

    def __init__(self, camera: Camera, total: int = 50, fail_open: bool = False) -> None:
        super().__init__(camera)
        self._total = total
        self._emitted = 0
        self._opened = False
        self._fail_open = fail_open
        self.open_calls = 0

    @property
    def kind(self) -> SourceType:
        return SourceType.file

    def _target(self) -> int | str:
        return "fake"

    def open(self) -> bool:
        self.open_calls += 1
        if self._fail_open:
            return False
        self._opened = True
        self._emitted = 0
        return True

    def is_open(self) -> bool:
        return self._opened

    def read(self) -> RawFrame | None:
        if not self._opened or self._emitted >= self._total:
            return None
        self._emitted += 1
        image = synthetic_image(value=(self._emitted * 5) % 256)
        return RawFrame(image=image, width=320, height=240)

    def close(self) -> None:
        self._opened = False
