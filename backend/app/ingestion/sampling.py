"""Frame sampling — decimate a fast source down to a processing rate.

Example: a 30 FPS camera with ``target_processing_fps=10`` yields roughly
every third frame. Two cooperating gates:

1. ``frame_skip`` — cheap counter decimation (process every ``skip+1``-th
   frame). ``0`` disables it.
2. Time gate — at most ``target_processing_fps`` frames per second.

A frame is processed only when *both* gates pass. ``now`` is injectable so
tests stay deterministic (no wall-clock flakes).
"""

from __future__ import annotations

import time


class FrameSampler:
    """Decide which captured frames proceed to processing."""

    def __init__(self, target_processing_fps: float = 10.0, frame_skip: int = 0) -> None:
        if target_processing_fps < 0:
            raise ValueError("target_processing_fps must be >= 0")
        if frame_skip < 0:
            raise ValueError("frame_skip must be >= 0")
        self.target_processing_fps = target_processing_fps
        self.frame_skip = frame_skip
        self._seen = 0
        self._accepted = 0
        self._last_accepted_at: float | None = None

    @property
    def interval(self) -> float:
        if self.target_processing_fps <= 0:
            return 0.0
        return 1.0 / self.target_processing_fps

    def should_process(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        self._seen += 1
        if self.frame_skip and (self._seen - 1) % (self.frame_skip + 1) != 0:
            return False
        if self._last_accepted_at is not None and self.interval > 0:
            if now - self._last_accepted_at < self.interval:
                return False
        self._last_accepted_at = now
        self._accepted += 1
        return True

    def reset(self) -> None:
        self._seen = 0
        self._accepted = 0
        self._last_accepted_at = None

    @property
    def seen(self) -> int:
        return self._seen

    @property
    def accepted(self) -> int:
        return self._accepted
