"""Bounded frame buffer — drop-oldest overflow for real-time streams.

Design decision: for live video, a stale frame waiting in a queue is worse
than a dropped frame. The buffer therefore has a fixed capacity and, on
overflow, discards the *oldest* frame (``drop_oldest``) so consumers always
see the freshest image and end-to-end latency stays bounded. An alternative
``drop_newest`` policy is available but not recommended for realtime use.

Thread-safe via a single lock; holds frame references without copying.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Literal

from backend.app.domain.frame import IngestionFrame

OverflowPolicy = Literal["drop_oldest", "drop_newest"]


class FrameBuffer:
    """Fixed-capacity, thread-safe FIFO of frames with bounded memory."""

    def __init__(self, capacity: int = 30, overflow: OverflowPolicy = "drop_oldest") -> None:
        if capacity < 1:
            raise ValueError("FrameBuffer capacity must be >= 1")
        self._capacity = capacity
        self._overflow = overflow
        self._queue: deque[IngestionFrame] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._dropped = 0
        self._received = 0

    @property
    def capacity(self) -> int:
        return self._capacity

    def put(self, frame: IngestionFrame) -> bool:
        """Append a frame. Returns False if a frame was dropped on overflow."""
        with self._lock:
            self._received += 1
            if len(self._queue) >= self._capacity:
                self._dropped += 1
                if self._overflow == "drop_newest":
                    return False
                self._queue.popleft()
            self._queue.append(frame)
            return True

    def get(self) -> IngestionFrame | None:
        """Pop the oldest frame, or None when empty."""
        with self._lock:
            if not self._queue:
                return None
            return self._queue.popleft()

    def get_latest(self) -> IngestionFrame | None:
        """Pop the newest frame, counting skipped ones as dropped."""
        with self._lock:
            if not self._queue:
                return None
            skipped = len(self._queue) - 1
            self._dropped += skipped
            latest = self._queue[-1]
            self._queue.clear()
            return latest

    def peek_latest(self) -> IngestionFrame | None:
        with self._lock:
            return self._queue[-1] if self._queue else None

    def clear(self) -> None:
        with self._lock:
            self._queue.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._queue)

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    @property
    def received(self) -> int:
        with self._lock:
            return self._received
