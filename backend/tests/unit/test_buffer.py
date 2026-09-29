"""Frame buffer tests — bounded memory, overflow policy, thread safety."""

from __future__ import annotations

import threading

import pytest

from backend.app.domain.frame import IngestionFrame
from backend.app.ingestion.buffer import FrameBuffer
from backend.tests.helpers import synthetic_image


def _frame(number: int) -> IngestionFrame:
    image = synthetic_image(value=number % 256)
    return IngestionFrame(camera_id="cam-test", frame_number=number, width=320, height=240, image=image)


def test_buffer_rejects_invalid_capacity() -> None:
    with pytest.raises(ValueError):
        FrameBuffer(capacity=0)


def test_buffer_fifo_order() -> None:
    buffer = FrameBuffer(capacity=4)
    for i in range(3):
        assert buffer.put(_frame(i)) is True
    assert buffer.get().frame_number == 0  # type: ignore[union-attr]
    assert buffer.get().frame_number == 1  # type: ignore[union-attr]
    assert len(buffer) == 1


def test_buffer_drop_oldest_bounds_memory() -> None:
    buffer = FrameBuffer(capacity=3, overflow="drop_oldest")
    for i in range(10):
        buffer.put(_frame(i))
    assert len(buffer) == 3
    assert buffer.dropped == 7
    assert buffer.received == 10
    # Freshest frames survive.
    assert buffer.get().frame_number == 7  # type: ignore[union-attr]


def test_buffer_drop_newest_keeps_first() -> None:
    buffer = FrameBuffer(capacity=2, overflow="drop_newest")
    assert buffer.put(_frame(0)) is True
    assert buffer.put(_frame(1)) is True
    assert buffer.put(_frame(2)) is False
    assert buffer.get().frame_number == 0  # type: ignore[union-attr]


def test_get_latest_skips_stale_frames() -> None:
    buffer = FrameBuffer(capacity=8)
    for i in range(5):
        buffer.put(_frame(i))
    latest = buffer.get_latest()
    assert latest is not None and latest.frame_number == 4
    assert len(buffer) == 0
    assert buffer.dropped == 4  # the 4 skipped frames


def test_empty_buffer_returns_none() -> None:
    buffer = FrameBuffer(capacity=4)
    assert buffer.get() is None
    assert buffer.get_latest() is None
    assert buffer.peek_latest() is None


def test_buffer_thread_safety() -> None:
    buffer = FrameBuffer(capacity=16)
    errors: list[Exception] = []

    def producer() -> None:
        try:
            for i in range(200):
                buffer.put(_frame(i))
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    def consumer() -> None:
        try:
            for _ in range(200):
                buffer.get()
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=producer) for _ in range(2)]
    threads += [threading.Thread(target=consumer) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert len(buffer) <= 16
    assert buffer.received == 400
