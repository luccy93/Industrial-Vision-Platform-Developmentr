"""V02 performance tests — bounds, rates, concurrency, leak checks."""

from __future__ import annotations

import time

from backend.app.domain.frame import IngestionFrame
from backend.app.ingestion.buffer import FrameBuffer
from backend.app.ingestion.manager import StreamSupervisor
from backend.app.ingestion.sampling import FrameSampler
from backend.tests.helpers import FakeVideoSource, make_camera, synthetic_image


def _frame(number: int, size: int = 64) -> IngestionFrame:
    return IngestionFrame(
        camera_id="perf",
        frame_number=number,
        width=size,
        height=size,
        image=synthetic_image(size, size, value=number % 256),
    )


def test_buffer_memory_stays_bounded() -> None:
    """10k puts into capacity-8: length never exceeds capacity, drops counted."""
    buffer = FrameBuffer(capacity=8)
    started = time.time()
    for i in range(10_000):
        buffer.put(_frame(i))
        assert len(buffer) <= 8
    elapsed = time.time() - started
    assert buffer.dropped == 10_000 - 8
    assert elapsed < 5.0  # ~2k+ puts/sec minimum bar


def test_sampler_holds_rate_over_long_run() -> None:
    """Simulated 30 FPS / 30 s stream decimates to ~10 FPS processing."""
    sampler = FrameSampler(target_processing_fps=10.0)
    accepted = sum(1 for i in range(900) if sampler.should_process(now=i / 30.0))
    assert 285 <= accepted <= 315


def test_concurrent_stream_managers() -> None:
    """Four fake cameras run side by side without interference."""
    supervisor = StreamSupervisor()
    for index in range(4):
        supervisor.register(
            make_camera(camera_id=f"perf-{index}"),
            source_factory=lambda cam: FakeVideoSource(cam, total=2000),
            target_processing_fps=1000.0,
            backoff_initial=0.01,
            backoff_max=0.03,
        )
    try:
        for index in range(4):
            manager = supervisor.get(f"perf-{index}")
            assert manager is not None
            manager.start()
        time.sleep(1.0)
        statuses = supervisor.statuses()
        assert len(statuses) == 4
        for metrics in statuses.values():
            assert metrics.frames_received > 0
    finally:
        supervisor.stop_all()
