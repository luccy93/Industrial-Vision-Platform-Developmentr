"""Frame sampling tests — deterministic via injected timestamps."""

from __future__ import annotations

import pytest

from backend.app.ingestion.sampling import FrameSampler


def test_sampler_delivers_target_rate() -> None:
    """Simulate a 30 FPS source over 10 s with a 10 FPS target."""
    sampler = FrameSampler(target_processing_fps=10.0)
    accepted = sum(1 for i in range(300) if sampler.should_process(now=i / 30.0))
    assert 95 <= accepted <= 105
    assert sampler.seen == 300


def test_sampler_frame_skip_decimation() -> None:
    sampler = FrameSampler(target_processing_fps=1000.0, frame_skip=2)
    results = [sampler.should_process(now=i * 0.001) for i in range(9)]
    assert results == [True, False, False, True, False, False, True, False, False]


def test_sampler_rejects_invalid_config() -> None:
    with pytest.raises(ValueError):
        FrameSampler(target_processing_fps=-1)
    with pytest.raises(ValueError):
        FrameSampler(frame_skip=-1)


def test_sampler_reset() -> None:
    sampler = FrameSampler(target_processing_fps=10.0)
    sampler.should_process(now=0.0)
    sampler.reset()
    assert sampler.seen == 0
    assert sampler.accepted == 0
    assert sampler.should_process(now=0.0) is True


def test_zero_target_fps_accepts_everything() -> None:
    sampler = FrameSampler(target_processing_fps=0.0)
    assert all(sampler.should_process(now=i * 0.01) for i in range(5))
