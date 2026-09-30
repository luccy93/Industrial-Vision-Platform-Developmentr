"""Inference worker tests — results, bounded drops, error isolation."""

from __future__ import annotations

import time

import numpy as np

from backend.app.core.config import AppEnv, Settings
from backend.app.domain.frame import IngestionFrame
from backend.app.inference.base import ModelUnavailableError
from backend.app.inference.manager import ModelManager
from backend.app.inference.mock_model import MockModel
from backend.app.inference.worker import InferenceSupervisor, InferenceWorker


def _settings() -> Settings:
    return Settings(app_env=AppEnv.testing, _env_file=None)  # type: ignore[call-arg]


def _frame(number: int = 0) -> IngestionFrame:
    return IngestionFrame(
        camera_id="cam-w",
        frame_number=number,
        width=320,
        height=240,
        image=np.zeros((240, 320, 3), dtype=np.uint8),
    )


def _drain_source(frames: int):  # type: ignore[no-untyped-def]
    remaining = frames

    def _source() -> IngestionFrame | None:
        nonlocal remaining
        if remaining <= 0:
            time.sleep(0.01)
            return None
        remaining -= 1
        return _frame(remaining)

    return _source


def test_worker_produces_results() -> None:
    manager = ModelManager.from_settings(_settings())
    worker = InferenceWorker("cam-w", manager, _drain_source(10))
    try:
        worker.start()
        deadline = time.time() + 10
        while time.time() < deadline and worker.latest() is None:
            time.sleep(0.05)
        latest = worker.latest()
        assert latest is not None
        assert latest.camera_id == "cam-w"
        assert len(latest.detections) == 2
        assert len(worker.recent(5)) >= 1
    finally:
        worker.stop()
    assert not worker.running


def test_worker_queue_drops_are_bounded() -> None:
    manager = ModelManager.from_settings(_settings())
    worker = InferenceWorker("cam-w", manager, lambda: None, queue_size=2)
    first = _frame(0)
    assert worker.submit(first) is True
    assert worker.submit(_frame(1)) is True
    assert worker.submit(_frame(2)) is False  # overflow drops oldest
    assert worker.stats()["dropped"] == 1
    assert worker.stats()["queued"] == 3


def test_inference_failure_does_not_kill_worker() -> None:
    class BrokenModel(MockModel):
        def predict_raw(self, image: np.ndarray):  # type: ignore[no-untyped-def]
            raise ModelUnavailableError("boom")

    manager = ModelManager(BrokenModel(), _settings())
    worker = InferenceWorker("cam-w", manager, _drain_source(5))
    try:
        worker.start()
        time.sleep(1.0)
        assert worker.running
        assert worker.stats()["errors"] >= 1
        assert worker.latest() is None
    finally:
        worker.stop()


def test_supervisor_manages_workers() -> None:
    manager = ModelManager.from_settings(_settings())
    supervisor = InferenceSupervisor()
    worker = supervisor.attach("a", manager, _drain_source(3))
    assert supervisor.get("a") is worker
    assert supervisor.get("missing") is None
    assert supervisor.worker_count() == 1
    worker.start()
    worker.stop()
    assert supervisor.detach("a") is True
    assert supervisor.detach("a") is False
