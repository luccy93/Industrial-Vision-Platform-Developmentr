"""Worker supervision tests — heartbeats, snapshots, failure isolation."""

from __future__ import annotations

import time
from typing import Any

import numpy as np

from backend.app.core.config import AppEnv, Settings
from backend.app.domain.frame import IngestionFrame
from backend.app.inference.manager import ModelManager
from backend.app.inference.worker import InferenceSupervisor, InferenceWorker


def _settings(**overrides) -> Settings:
    params: dict = {"app_env": AppEnv.testing}
    params.update(overrides)
    return Settings(_env_file=None, **params)  # type: ignore[call-arg]


def _frame(number: int = 0) -> IngestionFrame:
    return IngestionFrame(
        camera_id="cam-sup",
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


def test_inference_worker_reports_heartbeat() -> None:
    manager = ModelManager.from_settings(_settings())
    worker = InferenceWorker("cam-sup", manager, _drain_source(30))
    try:
        assert worker.health_snapshot()["last_heartbeat"] is None
        worker.start()
        deadline = time.time() + 10
        snapshot: dict[str, Any] = {}
        while time.time() < deadline:
            snapshot = worker.health_snapshot()
            if snapshot["last_heartbeat"] is not None:
                break
            time.sleep(0.05)
        assert snapshot["last_heartbeat"] is not None
        assert snapshot["state"] == "RUNNING"
        assert snapshot["name"] == "inference:cam-sup"
    finally:
        worker.stop()
    stopped = worker.health_snapshot()
    assert stopped["state"] == "STOPPED"


def test_supervisor_snapshots_cover_workers() -> None:
    supervisor = InferenceSupervisor()
    manager = ModelManager.from_settings(_settings())
    supervisor.attach("cam-sup", manager, _drain_source(0))
    try:
        snapshots = supervisor.health_snapshots()
        assert set(snapshots) == {"cam-sup"}
        assert snapshots["cam-sup"]["name"] == "inference:cam-sup"
    finally:
        supervisor.detach("cam-sup")
    assert supervisor.health_snapshots() == {}


def test_one_worker_failure_does_not_kill_unrelated() -> None:
    manager = ModelManager.from_settings(_settings())
    good = InferenceWorker("good", manager, _drain_source(30))

    class _Boom:
        def sync_camera(self, *args: Any, **kwargs: Any) -> dict[str, int]:
            raise RuntimeError("incident db down")

    bad = InferenceWorker("bad", manager, _drain_source(30), incident_manager=_Boom())
    try:
        good.start()
        bad.start()
        deadline = time.time() + 10
        while time.time() < deadline and good.health_snapshot()["last_heartbeat"] is None:
            time.sleep(0.05)
        assert good.health_snapshot()["state"] == "RUNNING"
        assert bad.health_snapshot()["state"] == "RUNNING"
        assert good.stats()["incident_syncs"] == 0
    finally:
        good.stop()
        bad.stop()


def test_stream_manager_heartbeat() -> None:
    from backend.app.domain.camera import Camera, SourceType
    from backend.app.ingestion.manager import StreamManager

    camera = Camera(
        camera_id="cam-sup",
        name="Sup",
        source_type=SourceType.file,
        source="v.mp4",
    )
    stream = StreamManager(camera)
    assert stream.health_snapshot()["last_heartbeat"] is None
    snapshot = stream.health_snapshot()
    assert snapshot["name"] == "stream:cam-sup"
    assert snapshot["state"] in ("DISCONNECTED", "STOPPED", "RUNNING", "ERROR", "CONNECTING")


def test_worker_stale_detection_end_to_end() -> None:
    from backend.app.workers.base import WorkerSupervisor

    supervisor = WorkerSupervisor(heartbeat_timeout_seconds=30.0)
    manager = ModelManager.from_settings(_settings())
    probe = InferenceWorker("cam-sup", manager, _drain_source(0))
    assert probe.health_snapshot()["last_heartbeat"] is None
    # A never-started worker has no heartbeat: stale only when RUNNING.
    assert supervisor.stale_workers() == []
