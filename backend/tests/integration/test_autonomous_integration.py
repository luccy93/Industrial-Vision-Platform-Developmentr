"""Autonomous integration — startup warm-up, stream lifecycle, worker stage."""

from __future__ import annotations

import time
from typing import Any, cast

from fastapi.testclient import TestClient

from backend.app.domain.frame import IngestionFrame
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.main import create_app
from backend.tests.autonomous_helpers import synthetic_frame, utc
from backend.tests.safety_helpers import make_track


def _seed_camera_and_profile(test_settings: Any, camera_id: str = "cam-life") -> None:
    from backend.app.autonomous.repository import AutonomousProfileRepository
    from backend.app.autonomous.schemas import AutonomousProfile
    from backend.app.domain.stream import SourceType
    from backend.app.ingestion.repository import CameraRepository

    init_db(test_settings.database_url)
    factory = get_session_factory(test_settings.database_url)
    CameraRepository(factory).create(
        name="Lifecycle", camera_id=camera_id, source_type=SourceType.file, source="clip.mp4"
    )
    AutonomousProfileRepository(factory).create(
        camera_id=camera_id,
        profile=AutonomousProfile(profile_id="profile-01", camera_id=camera_id, name="Road"),
    )


def test_startup_warms_perception_profiles(test_settings) -> None:  # type: ignore[no-untyped-def]
    """Profiles survive a restart: the runtime reloads them from PostgreSQL."""
    _seed_camera_and_profile(test_settings)
    app = create_app(test_settings)
    with TestClient(app) as client:
        from typing import cast

        from fastapi import FastAPI

        state = cast(FastAPI, cast(Any, client).app).state
        assert set(state.autonomous_engine._cameras["cam-life"].profiles) == {"profile-01"}
        assert client.get("/api/v1/autonomous/status").json()["active_profiles"] >= 1


def test_stream_stop_clears_runtime_but_keeps_profiles(test_settings, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Restarting a stream drops perception state but reloads the profiles."""
    from typing import cast

    from fastapi import FastAPI

    from backend.tests.helpers import write_sample_video

    _seed_camera_and_profile(test_settings)
    app = create_app(test_settings)
    with TestClient(app) as client:
        video = write_sample_video(str(tmp_path / "lifecycle.mp4"), frames=40)
        assert client.put("/api/v1/cameras/cam-life", json={"source": video}).status_code == 200
        assert client.post("/api/v1/cameras/cam-life/start").status_code == 200

        state = cast(FastAPI, cast(Any, client).app).state
        engine = state.autonomous_engine
        boxes = [(100.0 + i * 10.0, 100.0, 150.0 + i * 10.0, 300.0) for i in range(5)]
        track = make_track(1, "car", boxes[-1], history_boxes=boxes, history_span_seconds=2.0)
        frame = IngestionFrame(
            camera_id="cam-life", frame_number=1, width=640, height=480, image=synthetic_frame()
        )
        engine.process("cam-life", [track], frame, utc(0), None)
        assert engine.latest_result("cam-life") is not None

        assert client.post("/api/v1/cameras/cam-life/stop").status_code == 200
        assert engine.latest_result("cam-life") is None
        assert set(engine._cameras["cam-life"].profiles) == {"profile-01"}


def test_worker_stage_produces_perception(test_settings) -> None:  # type: ignore[no-untyped-def]
    """The inference worker's autonomous stage perceives sampled frames."""
    import numpy as np

    from backend.app.autonomous.scene import FixtureSceneClassifier
    from backend.app.autonomous.schemas import SceneType
    from backend.app.core.config import AppEnv, Settings
    from backend.app.inference.manager import ModelManager
    from backend.app.inference.mock_model import MockModel
    from backend.app.inference.worker import InferenceWorker
    from backend.app.tracking.manager import TrackingManager

    settings = Settings(app_env=AppEnv.testing, _env_file=None)  # type: ignore[call-arg]
    manager = ModelManager(MockModel(), settings)
    from backend.app.autonomous.engine import AutonomousPerceptionEngine

    engine = AutonomousPerceptionEngine(
        settings, scene_classifier=FixtureSceneClassifier(scene_type=SceneType.ROAD)
    )
    frames = 30

    def _source() -> IngestionFrame | None:
        nonlocal frames
        if frames <= 0:
            time.sleep(0.01)
            return None
        frames -= 1
        return IngestionFrame(
            camera_id="cam-w",
            frame_number=frames,
            width=320,
            height=240,
            image=np.zeros((240, 320, 3), dtype=np.uint8),
        )

    worker = InferenceWorker(
        "cam-w",
        manager,
        _source,
        tracking_manager=TrackingManager(settings),
        autonomous_engine=engine,
    )
    try:
        worker.start()
        deadline = time.time() + 15
        while time.time() < deadline and worker.latest_perception() is None:
            time.sleep(0.05)
        perceived = worker.latest_perception()
        assert perceived is not None
        assert cast(Any, perceived).camera_id == "cam-w"
        stats = worker.stats()
        assert stats["autonomous_frames"] > 0
    finally:
        worker.stop()


def test_worker_skips_when_disabled(test_settings) -> None:  # type: ignore[no-untyped-def]
    """A disabled engine is never invoked by the worker (no attempt, no result)."""
    import numpy as np

    from backend.app.autonomous.engine import AutonomousPerceptionEngine
    from backend.app.core.config import AppEnv, Settings
    from backend.app.inference.manager import ModelManager
    from backend.app.inference.mock_model import MockModel
    from backend.app.inference.worker import InferenceWorker
    from backend.app.tracking.manager import TrackingManager

    settings = Settings(app_env=AppEnv.testing, autonomous_enabled=False, _env_file=None)  # type: ignore[call-arg]
    manager = ModelManager(MockModel(), settings)
    engine = AutonomousPerceptionEngine(settings)

    def _source() -> IngestionFrame | None:
        time.sleep(0.01)
        return IngestionFrame(
            camera_id="cam-w",
            frame_number=1,
            width=320,
            height=240,
            image=np.zeros((240, 320, 3), dtype=np.uint8),
        )

    worker = InferenceWorker(
        "cam-w",
        manager,
        _source,
        tracking_manager=TrackingManager(settings),
        autonomous_engine=engine,
    )
    try:
        worker.start()
        time.sleep(1.0)
        assert worker.latest_perception() is None
        assert worker.stats()["autonomous_frames"] == 0
    finally:
        worker.stop()


def test_camera_delete_removes_perception_profiles(client: TestClient) -> None:
    assert (
        client.post(
            "/api/v1/cameras",
            json={"name": "Gone", "camera_id": "cam-gone", "source_type": "file", "source": "v.mp4"},
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/api/v1/cameras/cam-gone/autonomous-profiles",
            json={"name": "Road", "profile_id": "p-1"},
        ).status_code
        == 201
    )
    assert client.delete("/api/v1/cameras/cam-gone").status_code == 200
    from typing import cast

    from fastapi import FastAPI

    state = cast(FastAPI, cast(Any, client).app).state
    assert "cam-gone" not in state.autonomous_engine._cameras
