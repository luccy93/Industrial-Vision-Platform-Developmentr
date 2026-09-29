"""Pytest fixtures — deterministic, hermetic, no external services."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app.core.config import AppEnv, Settings
from backend.app.infrastructure.db import init_db
from backend.app.main import create_app


@pytest.fixture()
def test_settings(tmp_path) -> Settings:  # type: ignore[no-untyped-def]
    return Settings(
        app_name="industrial-vision-platform",
        app_env=AppEnv.testing,
        log_level="WARNING",
        api_host="127.0.0.1",
        api_port=8000,
        database_url=f"sqlite:///{tmp_path}/test.db",
        redis_url="redis://localhost:6379/15",
        gpu_enabled=False,
        model_device="cpu",
        model_confidence_threshold=0.5,
        websocket_enabled=True,
        target_processing_fps=10.0,
        frame_skip=0,
        buffer_size=8,
        _env_file=None,  # type: ignore[call-arg]
    )


@pytest.fixture()
def client(test_settings: Settings) -> TestClient:
    init_db(test_settings.database_url)
    app = create_app(test_settings)
    return TestClient(app)
