"""Pytest fixtures — deterministic, hermetic, no external services."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app.core.config import AppEnv, Settings
from backend.app.main import create_app


@pytest.fixture()
def test_settings() -> Settings:
    return Settings(
        app_name="industrial-vision-platform",
        app_env=AppEnv.testing,
        log_level="INFO",
        api_host="127.0.0.1",
        api_port=8000,
        database_url="postgresql+psycopg2://postgres:postgres@localhost:5432/industrial_vision_test",
        redis_url="redis://localhost:6379/15",
        gpu_enabled=False,
        model_device="cpu",
        model_confidence_threshold=0.5,
        websocket_enabled=True,
    )


@pytest.fixture()
def client(test_settings: Settings) -> TestClient:
    app = create_app(test_settings)
    return TestClient(app)
