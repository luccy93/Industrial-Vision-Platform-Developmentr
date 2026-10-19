"""API baseline benchmarks (V19). Opt-in: pytest -m perf."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app.core.config import AppEnv, Settings
from backend.app.infrastructure.db import init_db
from backend.app.main import create_app
from backend.tests.perf.bench import run_benchmark

pytestmark = pytest.mark.perf


@pytest.fixture()
def perf_client(tmp_path):
    settings = Settings(
        app_env=AppEnv.testing,
        log_level="WARNING",
        database_url=f"sqlite:///{tmp_path}/perf.db",
        redis_url="redis://localhost:6379/15",
        gpu_enabled=False,
        model_device="cpu",
        _env_file=None,  # type: ignore[call-arg]
    )
    init_db(settings.database_url)
    app = create_app(settings)
    return TestClient(app)


def test_health_latency(perf_client):
    def call():
        r = perf_client.get("/health")
        assert r.status_code == 200

    res = run_benchmark(call, name="health", iterations=50, warmup=5)
    assert res.failures == 0
    assert res.median_ms >= 0


def test_ready_latency(perf_client):
    def call():
        r = perf_client.get("/ready")
        assert r.status_code == 200

    res = run_benchmark(call, name="ready", iterations=50, warmup=5)
    assert res.failures == 0
