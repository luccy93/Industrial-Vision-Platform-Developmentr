"""API load tests (V19, opt-in perf)."""

from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from backend.app.core.config import AppEnv, Settings
from backend.app.infrastructure.db import init_db
from backend.app.main import create_app
from backend.tests.perf.bench import run_benchmark

pytestmark = pytest.mark.perf


@pytest.fixture()
def client(tmp_path):
    settings = Settings(
        app_env=AppEnv.testing,
        log_level="WARNING",
        database_url=f"sqlite:///{tmp_path}/load.db",
        redis_url="redis://localhost:6379/15",
        gpu_enabled=False,
        model_device="cpu",
        _env_file=None,  # type: ignore[call-arg]
    )
    init_db(settings.database_url)
    app = create_app(settings)
    return TestClient(app)


def test_concurrent_load(client):
    results = []

    def worker():
        r = client.get("/health")
        results.append(r.status_code)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 50
    assert all(s == 200 for s in results)


def test_health_benchmark(client):
    def call():
        assert client.get("/health").status_code == 200

    res = run_benchmark(call, name="health_load", iterations=100, warmup=10)
    assert res.failures == 0
