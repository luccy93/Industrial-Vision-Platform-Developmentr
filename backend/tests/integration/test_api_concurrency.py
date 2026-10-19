"""API concurrency reliability tests (V19)."""

from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from backend.app.core.config import AppEnv, Settings
from backend.app.infrastructure.db import init_db
from backend.app.main import create_app


@pytest.fixture()
def client(tmp_path):
    settings = Settings(
        app_env=AppEnv.testing,
        log_level="WARNING",
        database_url=f"sqlite:///{tmp_path}/c.db",
        redis_url="redis://localhost:6379/15",
        gpu_enabled=False,
        model_device="cpu",
        _env_file=None,  # type: ignore[call-arg]
    )
    init_db(settings.database_url)
    app = create_app(settings)
    return TestClient(app)


def test_concurrent_health_requests(client):
    results = []
    lock = threading.Lock()

    def worker():
        r = client.get("/health")
        with lock:
            results.append(r.status_code)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 20
    assert all(s == 200 for s in results)


def test_concurrent_ready_requests(client):
    results = []

    def worker():
        r = client.get("/ready")
        results.append(r.status_code)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(s == 200 for s in results)
