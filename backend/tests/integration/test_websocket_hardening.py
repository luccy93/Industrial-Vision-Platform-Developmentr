"""WebSocket hardening tests — subscriptions, isolation, lifespan shutdown."""

from __future__ import annotations

import json
import time
from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _state(client: TestClient) -> Any:
    return cast(FastAPI, cast(Any, client).app).state


def _setup(client: TestClient, camera_id: str = "cam-wsh") -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "WSH", "camera_id": camera_id, "source_type": "file", "source": "v.mp4"},
    )
    assert res.status_code == 201


def _drain_bounded(websocket: Any, timeout: float = 5.0) -> list[dict[str, Any]]:
    """Collect whatever arrives within `timeout` (never blocks forever).

    A daemon thread owns the blocking receive; closing the socket at the
    end of the `with` block releases it.
    """
    import threading

    collected: list[dict[str, Any]] = []
    done = threading.Event()

    def _run() -> None:
        while not done.is_set():
            try:
                collected.append(json.loads(websocket.receive_text()))
            except Exception:
                break

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    time.sleep(timeout)
    done.set()
    thread.join(timeout=10.0)
    return collected


def test_subscription_filter_limits_feed(client: TestClient) -> None:
    _setup(client)
    incident_id = client.post("/api/v1/incidents", json={"title": "filtered", "priority": "P2"}).json()[
        "incident"
    ]["id"]
    assert incident_id
    with client.websocket_connect("/ws/cameras/cam-wsh?event_types=stream_status") as websocket:
        messages = _drain_bounded(websocket)
    types = {m.get("type") for m in messages}
    assert "stream_status" in types
    assert not types - {"stream_status"}, f"unfiltered types leaked: {types}"


def test_default_feed_unchanged(client: TestClient) -> None:
    _setup(client)
    client.post("/api/v1/incidents", json={"title": "full feed", "priority": "P2"})
    with client.websocket_connect("/ws/cameras/cam-wsh") as websocket:
        messages = _drain_bounded(websocket)
    types = {m.get("type") for m in messages}
    assert "stream_status" in types
    assert "incident_created" in types


def test_connections_registered_and_released(client: TestClient) -> None:
    _setup(client)
    manager = _state(client).ws_manager
    assert manager.metrics()["active_connections"] == 0
    with client.websocket_connect("/ws/cameras/cam-wsh"):
        assert manager.metrics()["active_connections"] == 1
        assert manager.metrics()["connections_total"] >= 1
    deadline = time.time() + 5
    while time.time() < deadline and manager.metrics()["active_connections"] != 0:
        time.sleep(0.05)
    assert manager.metrics()["active_connections"] == 0
    assert manager.metrics()["disconnects_total"] >= 1


def test_lifespan_shutdown_marks_stopped() -> None:
    import tempfile

    from fastapi.testclient import TestClient as _TestClient

    from backend.app.core.config import AppEnv, Settings
    from backend.app.infrastructure.db import init_db
    from backend.app.main import create_app

    tmp = tempfile.mkdtemp().replace("\\", "/")
    settings = Settings(
        app_env=AppEnv.testing,
        database_url=f"sqlite:///{tmp}/lifespan.db",
        _env_file=None,  # type: ignore[call-arg]
    )
    init_db(settings.database_url)
    app = create_app(settings)
    assert app.state.runtime.state.value == "READY"
    with _TestClient(app):
        assert app.state.runtime.state.value == "READY"
    assert app.state.runtime.state.value == "STOPPED"
    # Idempotent: a second shutdown never crashes.
    app.state.runtime.shutdown()
    assert app.state.runtime.state.value == "STOPPED"
