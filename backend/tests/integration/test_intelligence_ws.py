"""Intelligence WebSocket tests — new messages alongside V01–V08."""

from __future__ import annotations

import json
import time
from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.tests.intelligence_helpers import utc
from backend.tests.safety_helpers import make_track


def _app(client: TestClient) -> Any:
    """TestClient types ``app`` as an ASGI callable; we need its state."""
    return cast(FastAPI, cast(Any, client).app).state


def _setup(client: TestClient, camera_id: str = "cam-iws") -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "Intel WS", "camera_id": camera_id, "source_type": "file", "source": "v.mp4"},
    )
    assert res.status_code == 201


def _drive_crowd(client: TestClient, camera_id: str = "cam-iws") -> None:
    state = _app(client)
    tracks = [
        make_track(i + 1, "person", (10.0 + i * 60.0, 10.0, 50.0 + i * 60.0, 200.0), camera_id=camera_id)
        for i in range(6)
    ]
    state.safety_engine.process(camera_id, tracks, utc(0), 640.0, 480.0)
    state.intelligence_engine.process(camera_id, utc(0))


def test_ws_intelligence_event_and_cluster_and_update(client: TestClient) -> None:
    _setup(client)
    _drive_crowd(client)

    event_message: dict = {}
    cluster_message: dict = {}
    update_message: dict = {}
    seen: set[str] = set()
    with client.websocket_connect("/ws/cameras/cam-iws") as websocket:
        deadline = time.time() + 15
        while time.time() < deadline and not (event_message and cluster_message and update_message):
            message = json.loads(websocket.receive_text())
            seen.add(message["type"])
            if message["type"] == "intelligence_event" and not event_message:
                event_message = message
            elif message["type"] == "risk_cluster" and not cluster_message:
                cluster_message = message
            elif message["type"] == "risk_update" and not update_message:
                update_message = message

    assert event_message, "expected an intelligence_event message"
    assert event_message["camera_id"] == "cam-iws"
    assert event_message["event"]["event_type"] == "CROWD_WARNING"
    assert event_message["event"]["source_domain"] == "SAFETY"
    assert cluster_message, "expected a risk_cluster message"
    assert cluster_message["camera_id"] == "cam-iws"
    assert cluster_message["factors"]
    assert "priority" in cluster_message
    assert update_message, "expected a risk_update message"
    assert update_message["camera_id"] == "cam-iws"
    assert "risk_level" in update_message and "priority" in update_message
    assert "stream_status" in seen
    assert not {"video", "jpeg", "image"} & seen


def test_ws_preserves_older_messages(client: TestClient) -> None:
    """All V01–V08 channels still flow with the V09 block active."""
    _setup(client)
    _drive_crowd(client)
    with client.websocket_connect("/ws/cameras/cam-iws") as websocket:
        deadline = time.time() + 15
        seen: set[str] = set()
        while time.time() < deadline and "intelligence_event" not in seen:
            seen.add(json.loads(websocket.receive_text())["type"])
    assert "stream_status" in seen
    assert "safety_event" in seen
    assert "intelligence_event" in seen
    for retired in ("video", "jpeg", "image", "suppress", "acknowledge"):
        assert retired not in seen


def test_ws_unknown_camera_still_reports_error(client: TestClient) -> None:
    with client.websocket_connect("/ws/cameras/ghost") as websocket:
        message = json.loads(websocket.receive_text())
    assert message["type"] == "stream_error"
    assert message["code"] == "CAMERA_NOT_FOUND"
