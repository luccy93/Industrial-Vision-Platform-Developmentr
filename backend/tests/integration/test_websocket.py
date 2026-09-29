"""WebSocket tests — status/frame/error contract, no video bytes."""

from __future__ import annotations

import json
import time

from fastapi.testclient import TestClient

from backend.tests.helpers import write_sample_video


def test_ws_unknown_camera_returns_error(client: TestClient) -> None:
    with client.websocket_connect("/ws/cameras/nope") as websocket:
        message = json.loads(websocket.receive_text())
        assert message["type"] == "stream_error"
        assert message["code"] == "CAMERA_NOT_FOUND"


def test_ws_streams_status_and_frame_metadata(client: TestClient, tmp_path) -> None:  # type: ignore[no-untyped-def]
    video = write_sample_video(str(tmp_path / "ws.mp4"), frames=200)
    res = client.post(
        "/api/v1/cameras",
        json={"name": "WS", "camera_id": "cam-ws", "source_type": "file", "source": video},
    )
    assert res.status_code == 201
    client.post("/api/v1/cameras/cam-ws/start")
    try:
        seen: set[str] = set()
        with client.websocket_connect("/ws/cameras/cam-ws") as websocket:
            deadline = time.time() + 10
            while time.time() < deadline and seen != {"stream_status", "frame"}:
                message = json.loads(websocket.receive_text())
                seen.add(message["type"])
                if message["type"] == "frame":
                    assert message["camera_id"] == "cam-ws"
                    assert "width" in message and "height" in message
                    assert "source_fps" in message and "processing_fps" in message
                    assert "image" not in message  # no raw bytes on the wire
                    assert message["stream_state"] in ("RUNNING", "CONNECTED", "CONNECTING")
        assert "stream_status" in seen
        assert "frame" in seen
    finally:
        client.post("/api/v1/cameras/cam-ws/stop")
