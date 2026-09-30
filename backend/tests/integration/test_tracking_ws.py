"""WebSocket tracking-message tests — V04 addition, V02/V03 intact."""

from __future__ import annotations

import json
import time

from fastapi.testclient import TestClient

from backend.tests.helpers import write_sample_video


def test_ws_tracking_message(client: TestClient, tmp_path) -> None:  # type: ignore[no-untyped-def]
    video = write_sample_video(str(tmp_path / "wstrk.mp4"), frames=200)
    res = client.post(
        "/api/v1/cameras",
        json={"name": "W", "camera_id": "cam-wstrk", "source_type": "file", "source": video},
    )
    assert res.status_code == 201
    client.post("/api/v1/cameras/cam-wstrk/start")
    try:
        seen: set[str] = set()
        tracking: dict | None = None
        with client.websocket_connect("/ws/cameras/cam-wstrk") as websocket:
            deadline = time.time() + 20
            while time.time() < deadline and "tracking" not in seen:
                message = json.loads(websocket.receive_text())
                seen.add(message["type"])
                if message["type"] == "tracking":
                    tracking = message
        assert {"stream_status", "detection", "tracking"} <= seen
        assert tracking is not None
        assert tracking["camera_id"] == "cam-wstrk"
        assert "frame_id" in tracking and "timestamp" in tracking
        track = tracking["tracks"][0]
        assert track["track_id"] >= 1
        assert track["state"] in ("TENTATIVE", "CONFIRMED", "LOST")
        assert track["age"] >= 1 and track["hits"] >= 1
        assert set(track["velocity"].keys()) == {"x", "y", "speed"}
        assert "safety" not in json.dumps(tracking).lower()
    finally:
        client.post("/api/v1/cameras/cam-wstrk/stop")
