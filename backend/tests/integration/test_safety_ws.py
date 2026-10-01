"""Safety WebSocket tests — safety_event alongside V02–V04 messages."""

from __future__ import annotations

import json
import time

from fastapi.testclient import TestClient

from backend.tests.helpers import write_sample_video


def test_ws_safety_event_and_compatibility(client: TestClient, tmp_path) -> None:  # type: ignore[no-untyped-def]
    video = write_sample_video(str(tmp_path / "wssafe.mp4"), frames=200)
    res = client.post(
        "/api/v1/cameras",
        json={"name": "W", "camera_id": "cam-wssafe", "source_type": "file", "source": video},
    )
    assert res.status_code == 201
    client.post("/api/v1/cameras/cam-wssafe/start")
    try:
        seen: set[str] = set()
        safety: dict | None = None
        with client.websocket_connect("/ws/cameras/cam-wssafe") as websocket:
            deadline = time.time() + 20
            while time.time() < deadline and "safety_event" not in seen:
                message = json.loads(websocket.receive_text())
                seen.add(message["type"])
                if message["type"] == "safety_event":
                    safety = message
        assert {"stream_status", "detection", "tracking", "safety_event"} <= seen
        assert safety is not None
        assert safety["camera_id"] == "cam-wssafe"
        event = safety["event"]
        assert event["event_type"] == "PERSON_VEHICLE_PROXIMITY"
        assert event["severity"] == "HIGH"
        assert event["status"] == "ACTIVE"
        assert isinstance(event["track_ids"], list) and len(event["track_ids"]) == 2
    finally:
        client.post("/api/v1/cameras/cam-wssafe/stop")
