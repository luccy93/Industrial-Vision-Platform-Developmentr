"""WebSocket detection-message tests — V02 contract plus V03 detections."""

from __future__ import annotations

import json
import time

from fastapi.testclient import TestClient

from backend.tests.helpers import write_sample_video


def test_ws_detection_message(client: TestClient, tmp_path) -> None:  # type: ignore[no-untyped-def]
    video = write_sample_video(str(tmp_path / "wsdet.mp4"), frames=200)
    res = client.post(
        "/api/v1/cameras",
        json={"name": "W", "camera_id": "cam-wsdet", "source_type": "file", "source": video},
    )
    assert res.status_code == 201
    client.post("/api/v1/cameras/cam-wsdet/start")
    try:
        seen: set[str] = set()
        detection: dict | None = None
        with client.websocket_connect("/ws/cameras/cam-wsdet") as websocket:
            deadline = time.time() + 15
            while time.time() < deadline and "detection" not in seen:
                message = json.loads(websocket.receive_text())
                seen.add(message["type"])
                if message["type"] == "detection":
                    detection = message
        assert "stream_status" in seen  # V02 messages remain compatible
        assert detection is not None
        assert detection["camera_id"] == "cam-wsdet"
        assert detection["detections"][0]["class_name"] == "person"
        box = detection["detections"][0]["bounding_box"]
        assert set(box.keys()) == {"x1", "y1", "x2", "y2"}
        assert "track_id" not in json.dumps(detection)  # no tracking in V03
        assert detection["inference_time_ms"] >= 0
    finally:
        client.post("/api/v1/cameras/cam-wsdet/stop")
