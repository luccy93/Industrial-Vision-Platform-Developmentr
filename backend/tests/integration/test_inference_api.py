"""Inference API tests — status + recent detections (mock model, no weights)."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from backend.tests.helpers import write_sample_video


def test_inference_status_shape(client: TestClient) -> None:
    body = client.get("/api/v1/inference/status").json()
    for key in (
        "loaded",
        "model_name",
        "device",
        "classes",
        "confidence_threshold",
        "inference_fps",
        "average_latency_ms",
    ):
        assert key in body, key
    assert body["device"] == "cpu"


def test_detections_require_known_camera(client: TestClient) -> None:
    assert client.get("/api/v1/cameras/nope/detections").status_code == 404


def test_detections_flow_with_file_camera(client: TestClient, tmp_path) -> None:  # type: ignore[no-untyped-def]
    video = write_sample_video(str(tmp_path / "infer.mp4"), frames=120)
    res = client.post(
        "/api/v1/cameras",
        json={"name": "I", "camera_id": "cam-infer", "source_type": "file", "source": video},
    )
    assert res.status_code == 201
    client.post("/api/v1/cameras/cam-infer/start")
    try:
        deadline = time.time() + 15
        payload: dict | None = None
        while time.time() < deadline:
            body = client.get("/api/v1/cameras/cam-infer/detections?limit=3").json()
            if body["count"] > 0:
                payload = body
                break
            time.sleep(0.3)
        assert payload is not None
        assert payload["inference_running"] is True
        first = payload["results"][0]
        assert first["detections"][0]["class_name"] == "person"
        assert first["detections"][0]["bounding_box"]["x1"] >= 0
        status = client.get("/api/v1/inference/status").json()
        assert status["loaded"] is True
        assert status["inference_count"] >= 1
        assert status["active_workers"] >= 1
    finally:
        client.post("/api/v1/cameras/cam-infer/stop")
    stopped = client.get("/api/v1/cameras/cam-infer/detections").json()
    assert stopped["inference_running"] is False


def test_detections_empty_before_start(client: TestClient) -> None:
    client.post(
        "/api/v1/cameras",
        json={"name": "J", "camera_id": "cam-idle2", "source_type": "file", "source": "x.mp4"},
    )
    body = client.get("/api/v1/cameras/cam-idle2/detections").json()
    assert body["count"] == 0
    assert body["inference_running"] is False
