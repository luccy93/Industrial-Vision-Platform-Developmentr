"""Tracking API tests — status + per-camera tracks (mock inference)."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from backend.tests.helpers import write_sample_video


def test_tracking_status_shape(client: TestClient) -> None:
    body = client.get("/api/v1/tracking/status").json()
    for key in (
        "tracker",
        "algorithm",
        "active_cameras",
        "active_tracks",
        "confirmed_tracks",
        "tracking_fps",
        "average_latency_ms",
    ):
        assert key in body, key
    assert body["tracker"] == "bytetrack-native"
    assert "ReID" not in body["algorithm"]


def test_tracks_require_known_camera(client: TestClient) -> None:
    assert client.get("/api/v1/cameras/nope/tracks").status_code == 404


def test_tracks_flow_with_file_camera(client: TestClient, tmp_path) -> None:  # type: ignore[no-untyped-def]
    video = write_sample_video(str(tmp_path / "track.mp4"), frames=150)
    res = client.post(
        "/api/v1/cameras",
        json={"name": "T", "camera_id": "cam-track", "source_type": "file", "source": video},
    )
    assert res.status_code == 201
    assert client.get("/api/v1/cameras/cam-track/tracks").json()["count"] == 0
    client.post("/api/v1/cameras/cam-track/start")
    try:
        deadline = time.time() + 20
        payload: dict | None = None
        while time.time() < deadline:
            body = client.get("/api/v1/cameras/cam-track/tracks").json()
            if body["count"] > 0:
                payload = body
                break
            time.sleep(0.3)
        assert payload is not None
        assert payload["tracking_running"] is True
        first = payload["tracks"][0]
        assert first["track_id"] >= 1
        assert first["state"] in ("TENTATIVE", "CONFIRMED", "LOST")
        assert set(first["velocity"].keys()) == {"x", "y", "speed"}
        status = client.get("/api/v1/tracking/status").json()
        assert status["active_tracks"] >= 1
        assert status["detections_processed"] >= 1
    finally:
        client.post("/api/v1/cameras/cam-track/stop")


def test_track_ids_reset_on_restart(client: TestClient, tmp_path) -> None:  # type: ignore[no-untyped-def]
    video = write_sample_video(str(tmp_path / "restart.mp4"), frames=150)
    client.post(
        "/api/v1/cameras",
        json={"name": "R", "camera_id": "cam-restart", "source_type": "file", "source": video},
    )
    client.post("/api/v1/cameras/cam-restart/start")
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            if client.get("/api/v1/cameras/cam-restart/tracks").json()["count"] > 0:
                break
            time.sleep(0.3)
    finally:
        client.post("/api/v1/cameras/cam-restart/stop")
    client.post("/api/v1/cameras/cam-restart/start")
    try:
        deadline = time.time() + 20
        restarted: dict | None = None
        while time.time() < deadline:
            body = client.get("/api/v1/cameras/cam-restart/tracks").json()
            if body["count"] > 0:
                restarted = body
                break
            time.sleep(0.3)
        assert restarted is not None
        assert min(t["track_id"] for t in restarted["tracks"]) >= 1
    finally:
        client.post("/api/v1/cameras/cam-restart/stop")
