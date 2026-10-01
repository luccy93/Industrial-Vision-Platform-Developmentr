"""Safety API tests — status, events filter, suppress, live flow."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from backend.tests.helpers import write_sample_video


def test_safety_status_shape(client: TestClient) -> None:
    body = client.get("/api/v1/safety/status").json()
    assert body["enabled"] is True
    assert body["engine_status"] == "READY"
    assert set(body["rules_loaded"]) == {
        "fall_risk",
        "crowd_density",
        "person_vehicle_proximity",
        "stationary_object",
    }
    assert "active_event_count" in body and "average_latency_ms" in body


def test_events_require_known_camera(client: TestClient) -> None:
    assert client.get("/api/v1/cameras/nope/safety/events").status_code == 404
    assert client.post("/api/v1/cameras/nope/safety/suppress/x").status_code == 404


def test_events_empty_initially(client: TestClient) -> None:
    client.post(
        "/api/v1/cameras",
        json={"name": "S", "camera_id": "cam-s0", "source_type": "file", "source": "x.mp4"},
    )
    body = client.get("/api/v1/cameras/cam-s0/safety/events").json()
    assert body["count"] == 0 and body["events"] == []


def test_live_safety_flow(client: TestClient, tmp_path) -> None:  # type: ignore[no-untyped-def]
    video = write_sample_video(str(tmp_path / "safety.mp4"), frames=150)
    client.post(
        "/api/v1/cameras",
        json={"name": "S", "camera_id": "cam-live-s", "source_type": "file", "source": video},
    )
    client.post("/api/v1/cameras/cam-live-s/start")
    try:
        deadline = time.time() + 20
        payload: dict | None = None
        while time.time() < deadline:
            body = client.get("/api/v1/cameras/cam-live-s/safety/events").json()
            if body["count"] > 0:
                payload = body
                break
            time.sleep(0.3)
        assert payload is not None  # mock person+forklift overlap → proximity
        event = payload["events"][0]
        assert event["event_type"] == "PERSON_VEHICLE_PROXIMITY"
        assert event["status"] == "ACTIVE"
        assert "meter" not in event["message"].lower()

        resolved = client.get("/api/v1/cameras/cam-live-s/safety/events?status=all").json()
        assert resolved["count"] >= 1

        suppression = client.post(f"/api/v1/cameras/cam-live-s/safety/suppress/{event['event_id']}").json()
        assert suppression["status"] == "SUPPRESSED"
        remaining = client.get("/api/v1/cameras/cam-live-s/safety/events").json()
        assert all(e["event_id"] != event["event_id"] for e in remaining["events"])
    finally:
        client.post("/api/v1/cameras/cam-live-s/stop")
