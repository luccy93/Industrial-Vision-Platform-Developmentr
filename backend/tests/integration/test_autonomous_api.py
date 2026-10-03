"""Autonomous API tests — profile CRUD, status, latest, error codes."""

from __future__ import annotations

from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _app(client: TestClient) -> Any:
    """TestClient types ``app`` as an ASGI callable; we need its state."""
    return cast(FastAPI, cast(Any, client).app).state


def _camera(client: TestClient, camera_id: str = "cam-a") -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "Auto", "camera_id": camera_id, "source_type": "file", "source": "v.mp4"},
    )
    assert res.status_code == 201


def _profile(client: TestClient, camera_id: str = "cam-a", **overrides) -> dict:
    payload = {"name": "Road perception", "profile_id": "profile-01"}
    payload.update(overrides)
    res = client.post(f"/api/v1/cameras/{camera_id}/autonomous-profiles", json=payload)
    assert res.status_code == 201, res.text
    return res.json()


def test_profile_crud(client: TestClient) -> None:
    _camera(client)
    created = _profile(client)
    assert created["profile_id"] == "profile-01"
    assert created["scene_type"] == "UNKNOWN"
    assert created["trajectory_horizon_seconds"] == 2.0

    listed = client.get("/api/v1/cameras/cam-a/autonomous-profiles").json()
    assert listed["count"] == 1

    fetched = client.get("/api/v1/cameras/cam-a/autonomous-profiles/profile-01").json()
    assert fetched["name"] == "Road perception"

    updated = client.put(
        "/api/v1/cameras/cam-a/autonomous-profiles/profile-01",
        json={"name": "Renamed", "enabled": False, "scene_type": "road"},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Renamed"
    assert updated.json()["scene_type"] == "ROAD"

    deleted = client.delete("/api/v1/cameras/cam-a/autonomous-profiles/profile-01")
    assert deleted.status_code == 200
    assert client.get("/api/v1/cameras/cam-a/autonomous-profiles").json()["count"] == 0


def test_profile_unknown_camera_404(client: TestClient) -> None:
    assert client.get("/api/v1/cameras/ghost/autonomous-profiles").status_code == 404
    assert client.post("/api/v1/cameras/ghost/autonomous-profiles", json={"name": "x"}).status_code == 404
    assert client.get("/api/v1/cameras/ghost/autonomous/latest").status_code == 404
    assert client.get("/api/v1/cameras/ghost/autonomous/events").status_code == 404


def test_profile_unknown_profile_404(client: TestClient) -> None:
    _camera(client)
    assert client.get("/api/v1/cameras/cam-a/autonomous-profiles/nope").status_code == 404
    assert client.put("/api/v1/cameras/cam-a/autonomous-profiles/nope", json={"name": "x"}).status_code == 404
    assert client.delete("/api/v1/cameras/cam-a/autonomous-profiles/nope").status_code == 404


def test_profile_duplicate_id_409(client: TestClient) -> None:
    _camera(client)
    _profile(client)
    res = client.post(
        "/api/v1/cameras/cam-a/autonomous-profiles",
        json={"name": "Dup", "profile_id": "profile-01"},
    )
    assert res.status_code == 409


def test_profile_invalid_thresholds_422(client: TestClient) -> None:
    _camera(client)
    res = client.post(
        "/api/v1/cameras/cam-a/autonomous-profiles",
        json={"name": "Bad", "collision_risk_threshold": 1.5},
    )
    assert res.status_code == 422
    res = client.post(
        "/api/v1/cameras/cam-a/autonomous-profiles",
        json={"name": "Bad", "trajectory_horizon_seconds": 0.0},
    )
    assert res.status_code == 422


def test_profile_scene_type_case_insensitive(client: TestClient) -> None:
    _camera(client)
    created = _profile(client, scene_type="warehouse", profile_id="p-case")
    assert created["scene_type"] == "WAREHOUSE"


def test_profile_created_while_running_is_applied(client: TestClient) -> None:
    _camera(client)
    engine = _app(client).autonomous_engine
    assert engine._cameras.get("cam-a") is None
    _profile(client)
    assert set(engine._cameras["cam-a"].profiles) == {"profile-01"}
    client.delete("/api/v1/cameras/cam-a/autonomous-profiles/profile-01")
    assert engine._cameras["cam-a"].profiles == {}


def test_autonomous_status_shape(client: TestClient) -> None:
    body = client.get("/api/v1/autonomous/status").json()
    assert body["engine_status"] == "READY"
    assert body["depth_status"] == "NOT_CONFIGURED"
    for key in (
        "scene_classifier_status",
        "lane_detector_status",
        "trajectory_status",
        "collision_status",
        "bev_status",
        "active_profiles",
        "active_cameras",
        "tracked_objects",
        "perception_count",
        "average_perception_ms",
        "frames_skipped",
        "perception_fps",
        "cameras",
    ):
        assert key in body


def test_latest_empty_and_events_empty(client: TestClient) -> None:
    _camera(client)
    assert client.get("/api/v1/cameras/cam-a/autonomous/latest").json() == {
        "camera_id": "cam-a",
        "result": None,
    }
    assert client.get("/api/v1/cameras/cam-a/autonomous/events").json()["events"] == []


def test_events_status_filter(client: TestClient) -> None:
    _camera(client)
    _profile(client)
    active = client.get("/api/v1/cameras/cam-a/autonomous/events?status=active").json()
    assert active["events"] == []
    resolved = client.get("/api/v1/cameras/cam-a/autonomous/events?status=resolved").json()
    assert resolved["events"] == []
    bad = client.get("/api/v1/cameras/cam-a/autonomous/events?limit=0")
    assert bad.status_code == 422
