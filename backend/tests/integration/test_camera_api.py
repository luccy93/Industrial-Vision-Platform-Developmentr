"""Camera API tests — CRUD, lifecycle, honest status, no fake connections."""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from backend.tests.helpers import write_sample_video


def _create(client: TestClient, **overrides) -> dict:  # type: ignore[no-untyped-def]
    payload = {"name": "Test", "source_type": "file", "source": "x.mp4"}
    payload.update(overrides)
    res = client.post("/api/v1/cameras", json=payload)
    assert res.status_code == 201, res.text
    return res.json()


def test_crud_lifecycle(client: TestClient) -> None:
    created = _create(client, camera_id="cam-crud")
    assert created["camera_id"] == "cam-crud"
    assert "source_secret" not in created

    assert client.get("/api/v1/cameras").json()["items"][0]["camera_id"] == "cam-crud"
    assert client.get("/api/v1/cameras/cam-crud").json()["name"] == "Test"

    res = client.put("/api/v1/cameras/cam-crud", json={"name": "Renamed"})
    assert res.status_code == 200 and res.json()["name"] == "Renamed"

    assert client.delete("/api/v1/cameras/cam-crud").status_code == 200
    assert client.get("/api/v1/cameras/cam-crud").status_code == 404


def test_duplicate_camera_id_rejected(client: TestClient) -> None:
    _create(client, camera_id="cam-dup")
    res = client.post(
        "/api/v1/cameras",
        json={
            "name": "Dup",
            "source_type": "file",
            "source": "y.mp4",
            "camera_id": "cam-dup",
        },
    )
    assert res.status_code == 409


def test_secret_never_leaks_through_api(client: TestClient) -> None:
    created = _create(
        client,
        camera_id="cam-secret",
        source_type="rtsp",
        source="rtsp://10.0.0.5/live",
        source_secret="admin:s3cret",
    )
    for body in (
        created,
        client.get("/api/v1/cameras").json()["items"][0],
        client.get("/api/v1/cameras/cam-secret").json(),
    ):
        assert "source_secret" not in body
        assert "s3cret" not in str(body)


def test_status_is_disconnected_before_start(client: TestClient) -> None:
    _create(client, camera_id="cam-idle")
    body = client.get("/api/v1/cameras/cam-idle/status").json()
    assert body["state"] == "DISCONNECTED"
    assert body["configured"] is True


def test_start_stop_lifecycle_with_file_source(client: TestClient, tmp_path) -> None:  # type: ignore[no-untyped-def]
    video = write_sample_video(str(tmp_path / "lifecycle.mp4"), frames=120)
    _create(client, camera_id="cam-live", source=video)
    assert client.post("/api/v1/cameras/cam-live/start").json()["state"] in (
        "CONNECTING",
        "CONNECTED",
        "RUNNING",
    )
    deadline = time.time() + 10
    state = ""
    while time.time() < deadline:
        state = client.get("/api/v1/cameras/cam-live/status").json()["state"]
        if state == "RUNNING":
            break
        time.sleep(0.2)
    assert state == "RUNNING"
    metrics = client.get("/api/v1/cameras/cam-live/status").json()["metrics"]
    assert metrics["frames_received"] > 0
    assert metrics["frames_processed"] > 0
    assert client.post("/api/v1/cameras/cam-live/stop").json()["state"] == "STOPPED"


def test_unknown_camera_returns_404(client: TestClient) -> None:
    assert client.get("/api/v1/cameras/nope").status_code == 404
    assert client.post("/api/v1/cameras/nope/start").status_code == 404
    assert client.post("/api/v1/cameras/nope/stop").status_code == 404
    assert client.get("/api/v1/cameras/nope/status").status_code == 404
