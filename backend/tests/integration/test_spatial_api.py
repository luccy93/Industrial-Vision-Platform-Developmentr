"""Spatial API integration tests — zone CRUD, status, and runtime snapshot."""

from __future__ import annotations

from fastapi.testclient import TestClient

_POLYGON = [
    {"x": 0.2, "y": 0.4},
    {"x": 0.8, "y": 0.4},
    {"x": 0.8, "y": 0.9},
    {"x": 0.2, "y": 0.9},
]


def _camera(client: TestClient, camera_id: str = "cam-zone") -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "Zone cam", "camera_id": camera_id, "source_type": "file", "source": "x.mp4"},
    )
    assert res.status_code == 201


def test_spatial_status_shape(client: TestClient) -> None:
    body = client.get("/api/v1/spatial/status").json()
    assert body["enabled"] is True
    assert body["engine_status"] == "READY"
    assert body["coordinate_space"] == "normalized_image_space"
    assert body["membership_heuristic"] == "bounding_box_bottom_center"
    assert body["proximity_strategy"] in ("CENTER_DISTANCE", "IOU", "HYBRID")
    rels = {r["relationship"]: r["enabled"] for r in body["relationships"]}
    assert set(rels) == {"PERSON_VEHICLE", "PERSON_PERSON", "VEHICLE_VEHICLE"}
    assert rels["PERSON_VEHICLE"] is True and rels["PERSON_PERSON"] is False


def test_zone_crud_round_trip(client: TestClient) -> None:
    _camera(client)
    created = client.post(
        "/api/v1/cameras/cam-zone/zones",
        json={
            "name": "Furnace hall",
            "zone_id": "restricted-01",
            "zone_type": "RESTRICTED",
            "polygon": _POLYGON,
            "severity": "CRITICAL",
            "dwell_threshold_seconds": 3.5,
        },
    )
    assert created.status_code == 201
    zone = created.json()
    assert zone["zone_id"] == "restricted-01"
    assert zone["severity"] == "CRITICAL"
    assert zone["dwell_threshold_seconds"] == 3.5
    assert zone["polygon"] == _POLYGON

    listed = client.get("/api/v1/cameras/cam-zone/zones").json()
    assert listed["count"] == 1 and listed["zones"][0]["zone_id"] == "restricted-01"

    fetched = client.get("/api/v1/cameras/cam-zone/zones/restricted-01").json()
    assert fetched["name"] == "Furnace hall"

    updated = client.put(
        "/api/v1/cameras/cam-zone/zones/restricted-01",
        json={"enabled": False, "dwell_threshold_seconds": 1.0},
    )
    assert updated.status_code == 200
    assert updated.json()["enabled"] is False
    assert updated.json()["dwell_threshold_seconds"] == 1.0

    deleted = client.delete("/api/v1/cameras/cam-zone/zones/restricted-01")
    assert deleted.status_code == 200 and deleted.json()["deleted"] is True
    assert client.get("/api/v1/cameras/cam-zone/zones").json()["count"] == 0


def test_zone_validation_and_conflicts(client: TestClient) -> None:
    _camera(client)
    # Too few polygon points.
    short = client.post(
        "/api/v1/cameras/cam-zone/zones",
        json={"name": "Bad", "polygon": [{"x": 0.1, "y": 0.1}, {"x": 0.9, "y": 0.9}]},
    )
    assert short.status_code == 422
    # Out-of-range normalized coordinates.
    outside = client.post(
        "/api/v1/cameras/cam-zone/zones",
        json={"name": "Bad", "polygon": [{"x": 1.5, "y": 0.1}, {"x": 0.9, "y": 0.9}, {"x": 0.2, "y": 0.3}]},
    )
    assert outside.status_code == 422

    payload = {"name": "Z", "zone_id": "dup", "polygon": _POLYGON}
    assert client.post("/api/v1/cameras/cam-zone/zones", json=payload).status_code == 201
    assert client.post("/api/v1/cameras/cam-zone/zones", json=payload).status_code == 409


def test_zone_routes_require_existing_camera(client: TestClient) -> None:
    assert client.get("/api/v1/cameras/nope/zones").status_code == 404
    assert (
        client.post("/api/v1/cameras/nope/zones", json={"name": "Z", "polygon": _POLYGON}).status_code == 404
    )
    assert client.get("/api/v1/cameras/nope/zones/z1").status_code == 404
    assert client.put("/api/v1/cameras/nope/zones/z1", json={"name": "x"}).status_code == 404
    assert client.delete("/api/v1/cameras/nope/zones/z1").status_code == 404
    assert client.get("/api/v1/cameras/nope/zones/state").status_code == 404


def test_unknown_zone_returns_404(client: TestClient) -> None:
    _camera(client)
    assert client.get("/api/v1/cameras/cam-zone/zones/missing").status_code == 404
    assert client.put("/api/v1/cameras/cam-zone/zones/missing", json={"enabled": False}).status_code == 404
    assert client.delete("/api/v1/cameras/cam-zone/zones/missing").status_code == 404


def test_zone_state_endpoint(client: TestClient) -> None:
    _camera(client)
    body = client.get("/api/v1/cameras/cam-zone/zones/state").json()
    assert body["camera_id"] == "cam-zone"
    assert body["count"] == 0
    assert body["members"] == []


def test_zones_are_isolated_per_camera(client: TestClient) -> None:
    _camera(client, "cam-a")
    _camera(client, "cam-b")
    assert (
        client.post(
            "/api/v1/cameras/cam-a/zones",
            json={"name": "A zone", "zone_id": "shared", "polygon": _POLYGON},
        ).status_code
        == 201
    )
    # Same zone_id is allowed on a different camera.
    assert (
        client.post(
            "/api/v1/cameras/cam-b/zones",
            json={"name": "B zone", "zone_id": "shared", "polygon": _POLYGON},
        ).status_code
        == 201
    )
    assert client.get("/api/v1/cameras/cam-b/zones").json()["zones"][0]["name"] == "B zone"


def test_camera_delete_removes_zones(client: TestClient) -> None:
    _camera(client)
    client.post(
        "/api/v1/cameras/cam-zone/zones",
        json={"name": "Z", "zone_id": "z1", "polygon": _POLYGON},
    )
    assert client.delete("/api/v1/cameras/cam-zone").status_code == 200
    _camera(client)
    assert client.get("/api/v1/cameras/cam-zone/zones").json()["count"] == 0
