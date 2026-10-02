"""Operator-facing ergonomics for the zone API (V06 hardening)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app.spatial.schemas import ZoneType


def test_zone_type_and_severity_accept_lowercase(client: TestClient) -> None:
    """Operators type `restricted`; the API normalizes instead of 422."""
    assert (
        client.post(
            "/api/v1/cameras",
            json={"name": "E", "camera_id": "cam-enum", "source_type": "file", "source": "v.mp4"},
        ).status_code
        == 201
    )
    res = client.post(
        "/api/v1/cameras/cam-enum/zones",
        json={
            "name": "Furnace hall",
            "zone_type": "restricted",
            "severity": "high",
            "polygon": [
                {"x": 0.2, "y": 0.4},
                {"x": 0.8, "y": 0.4},
                {"x": 0.8, "y": 0.9},
                {"x": 0.2, "y": 0.9},
            ],
        },
    )
    assert res.status_code == 201
    zone = res.json()
    assert zone["zone_type"] == "RESTRICTED"
    assert zone["severity"] == "HIGH"

    # The stored/serialized form stays canonical regardless of input casing.
    listed = client.get("/api/v1/cameras/cam-enum/zones").json()["zones"][0]
    assert listed["zone_type"] == ZoneType.RESTRICTED.value
    assert listed["severity"] == "HIGH"


def test_update_accepts_mixed_case_and_whitespace(client: TestClient) -> None:
    assert (
        client.post(
            "/api/v1/cameras",
            json={"name": "E2", "camera_id": "cam-enum2", "source_type": "file", "source": "v.mp4"},
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/api/v1/cameras/cam-enum2/zones",
            json={
                "name": "Zone",
                "polygon": [
                    {"x": 0.1, "y": 0.1},
                    {"x": 0.6, "y": 0.1},
                    {"x": 0.6, "y": 0.6},
                ],
            },
        ).status_code
        == 201
    )

    zone_id = client.get("/api/v1/cameras/cam-enum2/zones").json()["zones"][0]["zone_id"]
    res = client.put(
        f"/api/v1/cameras/cam-enum2/zones/{zone_id}",
        json={"zone_type": " Danger ", "severity": "critical"},
    )
    assert res.status_code == 200
    assert res.json()["zone_type"] == "DANGER"
    assert res.json()["severity"] == "CRITICAL"


def test_unknown_enum_value_still_rejected(client: TestClient) -> None:
    """Normalization must not accept nonsense values."""
    assert (
        client.post(
            "/api/v1/cameras",
            json={"name": "E3", "camera_id": "cam-enum3", "source_type": "file", "source": "v.mp4"},
        ).status_code
        == 201
    )
    res = client.post(
        "/api/v1/cameras/cam-enum3/zones",
        json={
            "name": "Zone",
            "zone_type": "nuclear",
            "polygon": [
                {"x": 0.1, "y": 0.1},
                {"x": 0.6, "y": 0.1},
                {"x": 0.6, "y": 0.6},
            ],
        },
    )
    assert res.status_code == 422
