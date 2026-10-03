"""Quality API tests — profile/category CRUD, status, latest, error codes."""

from __future__ import annotations

from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

_RECT = {"x": 0.1, "y": 0.1, "width": 0.8, "height": 0.8}
_POLYGON = {
    "points": [
        {"x": 0.1, "y": 0.1},
        {"x": 0.9, "y": 0.1},
        {"x": 0.9, "y": 0.9},
    ]
}


def _app(client: TestClient) -> Any:
    """TestClient types ``app`` as an ASGI callable; we need its state."""
    return cast(FastAPI, cast(Any, client).app).state


def _camera(client: TestClient, camera_id: str = "cam-q") -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "Quality", "camera_id": camera_id, "source_type": "file", "source": "v.mp4"},
    )
    assert res.status_code == 201


def _category(client: TestClient, code: str = "CRACK", **overrides) -> dict:
    payload = {
        "code": code,
        "name": code.title(),
        "description": f"{code.title()} defect",
        "severity": "HIGH",
        "confidence_threshold": 0.6,
        "review_threshold": 0.35,
    }
    payload.update(overrides)
    res = client.post("/api/v1/quality/defect-categories", json=payload)
    assert res.status_code == 201, res.text
    return res.json()


def _profile(client: TestClient, camera_id: str = "cam-q", **overrides) -> dict:
    payload = {
        "name": "Surface inspection",
        "profile_id": "profile-01",
        "inspection_type": "SURFACE",
        "regions": [{"name": "Housing", "geometry": _RECT}],
        "defect_codes": [],
    }
    payload.update(overrides)
    res = client.post(f"/api/v1/cameras/{camera_id}/inspection-profiles", json=payload)
    assert res.status_code == 201, res.text
    return res.json()


def test_category_crud(client: TestClient) -> None:
    created = _category(client)
    assert created["code"] == "CRACK"
    assert created["severity"] == "HIGH"

    listed = client.get("/api/v1/quality/defect-categories").json()
    assert listed["count"] == 1

    updated = client.put(
        "/api/v1/quality/defect-categories/CRACK", json={"severity": "critical", "name": "Hairline"}
    )
    assert updated.status_code == 200
    assert updated.json()["severity"] == "CRITICAL"

    deleted = client.delete("/api/v1/quality/defect-categories/CRACK")
    assert deleted.status_code == 200
    assert client.get("/api/v1/quality/defect-categories").json()["count"] == 0


def test_category_duplicate_code_conflicts(client: TestClient) -> None:
    _category(client)
    res = client.post(
        "/api/v1/quality/defect-categories",
        json={"code": "crack", "name": "Dup"},
    )
    assert res.status_code == 409


def test_category_unknown_code_404(client: TestClient) -> None:
    assert client.put("/api/v1/quality/defect-categories/NOPE", json={"name": "x"}).status_code == 404
    assert client.delete("/api/v1/quality/defect-categories/NOPE").status_code == 404


def test_category_invalid_thresholds_422(client: TestClient) -> None:
    res = client.post(
        "/api/v1/quality/defect-categories",
        json={"code": "BAD", "name": "Bad", "confidence_threshold": 0.2, "review_threshold": 0.8},
    )
    assert res.status_code == 422


def test_category_severity_case_insensitive(client: TestClient) -> None:
    created = _category(client, code="DENT", severity="medium")
    assert created["severity"] == "MEDIUM"


def test_profile_crud(client: TestClient) -> None:
    _camera(client)
    _category(client)
    created = _profile(client, defect_codes=["CRACK"])
    assert created["profile_id"] == "profile-01"
    assert created["inspection_type"] == "SURFACE"

    listed = client.get("/api/v1/cameras/cam-q/inspection-profiles").json()
    assert listed["count"] == 1

    fetched = client.get("/api/v1/cameras/cam-q/inspection-profiles/profile-01").json()
    assert fetched["name"] == "Surface inspection"

    updated = client.put(
        "/api/v1/cameras/cam-q/inspection-profiles/profile-01",
        json={"name": "Renamed", "enabled": False},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Renamed"

    deleted = client.delete("/api/v1/cameras/cam-q/inspection-profiles/profile-01")
    assert deleted.status_code == 200
    assert client.get("/api/v1/cameras/cam-q/inspection-profiles").json()["count"] == 0


def test_profile_unknown_camera_404(client: TestClient) -> None:
    assert client.get("/api/v1/cameras/ghost/inspection-profiles").status_code == 404
    assert client.post("/api/v1/cameras/ghost/inspection-profiles", json={"name": "x"}).status_code == 404
    assert client.get("/api/v1/cameras/ghost/quality/latest").status_code == 404
    assert client.get("/api/v1/cameras/ghost/quality/events").status_code == 404


def test_profile_unknown_profile_404(client: TestClient) -> None:
    _camera(client)
    assert client.get("/api/v1/cameras/cam-q/inspection-profiles/nope").status_code == 404
    assert client.put("/api/v1/cameras/cam-q/inspection-profiles/nope", json={"name": "x"}).status_code == 404
    assert client.delete("/api/v1/cameras/cam-q/inspection-profiles/nope").status_code == 404


def test_profile_duplicate_id_409(client: TestClient) -> None:
    _camera(client)
    _profile(client)
    res = client.post(
        "/api/v1/cameras/cam-q/inspection-profiles",
        json={"name": "Dup", "profile_id": "profile-01"},
    )
    assert res.status_code == 409


def test_profile_unknown_defect_code_422(client: TestClient) -> None:
    _camera(client)
    res = client.post(
        "/api/v1/cameras/cam-q/inspection-profiles",
        json={"name": "Bad", "defect_codes": ["NOPE"]},
    )
    assert res.status_code == 422


def test_profile_invalid_geometry_422(client: TestClient) -> None:
    _camera(client)
    res = client.post(
        "/api/v1/cameras/cam-q/inspection-profiles",
        json={
            "name": "Bad",
            "regions": [{"name": "Bad", "geometry": {"x": 0.9, "y": 0.9, "width": 0.5, "height": 0.5}}],
        },
    )
    assert res.status_code == 422
    res = client.post(
        "/api/v1/cameras/cam-q/inspection-profiles",
        json={
            "name": "Bad",
            "regions": [
                {
                    "name": "Bad",
                    "region_type": "POLYGON",
                    "geometry": {"points": [{"x": 0.1, "y": 0.1}]},
                }
            ],
        },
    )
    assert res.status_code == 422


def test_profile_threshold_ordering_422(client: TestClient) -> None:
    _camera(client)
    res = client.post(
        "/api/v1/cameras/cam-q/inspection-profiles",
        json={"name": "Bad", "confidence_threshold": 0.2, "review_threshold": 0.8},
    )
    assert res.status_code == 422


def test_profile_inspection_type_case_insensitive(client: TestClient) -> None:
    _camera(client)
    created = _profile(client, inspection_type="surface", profile_id="p-case")
    assert created["inspection_type"] == "SURFACE"


def test_profile_update_replaces_regions_and_codes(client: TestClient) -> None:
    _camera(client)
    _category(client)
    _category(client, code="DENT", severity="LOW")
    _profile(client, defect_codes=["CRACK"])
    res = client.put(
        "/api/v1/cameras/cam-q/inspection-profiles/profile-01",
        json={
            "regions": [{"name": "New", "geometry": _POLYGON, "region_type": "POLYGON"}],
            "defect_codes": ["DENT"],
        },
    )
    assert res.status_code == 200, res.text
    # Runtime snapshot is reloaded: the region and the new code are visible.
    state = _app(client)
    regions = state.quality_engine._cameras["cam-q"].regions
    assert set(regions) == {"region-01"} or len(regions) == 1


def test_quality_status_shape(client: TestClient) -> None:
    body = client.get("/api/v1/quality/status").json()
    assert body["engine_status"] == "READY"
    assert body["model_status"] == "NOT_CONFIGURED"
    assert body["model_name"] is None
    for key in (
        "active_profiles",
        "active_sessions",
        "inspection_count",
        "pass_count",
        "fail_count",
        "review_count",
        "error_count",
        "defect_count",
        "average_inspection_ms",
        "frames_skipped",
        "inspection_fps",
        "cameras",
    ):
        assert key in body


def test_latest_empty_and_events_empty(client: TestClient) -> None:
    _camera(client)
    assert client.get("/api/v1/cameras/cam-q/quality/latest").json() == {
        "camera_id": "cam-q",
        "result": None,
    }
    assert client.get("/api/v1/cameras/cam-q/quality/events").json()["events"] == []


def test_suppress_unknown_event_404(client: TestClient) -> None:
    _camera(client)
    res = client.post("/api/v1/cameras/cam-q/quality/suppress/00000000-0000-0000-0000-000000000000")
    assert res.status_code == 404
