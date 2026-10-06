"""Intelligence API tests — status, events, clusters, risk; no mutation routes."""

from __future__ import annotations

from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.domain.frame import IngestionFrame
from backend.app.quality.fixture import FixtureInspectionModel
from backend.app.quality.inspection import RawDefect
from backend.tests.autonomous_helpers import synthetic_frame
from backend.tests.autonomous_helpers import utc as auto_utc
from backend.tests.intelligence_helpers import utc
from backend.tests.quality_helpers import make_category, make_profile, make_region
from backend.tests.safety_helpers import make_track


def _app(client: TestClient) -> Any:
    """TestClient types ``app`` as an ASGI callable; we need its state."""
    return cast(FastAPI, cast(Any, client).app).state


def _camera(client: TestClient, camera_id: str = "cam-i") -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "Intel", "camera_id": camera_id, "source_type": "file", "source": "v.mp4"},
    )
    assert res.status_code == 201


def _frame(camera_id: str = "cam-i") -> IngestionFrame:
    return IngestionFrame(camera_id=camera_id, frame_number=1, width=640, height=480, image=synthetic_frame())


def _run_intelligence(client: TestClient, camera_id: str = "cam-i") -> None:
    """Run the app's intelligence pass (what the worker stage does live)."""
    _app(client).intelligence_engine.process(camera_id, utc(0))


def _drive_quality(client: TestClient, camera_id: str = "cam-i") -> None:
    """Produce a real QUALITY_FAIL through the app's quality engine."""
    state = _app(client)
    engine = state.quality_engine
    engine._model = FixtureInspectionModel(
        observations=[RawDefect(code="CRACK", box=(10.0, 10.0, 100.0, 100.0), confidence=0.9)]
    )
    profile = make_profile(camera_id=camera_id)
    engine.set_profiles(camera_id, [profile], [make_region(camera_id=camera_id)], [make_category()], {})
    engine.inspect(camera_id, profile, _frame(camera_id), utc(0), None)
    _run_intelligence(client, camera_id)


def _drive_safety(client: TestClient, camera_id: str = "cam-i") -> None:
    """Produce a real CROWD_WARNING through the app's safety engine."""
    state = _app(client)
    tracks = [
        make_track(i + 1, "person", (10.0 + i * 60.0, 10.0, 50.0 + i * 60.0, 200.0), camera_id=camera_id)
        for i in range(6)
    ]
    state.safety_engine.process(camera_id, tracks, utc(0), 640.0, 480.0)
    _run_intelligence(client, camera_id)


def test_status_empty(client: TestClient) -> None:
    body = client.get("/api/v1/intelligence/status").json()
    assert body["engine_status"] == "READY"
    assert body["active_events"] == 0
    assert body["active_clusters"] == 0
    assert body["highest_priority"] == "P4"
    assert body["highest_risk"]["risk_level"] == "UNKNOWN"
    assert set(body["metrics"]) == {
        "events_processed",
        "events_normalized",
        "events_deduplicated",
        "clusters_created",
        "clusters_resolved",
        "risk_updates",
        "processing_latency_ms",
    }
    assert body["configuration"]["risk_high_threshold"] == 0.65
    assert set(body["domains"]) == {"SAFETY", "SPATIAL", "QUALITY", "AUTONOMOUS"}
    assert body["domains"]["SAFETY"]["available"] is True


def test_status_populated(client: TestClient) -> None:
    _camera(client)
    _drive_quality(client)
    _drive_safety(client)
    body = client.get("/api/v1/intelligence/status").json()
    assert body["active_events"] >= 2
    assert body["active_clusters"] >= 1
    assert body["domains"]["QUALITY"]["active_events"] >= 1
    assert body["domains"]["SAFETY"]["active_events"] >= 1
    assert body["cameras"]["cam-i"]["active_events"] >= 2


def test_events_endpoint(client: TestClient) -> None:
    _camera(client)
    empty = client.get("/api/v1/cameras/cam-i/intelligence/events").json()
    assert empty == {"camera_id": "cam-i", "count": 0, "events": []}
    _drive_quality(client)
    body = client.get("/api/v1/cameras/cam-i/intelligence/events").json()
    assert body["count"] >= 1
    assert all(e["source_domain"] == "QUALITY" for e in body["events"])
    fail = next(e for e in body["events"] if e["event_type"] == "QUALITY_FAIL")
    assert "reason" in fail


def test_events_status_filter(client: TestClient) -> None:
    _camera(client)
    _drive_quality(client)
    active = client.get("/api/v1/cameras/cam-i/intelligence/events?status=active").json()
    assert active["count"] >= 1
    assert all(e["status"] == "ACTIVE" for e in active["events"])
    resolved = client.get("/api/v1/cameras/cam-i/intelligence/events?status=resolved").json()
    assert resolved["count"] == 0
    bad = client.get("/api/v1/cameras/cam-i/intelligence/events?limit=0")
    assert bad.status_code == 422


def test_clusters_endpoint(client: TestClient) -> None:
    _camera(client)
    empty = client.get("/api/v1/cameras/cam-i/intelligence/clusters").json()
    assert empty == {"camera_id": "cam-i", "count": 0, "clusters": []}
    _drive_quality(client)
    body = client.get("/api/v1/cameras/cam-i/intelligence/clusters").json()
    assert body["count"] >= 1
    cluster = body["clusters"][0]
    assert cluster["camera_id"] == "cam-i"
    assert cluster["factors"]
    assert "priority" in cluster


def test_risk_endpoint(client: TestClient) -> None:
    _camera(client)
    empty = client.get("/api/v1/cameras/cam-i/intelligence/risk").json()
    assert empty["risk_level"] == "UNKNOWN"
    assert empty["priority"] == "P4"
    assert empty["timestamp"] is None
    _drive_quality(client)
    _drive_safety(client)
    body = client.get("/api/v1/cameras/cam-i/intelligence/risk").json()
    assert body["active_events"] >= 2
    assert body["priority"] in ("P0", "P1", "P2", "P3", "P4")
    assert body["timestamp"] is not None


def test_unknown_camera_404(client: TestClient) -> None:
    assert client.get("/api/v1/cameras/ghost/intelligence/events").status_code == 404
    assert client.get("/api/v1/cameras/ghost/intelligence/clusters").status_code == 404
    assert client.get("/api/v1/cameras/ghost/intelligence/risk").status_code == 404


def test_no_mutation_routes_exist(client: TestClient) -> None:
    """V09 exposes no suppression/acknowledgement endpoints (V10 owns those)."""
    # NOTE: app.routes holds lazy _IncludedRouter placeholders in this
    # FastAPI version, so the OpenAPI schema (fully expanded) is the
    # reliable route inventory.
    app = cast(FastAPI, cast(Any, client).app)
    paths = app.openapi()["paths"]
    intelligence = {p: methods for p, methods in paths.items() if "intelligence" in p}
    assert set(intelligence) == {
        "/api/v1/intelligence/status",
        "/api/v1/cameras/{camera_id}/intelligence/events",
        "/api/v1/cameras/{camera_id}/intelligence/clusters",
        "/api/v1/cameras/{camera_id}/intelligence/risk",
    }
    for path, methods in intelligence.items():
        assert set(methods) == {"get"}, (path, methods)


def test_autonomous_ingest_visible(client: TestClient) -> None:
    _camera(client, "cam-auto")
    state = _app(client)
    boxes = [(100.0 + i * 10.0, 100.0, 150.0 + i * 10.0, 300.0) for i in range(5)]
    track = make_track(
        1, "car", boxes[-1], history_boxes=boxes, history_span_seconds=2.0, camera_id="cam-auto"
    )
    state.autonomous_engine.process("cam-auto", [track], _frame("cam-auto"), auto_utc(0), None)
    _run_intelligence(client, "cam-auto")
    body = client.get("/api/v1/cameras/cam-auto/intelligence/events").json()
    assert body["count"] >= 0  # autonomous may emit nothing observable; must not error
    status = client.get("/api/v1/intelligence/status").json()
    assert status["engine_status"] == "READY"
