"""Incident pipeline integration — app-state engines → REST detail."""

from __future__ import annotations

import time
from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.tests.intelligence_helpers import utc
from backend.tests.quality_helpers import make_category, make_profile, make_region
from backend.tests.safety_helpers import make_track


def _state(client: TestClient) -> Any:
    return cast(FastAPI, cast(Any, client).app).state


def _accept_all_priorities(client: TestClient) -> None:
    """Lower the auto-create threshold for synthetic single-camera scenes.

    App scenes produce LOW/MEDIUM single-domain clusters (P3); production
    scenes with correlated multi-domain clusters score P0–P2. Tests accept
    P4 so the pipeline wiring itself is what is under test.
    """
    manager = _state(client).incident_manager
    manager._settings = manager._settings.model_copy(update={"incident_min_priority": "P4"})


def _camera(client: TestClient, camera_id: str = "cam-pipe") -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "Pipe", "camera_id": camera_id, "source_type": "file", "source": "v.mp4"},
    )
    assert res.status_code == 201


def _drive_safety(client: TestClient, camera_id: str = "cam-pipe") -> None:

    state = _state(client)
    tracks = [
        make_track(i + 1, "person", (10.0 + i * 60.0, 10.0, 50.0 + i * 60.0, 200.0), camera_id=camera_id)
        for i in range(6)
    ]
    tape = getattr(state.safety_engine, "_rules", None)
    assert tape is not None and tape, "app safety engine must ship default rules"
    state.safety_engine.process(camera_id, tracks, utc(0), 640.0, 480.0)
    state.intelligence_engine.process(camera_id, utc(0))
    summary = state.incident_manager.sync_camera(camera_id, utc(0))
    assert summary["created"] >= 1


def test_auto_incident_visible_with_linked_events(client: TestClient) -> None:
    """Safety → V09 → incident sync → REST detail with linked events."""
    _camera(client)
    _accept_all_priorities(client)
    _drive_safety(client)

    res = client.get("/api/v1/incidents")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1
    incident = body["incidents"][0]
    assert incident["source"] == "AUTOMATIC"
    assert incident["source_cluster_id"]

    res = client.get(f"/api/v1/incidents/{incident['id']}")
    assert res.status_code == 200
    detail = res.json()
    assert detail["linked_events"], "auto incidents must link their V09 member events"
    member = detail["linked_events"][0]
    assert member["source_domain"] == "SAFETY"
    types = [t["event_type"] for t in detail["timeline"]]
    assert types[0] == "CREATED"


def test_auto_incident_dedupes_across_passes(client: TestClient) -> None:
    """Repeated pipeline passes never duplicate an open automatic incident."""
    _camera(client)
    _accept_all_priorities(client)
    _drive_safety(client)
    state = _state(client)
    summary = state.incident_manager.sync_camera("cam-pipe", utc(60))
    assert summary["created"] == 0
    res = client.get("/api/v1/incidents")
    assert res.json()["total"] == 1


def test_manual_and_auto_coexist(client: TestClient) -> None:
    _camera(client)
    _accept_all_priorities(client)
    _drive_safety(client)
    res = client.post("/api/v1/incidents", json={"title": "Operator note", "priority": "P4"})
    assert res.status_code == 201
    body = client.get("/api/v1/incidents").json()
    assert body["total"] == 2
    sources = {i["source"] for i in body["incidents"]}
    assert sources == {"AUTOMATIC", "MANUAL"}


def test_quality_driven_incident_category(client: TestClient) -> None:
    """QUALITY clusters map to the QUALITY category (no string inference)."""
    import numpy as np

    from backend.app.domain.frame import IngestionFrame
    from backend.app.quality.fixture import FixtureInspectionModel
    from backend.app.quality.inspection import RawDefect

    _camera(client, "cam-q")
    _accept_all_priorities(client)
    state = _state(client)
    state.quality_engine._model = FixtureInspectionModel(
        observations=[RawDefect(code="CRACK", box=(10.0, 10.0, 100.0, 100.0), confidence=0.9)]
    )
    profile = make_profile(camera_id="cam-q")
    state.quality_engine.set_profiles(
        "cam-q", [profile], [make_region(camera_id="cam-q")], [make_category()], {}
    )
    frame = IngestionFrame(
        camera_id="cam-q",
        frame_number=1,
        width=640,
        height=480,
        image=np.zeros((480, 640, 3), dtype=np.uint8),
    )
    state.quality_engine.inspect("cam-q", profile, frame, utc(0), None)
    state.intelligence_engine.process("cam-q", utc(0))
    summary = state.incident_manager.sync_camera("cam-q", utc(0))
    assert summary["created"] >= 1
    body = client.get("/api/v1/incidents?camera_id=cam-q").json()
    assert body["total"] >= 1
    assert {i["category"] for i in body["incidents"]} == {"QUALITY"}


def test_sync_storm_stays_bounded(client: TestClient) -> None:
    """Many no-op syncs complete fast and never duplicate or crash."""
    _camera(client)
    _accept_all_priorities(client)
    _drive_safety(client)
    state = _state(client)
    started = time.perf_counter()
    for _ in range(20):
        state.incident_manager.sync_camera("cam-pipe", utc(0))
    elapsed = time.perf_counter() - started
    assert elapsed < 10.0, f"20 debounced syncs took {elapsed:.2f}s"
    assert client.get("/api/v1/incidents").json()["total"] == 1
