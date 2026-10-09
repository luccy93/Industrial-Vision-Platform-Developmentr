"""Operations summary tests — aggregation, honesty, bounds, isolation."""

from __future__ import annotations

from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.tests.safety_helpers import make_track


def _state(client: TestClient) -> Any:
    return cast(FastAPI, cast(Any, client).app).state


def _camera(client: TestClient, camera_id: str = "cam-ops") -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "Ops", "camera_id": camera_id, "source_type": "file", "source": "v.mp4"},
    )
    assert res.status_code == 201


def _summary(client: TestClient) -> dict[str, Any]:
    res = client.get("/api/v1/operations/summary")
    assert res.status_code == 200, res.text
    return res.json()


def test_empty_deployment_is_honest(client: TestClient) -> None:
    body = _summary(client)
    assert set(body) == {"timestamp", "cameras", "safety", "incidents", "quality", "risk", "health"}
    assert body["cameras"]["status"] == "ok"
    assert body["cameras"]["configured"] == 0
    assert body["incidents"]["status"] == "ok"
    assert body["incidents"]["total"] == 0
    # Unconfigured quality is unavailable — never zeros-as-ok.
    assert body["quality"]["status"] == "unavailable"
    assert body["quality"]["model_status"] == "NOT_CONFIGURED"
    # No risk signal yet: established UNKNOWN contract, still ok.
    assert body["risk"]["status"] == "ok"
    assert body["risk"]["risk_level"] == "UNKNOWN"
    assert body["health"]["ready"] is True


def test_counts_reflect_real_data(client: TestClient) -> None:
    from backend.tests.intelligence_helpers import utc

    _camera(client)
    state = _state(client)
    tracks = [
        make_track(i + 1, "person", (10.0 + i * 60.0, 10.0, 50.0 + i * 60.0, 200.0), camera_id="cam-ops")
        for i in range(6)
    ]
    state.safety_engine.process("cam-ops", tracks, utc(0), 640.0, 480.0)
    res = client.post("/api/v1/incidents", json={"title": "ops incident", "priority": "P1"})
    assert res.status_code == 201
    body = _summary(client)
    assert body["cameras"]["configured"] == 1
    assert body["cameras"]["by_state"].get("NOT_STARTED", 0) == 1
    assert body["safety"]["total_active"] >= 1
    assert sum(body["safety"]["by_severity"].values()) == body["safety"]["total_active"]
    assert body["incidents"]["total"] == 1
    assert body["incidents"]["open_total"] == 1
    assert body["incidents"]["by_status"].get("OPEN") == 1
    assert body["incidents"]["by_priority"].get("P1") == 1


def test_partial_failure_isolates_sections(client: TestClient) -> None:
    state = _state(client)
    saved = state.quality_engine
    state.quality_engine = None
    try:
        body = _summary(client)
        assert body["quality"]["status"] == "unavailable"
        assert body["cameras"]["status"] == "ok"
        assert body["incidents"]["status"] == "ok"
        assert body["risk"]["status"] == "ok"
        assert body["health"]["status"] == "ok"
    finally:
        state.quality_engine = saved


def test_event_scan_is_bounded(client: TestClient, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import backend.app.api.v1.operations as operations
    from backend.tests.intelligence_helpers import utc

    _camera(client)
    _camera(client, "cam-ops-2")
    state = _state(client)
    for camera_id in ("cam-ops", "cam-ops-2"):
        tracks = [
            make_track(i + 1, "person", (10.0 + i * 60.0, 10.0, 50.0 + i * 60.0, 200.0), camera_id=camera_id)
            for i in range(6)
        ]
        state.safety_engine.process(camera_id, tracks, utc(0), 640.0, 480.0)
    monkeypatch.setattr(operations, "MAX_EVENT_SCAN", 1)
    body = _summary(client)
    assert body["safety"]["total_active"] == 1
    assert body["safety"]["truncated"] is True


def test_openapi_documents_summary() -> None:
    import tempfile

    from fastapi.testclient import TestClient as _TestClient

    from backend.app.core.config import AppEnv, Settings
    from backend.app.infrastructure.db import init_db
    from backend.app.main import create_app

    tmp = tempfile.mkdtemp().replace("\\", "/")
    settings = Settings(
        app_env=AppEnv.testing,
        database_url=f"sqlite:///{tmp}/openapi.db",
        _env_file=None,  # type: ignore[call-arg]
    )
    init_db(settings.database_url)
    spec = _TestClient(create_app(settings)).get("/openapi.json").json()
    assert spec["paths"]["/api/v1/operations/summary"]["get"]["summary"] == "Operations summary"
