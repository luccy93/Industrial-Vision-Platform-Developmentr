"""Quality integration — startup warm-up, stream lifecycle, honest errors."""

from __future__ import annotations

from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.domain.frame import IngestionFrame
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.main import create_app
from backend.app.quality.schemas import (
    InspectionProfile,
    InspectionRegion,
    InspectionType,
    RegionType,
)
from backend.tests.quality_helpers import synthetic_frame, utc

_RECT = {"x": 0.1, "y": 0.1, "width": 0.8, "height": 0.8}


def _app(client: TestClient) -> Any:
    """TestClient types ``app`` as an ASGI callable; we need its state."""
    return cast(FastAPI, cast(Any, client).app).state


def _seed_camera(test_settings: Any, camera_id: str = "cam-lifecycle") -> None:
    from backend.app.domain.stream import SourceType
    from backend.app.ingestion.repository import CameraRepository

    init_db(test_settings.database_url)
    factory = get_session_factory(test_settings.database_url)
    CameraRepository(factory).create(
        name="Lifecycle", camera_id=camera_id, source_type=SourceType.file, source="clip.mp4"
    )


def _seed_profile(test_settings: Any, camera_id: str = "cam-lifecycle") -> None:
    from backend.app.quality.repository import DefectCategoryRepository, InspectionProfileRepository
    from backend.tests.quality_helpers import make_category

    factory = get_session_factory(test_settings.database_url)
    DefectCategoryRepository(factory).create(make_category())
    InspectionProfileRepository(factory).create(
        camera_id=camera_id,
        profile=InspectionProfile(
            profile_id="profile-01",
            camera_id=camera_id,
            name="Surface",
            inspection_type=InspectionType.SURFACE,
        ),
        regions=[
            InspectionRegion(
                region_id="region-01",
                camera_id=camera_id,
                profile_id="profile-01",
                name="Housing",
                region_type=RegionType.RECTANGLE,
                geometry=dict(_RECT),
            )
        ],
        associations=[],
    )


def _frame(camera_id: str) -> IngestionFrame:
    return IngestionFrame(camera_id=camera_id, frame_number=1, width=640, height=480, image=synthetic_frame())


def test_startup_warms_quality_configuration(test_settings) -> None:  # type: ignore[no-untyped-def]
    """Profiles survive a restart: the runtime reloads them from PostgreSQL."""
    _seed_camera(test_settings)
    _seed_profile(test_settings)
    app = create_app(test_settings)
    with TestClient(app) as client:
        engine = _app(client).quality_engine
        state = engine._cameras["cam-lifecycle"]
        assert set(state.profiles) == {"profile-01"}
        assert set(state.regions) == {"region-01"}
        assert "CRACK" in state.categories
        assert client.get("/api/v1/quality/status").json()["active_profiles"] >= 1


def test_stream_stop_clears_runtime_but_keeps_config(test_settings, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Restarting a stream drops sessions/events but reloads the configuration."""
    from backend.tests.helpers import write_sample_video

    _seed_camera(test_settings)
    _seed_profile(test_settings)
    app = create_app(test_settings)
    with TestClient(app) as client:
        video = write_sample_video(str(tmp_path / "lifecycle.mp4"), frames=40)
        assert client.put("/api/v1/cameras/cam-lifecycle", json={"source": video}).status_code == 200
        assert client.post("/api/v1/cameras/cam-lifecycle/start").status_code == 200

        engine = _app(client).quality_engine
        profile = engine._cameras["cam-lifecycle"].profiles["profile-01"]
        # No model is configured: the inspection attempt is an honest ERROR.
        result = engine.inspect("cam-lifecycle", profile, _frame("cam-lifecycle"), utc(0), None)
        assert result.decision.value == "ERROR"
        assert result.error_code == "INSPECTION_MODEL_NOT_CONFIGURED"
        assert engine.session("cam-lifecycle", "profile-01") is not None

        assert client.post("/api/v1/cameras/cam-lifecycle/stop").status_code == 200
        # Sessions and results are gone; the profile configuration is reloaded.
        assert engine.session("cam-lifecycle", "profile-01") is None
        assert engine.latest_result("cam-lifecycle") is None
        assert set(engine._cameras["cam-lifecycle"].profiles) == {"profile-01"}


def test_profile_created_while_streaming_is_applied(client: TestClient) -> None:
    """A profile created after startup is picked up without a restart."""
    assert (
        client.post(
            "/api/v1/cameras",
            json={"name": "Live", "camera_id": "cam-live-q", "source_type": "file", "source": "v.mp4"},
        ).status_code
        == 201
    )
    engine = _app(client).quality_engine
    assert engine._cameras.get("cam-live-q") is None

    assert (
        client.post("/api/v1/quality/defect-categories", json={"code": "DENT", "name": "Dent"}).status_code
        == 201
    )
    res = client.post(
        "/api/v1/cameras/cam-live-q/inspection-profiles",
        json={"name": "Assembly", "profile_id": "asm-01", "defect_codes": ["DENT"]},
    )
    assert res.status_code == 201, res.text
    assert set(engine._cameras["cam-live-q"].profiles) == {"asm-01"}

    assert client.delete("/api/v1/cameras/cam-live-q/inspection-profiles/asm-01").status_code == 200
    assert engine._cameras["cam-live-q"].profiles == {}


def test_error_result_visible_through_latest_endpoint(client: TestClient) -> None:
    """The honest ERROR path is observable through the REST contract."""
    assert (
        client.post(
            "/api/v1/cameras",
            json={"name": "Ev", "camera_id": "cam-qev", "source_type": "file", "source": "v.mp4"},
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/api/v1/cameras/cam-qev/inspection-profiles",
            json={"name": "General", "profile_id": "gen-01"},
        ).status_code
        == 201
    )

    engine = _app(client).quality_engine
    profile = engine._cameras["cam-qev"].profiles["gen-01"]
    result = engine.inspect("cam-qev", profile, _frame("cam-qev"), utc(0), None)
    assert result.decision.value == "ERROR"

    body = client.get("/api/v1/cameras/cam-qev/quality/latest").json()
    assert body["result"]["decision"] == "ERROR"
    assert body["result"]["error_code"] == "INSPECTION_MODEL_NOT_CONFIGURED"
    assert body["result"]["model_name"] is None

    events = client.get("/api/v1/cameras/cam-qev/quality/events").json()
    assert any(e["event_type"] == "QUALITY_ERROR" for e in events["events"])

    # Suppression works through the V07 endpoint.
    error_event = next(e for e in events["events"] if e["event_type"] == "QUALITY_ERROR")
    suppressed = client.post(f"/api/v1/cameras/cam-qev/quality/suppress/{error_event['event_id']}")
    assert suppressed.status_code == 200
    assert suppressed.json()["status"] == "SUPPRESSED"


def test_camera_delete_removes_quality_configuration(client: TestClient) -> None:
    assert (
        client.post(
            "/api/v1/cameras",
            json={"name": "Gone", "camera_id": "cam-gone", "source_type": "file", "source": "v.mp4"},
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/api/v1/cameras/cam-gone/inspection-profiles",
            json={"name": "General", "profile_id": "gen-01"},
        ).status_code
        == 201
    )
    assert client.delete("/api/v1/cameras/cam-gone").status_code == 200
    engine = _app(client).quality_engine
    assert "cam-gone" not in engine._cameras
    # The global defect catalog is unaffected by camera deletion.
    assert client.get("/api/v1/quality/defect-categories").status_code == 200
