"""V06 spatial integration — migrations, startup warm-up, and stream lifecycle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect

from backend.app.infrastructure.db import get_session_factory
from backend.app.main import create_app
from backend.app.spatial.engine import SpatialEngine
from backend.app.spatial.repository import ZoneRepository
from backend.app.spatial.schemas import ZonePoint
from backend.tests.safety_helpers import make_track, utc

_POLYGON = [
    ZonePoint(x=0.2, y=0.4),
    ZonePoint(x=0.8, y=0.4),
    ZonePoint(x=0.8, y=0.9),
    ZonePoint(x=0.2, y=0.9),
]
_REPO_ROOT = Path(__file__).resolve().parents[3]


def _tables(url: str) -> set[str]:
    return set(inspect(create_engine(url)).get_table_names())


def _state(client: Any) -> Any:
    """Access app state; `TestClient.app` is typed as a generic ASGI callable."""
    return client.app.state


def _spatial(client: Any) -> SpatialEngine:
    return _state(client).spatial_engine


def test_migration_upgrade_and_downgrade_cycle(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The migration chain applies and reverses cleanly (002 zones, 003 quality)."""
    url = f"sqlite:///{tmp_path}/migrate.db"
    # alembic/env.py resolves the URL from the environment (same as real runs).
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config(str(_REPO_ROOT / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(_REPO_ROOT / "backend" / "alembic"))

    command.upgrade(config, "head")
    assert {"cameras", "zones", "inspection_profiles"} <= _tables(url)

    # V07 (003) reverses first: quality tables go, zones stay.
    command.downgrade(config, "-1")
    remaining = _tables(url)
    assert "inspection_profiles" not in remaining
    assert "zones" in remaining

    # V06 (002) reverses next: zones go, cameras stay.
    command.downgrade(config, "-1")
    remaining = _tables(url)
    assert "zones" not in remaining
    assert "cameras" in remaining

    command.upgrade(config, "head")
    assert {"zones", "inspection_profiles"} <= _tables(url)


def _seed_camera_and_zone(test_settings: Any, camera_id: str = "cam-lifecycle") -> None:
    from backend.app.domain.stream import SourceType
    from backend.app.infrastructure.db import init_db
    from backend.app.ingestion.repository import CameraRepository

    init_db(test_settings.database_url)
    factory = get_session_factory(test_settings.database_url)
    CameraRepository(factory).create(
        name="Lifecycle", camera_id=camera_id, source_type=SourceType.file, source="clip.mp4"
    )
    ZoneRepository(factory).create(
        camera_id=camera_id, zone_id="restricted-01", name="Furnace", polygon=_POLYGON
    )


def test_startup_warms_spatial_configuration(test_settings) -> None:  # type: ignore[no-untyped-def]
    """Zones survive a restart: the runtime reloads them from PostgreSQL."""
    _seed_camera_and_zone(test_settings)
    app = create_app(test_settings)
    with TestClient(app) as client:
        spatial = _spatial(client)
        zones = spatial.zones_for("cam-lifecycle")
        assert [z.zone_id for z in zones] == ["restricted-01"]
        assert client.get("/api/v1/spatial/status").json()["zone_count"] >= 1


def test_stream_stop_clears_runtime_state(test_settings, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Restarting a stream invalidates track IDs, so membership must reset."""
    from backend.tests.helpers import write_sample_video

    _seed_camera_and_zone(test_settings)
    app = create_app(test_settings)
    with TestClient(app) as client:
        video = write_sample_video(str(tmp_path / "lifecycle.mp4"), frames=40)
        res = client.put(
            "/api/v1/cameras/cam-lifecycle",
            json={"source": video},
        )
        assert res.status_code == 200
        assert client.post("/api/v1/cameras/cam-lifecycle/start").status_code == 200

        spatial = _spatial(client)
        # Seed synthetic membership to prove the stop path clears it.
        track = make_track(1, "person", (400.0, 300.0, 450.0, 500.0), camera_id="cam-lifecycle")
        _state(client).safety_engine.process("cam-lifecycle", [track], utc(0), 1000.0, 1000.0)
        assert spatial.state_count() >= 1

        assert client.post("/api/v1/cameras/cam-lifecycle/stop").status_code == 200
        assert spatial.state_count() == 0
        # Zone configuration itself is reloaded, not dropped.
        assert [z.zone_id for z in spatial.zones_for("cam-lifecycle")] == ["restricted-01"]


def test_zone_created_while_streaming_is_applied(client: TestClient) -> None:
    """A zone created after startup is picked up without a restart."""
    assert (
        client.post(
            "/api/v1/cameras",
            json={"name": "Live", "camera_id": "cam-live-zone", "source_type": "file", "source": "v.mp4"},
        ).status_code
        == 201
    )
    spatial = _spatial(client)
    assert spatial.zones_for("cam-live-zone") == []

    assert (
        client.post(
            "/api/v1/cameras/cam-live-zone/zones",
            json={"name": "Hot zone", "zone_id": "hot-01", "polygon": [p.model_dump() for p in _POLYGON]},
        ).status_code
        == 201
    )
    assert [z.zone_id for z in spatial.zones_for("cam-live-zone")] == ["hot-01"]

    # A zone update and a deletion are reflected immediately.
    assert (
        client.put("/api/v1/cameras/cam-live-zone/zones/hot-01", json={"enabled": False}).status_code == 200
    )
    assert spatial.zones_for("cam-live-zone") == []
    assert client.delete("/api/v1/cameras/cam-live-zone/zones/hot-01").status_code == 200
    assert spatial.zones_for("cam-live-zone", enabled_only=False) == []


def test_spatial_events_visible_through_safety_endpoint(client: TestClient) -> None:
    """Spatial events use the V05 REST contract (one place to query events)."""
    assert (
        client.post(
            "/api/v1/cameras",
            json={"name": "Ev", "camera_id": "cam-ev", "source_type": "file", "source": "v.mp4"},
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/api/v1/cameras/cam-ev/zones",
            json={"name": "Zone", "zone_id": "z", "polygon": [p.model_dump() for p in _POLYGON]},
        ).status_code
        == 201
    )

    person = make_track(1, "person", (400.0, 300.0, 480.0, 600.0), camera_id="cam-ev")
    vehicle = make_track(2, "forklift", (500.0, 350.0, 800.0, 650.0), camera_id="cam-ev")
    _state(client).safety_engine.process("cam-ev", [person, vehicle], utc(0), 1000.0, 1000.0)

    body = client.get("/api/v1/cameras/cam-ev/safety/events?status=active").json()
    types = {event["event_type"] for event in body["events"]}
    assert "RESTRICTED_ZONE_ENTRY" in types
    assert "PERSON_VEHICLE_PROXIMITY" in types
    assert all(event["spatial"] is True for event in body["events"])

    # Suppression works for spatial events through the V05 endpoint too.
    event_id = next(e["event_id"] for e in body["events"] if e["event_type"] == "ZONE_DWELL" or True)
    suppressed = client.post(f"/api/v1/cameras/cam-ev/safety/suppress/{event_id}")
    assert suppressed.status_code == 200
    assert suppressed.json()["status"] == "SUPPRESSED"
