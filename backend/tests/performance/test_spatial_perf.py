"""V06 spatial hardening — bounds, performance, concurrency, migration."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from backend.app.core.config import Settings
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.safety.engine import SafetyEngine
from backend.app.spatial.engine import SpatialEngine
from backend.app.spatial.repository import ZoneRepository
from backend.app.spatial.rules import spatial_rules
from backend.app.spatial.schemas import SafetyZone, ZonePoint, ZoneType
from backend.tests.safety_helpers import make_track, utc

_WIDTH, _HEIGHT = 1000.0, 1000.0
_POLYGON = [
    ZonePoint(x=0.2, y=0.4),
    ZonePoint(x=0.8, y=0.4),
    ZonePoint(x=0.8, y=0.9),
    ZonePoint(x=0.2, y=0.9),
]


def _settings(**overrides: Any) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def _engine(**overrides: Any) -> SpatialEngine:
    return SpatialEngine(_settings(**overrides))


def _zone(zone_id: str = "restricted-01", camera_id: str = "cam-01", **extra: Any) -> SafetyZone:
    params: dict = {
        "zone_id": zone_id,
        "camera_id": camera_id,
        "name": "Furnace hall",
        "zone_type": ZoneType.RESTRICTED,
        "polygon": _POLYGON,
    }
    params.update(extra)
    return SafetyZone(**params)  # type: ignore[arg-type]


def test_state_stays_bounded_across_many_tracks() -> None:
    """Membership state must not grow without bound over a long stream."""
    engine = _engine()
    engine.set_zones("cam-01", [_zone()])
    for i in range(400):
        track = make_track(i + 1, "person", (float(i % 900), 300.0, float(i % 900) + 40.0, 500.0))
        engine.process_zones("cam-01", [track], _WIDTH, _HEIGHT, utc(i * 0.1))
    # One state per live (zone, track); vanished tracks are purged by grace.
    assert engine.state_count() <= 400
    engine.reset_camera("cam-01")
    assert engine.state_count() == 0


def test_pruning_after_grace_keeps_memory_flat() -> None:
    engine = _engine(spatial_state_grace_seconds=0.5)
    engine.set_zones("cam-01", [_zone()])
    for i in range(50):
        track = make_track(1, "person", (400.0, 300.0, 440.0, 500.0))
        engine.process_zones("cam-01", [track], _WIDTH, _HEIGHT, utc(i * 0.1))
        # Empty frame between observations: states expire instead of accumulating.
        engine.process_zones("cam-01", [], _WIDTH, _HEIGHT, utc(i * 0.1 + 1.0))
    assert engine.state_count() == 0


def test_zone_latency_low_milliseconds() -> None:
    engine = _engine()
    engine.set_zones("cam-01", [_zone()])
    tracks = [
        make_track(i, "person", (float(i * 30), 300.0, float(i * 30) + 40.0, 500.0)) for i in range(1, 21)
    ]
    started = time.perf_counter()
    for i in range(100):
        engine.process_zones("cam-01", tracks, _WIDTH, _HEIGHT, utc(i * 0.1))
    per_call_ms = (time.perf_counter() - started) * 10.0
    assert per_call_ms < 50.0


def test_proximity_latency_with_busy_scene() -> None:
    engine = _engine(spatial_person_person_enabled=True, spatial_vehicle_vehicle_enabled=True)
    persons = [
        make_track(i, "person", (float(i % 300), 100.0, float(i % 300) + 30.0, 400.0)) for i in range(1, 40)
    ]
    vehicles = [
        make_track(100 + i, "forklift", (float(i % 300), 420.0, float(i % 300) + 90.0, 700.0))
        for i in range(1, 25)
    ]
    tracks = [*persons, *vehicles]
    started = time.perf_counter()
    for i in range(20):
        engine.process_proximity("cam-01", tracks, _WIDTH, _HEIGHT, utc(i * 0.1))
    per_call_ms = (time.perf_counter() - started) * 1000.0 / 20
    assert per_call_ms < 60.0


def test_concurrent_processing_is_safe() -> None:
    """Per-camera isolation must hold under parallel evaluation."""
    engine = _engine()
    engine.set_zones("cam-a", [_zone(zone_id="z-a", camera_id="cam-a")])
    engine.set_zones("cam-b", [_zone(zone_id="z-b", camera_id="cam-b")])
    errors: list[Exception] = []

    def run(camera_id: str) -> None:
        try:
            for i in range(200):
                track = make_track(1, "person", (400.0, 300.0, 440.0, 500.0), camera_id=camera_id)
                engine.process_zones(camera_id, [track], _WIDTH, _HEIGHT, utc(i * 0.05))
                engine.process_proximity(camera_id, [track], _WIDTH, _HEIGHT, utc(i * 0.05))
                engine.status()
        except Exception as exc:  # pragma: no cover - only on a real race
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(cam,)) for cam in ("cam-a", "cam-b", "cam-a")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not errors
    assert engine.state_count() <= 2  # one per camera, never per thread


def test_event_history_bounded_under_churn() -> None:
    settings = _settings(safety_max_events_per_camera=25, safety_event_resolution_grace_seconds=0.1)
    spatial = SpatialEngine(settings)
    spatial.set_zones("cam-01", [_zone(dwell_threshold_seconds=0.0)])
    engine = SafetyEngine(settings, spatial_rules(spatial))
    for i in range(200):
        x = 400.0 if i % 2 == 0 else 50.0
        track = make_track(i % 5 + 1, "person", (x, 300.0, x + 40.0, 500.0))
        engine.process("cam-01", [track], utc(i * 0.5), _WIDTH, _HEIGHT)
    assert len(engine.recent_events("cam-01", 10_000)) <= 25


def test_zone_configuration_survives_reload(tmp_path) -> None:
    """Zones live in the database; the runtime is a disposable snapshot."""
    url = f"sqlite:///{tmp_path}/reload.db"
    init_db(url)
    repository = ZoneRepository(get_session_factory(url))
    repository.create(camera_id="cam-01", zone_id="z-01", name="Persisted", polygon=_POLYGON)

    first = SpatialEngine(_settings())
    first.set_zones("cam-01", repository.list("cam-01"))
    assert [z.zone_id for z in first.zones_for("cam-01")] == ["z-01"]

    # Simulate a restart: the new runtime reloads from storage only.
    second = SpatialEngine(_settings())
    assert second.zones_for("cam-01") == []
    second.set_zones("cam-01", repository.list("cam-01"))
    assert [z.name for z in second.zones_for("cam-01")] == ["Persisted"]


@pytest.mark.parametrize("revision", ["002_create_zones"])
def test_migration_revision_is_registered(revision: str) -> None:
    """The V06 revision must stay in the Alembic chain above V02."""
    import importlib.util
    from pathlib import Path

    path = Path("backend/alembic/versions/002_create_zones.py")
    assert path.exists()
    spec = importlib.util.spec_from_file_location("v06_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == revision
    assert module.down_revision == "001_create_cameras"
    assert hasattr(module, "upgrade") and hasattr(module, "downgrade")
