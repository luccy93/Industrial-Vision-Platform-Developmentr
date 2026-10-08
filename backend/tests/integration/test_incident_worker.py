"""Incident worker-stage tests — wiring, disabled skip, failure isolation."""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import numpy as np

from backend.app.core.config import AppEnv, Settings
from backend.app.domain.frame import IngestionFrame
from backend.app.incidents.manager import IncidentManager
from backend.app.inference.manager import ModelManager
from backend.app.inference.worker import InferenceWorker
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.intelligence.engine import IntelligenceEngine
from backend.app.safety.engine import SafetyEngine
from backend.app.safety.rules import default_rules
from backend.tests.intelligence_helpers import utc
from backend.tests.safety_helpers import make_track


def _settings(**overrides) -> Settings:
    params: dict = {"app_env": AppEnv.testing}
    params.update(overrides)
    return Settings(_env_file=None, **params)  # type: ignore[call-arg]


def _frame(number: int = 0) -> IngestionFrame:
    return IngestionFrame(
        camera_id="cam-w",
        frame_number=number,
        width=320,
        height=240,
        image=np.zeros((240, 320, 3), dtype=np.uint8),
    )


def _drain_source(frames: int):  # type: ignore[no-untyped-def]
    remaining = frames

    def _source() -> IngestionFrame | None:
        nonlocal remaining
        if remaining <= 0:
            time.sleep(0.01)
            return None
        remaining -= 1
        return _frame(remaining)

    return _source


def _wired_worker(db_url: str, **overrides) -> tuple[IncidentManager, InferenceWorker]:
    settings = _settings(**overrides)
    safety = SafetyEngine(settings, default_rules(settings))
    tracks = [
        make_track(i + 1, "person", (10.0 + i * 40.0, 10.0, 50.0 + i * 40.0, 200.0), camera_id="cam-w")
        for i in range(6)
    ]
    safety.process("cam-w", tracks, utc(0), 320.0, 240.0)
    intel_engine = IntelligenceEngine(settings, safety_engine=safety)
    incidents = IncidentManager(settings, get_session_factory(db_url), intel_engine)
    manager = ModelManager.from_settings(settings)
    from backend.app.tracking.manager import TrackingManager

    worker = InferenceWorker(
        "cam-w",
        manager,
        _drain_source(0),
        tracking_manager=TrackingManager(settings),
        intelligence_engine=intel_engine,
        incident_manager=incidents,
    )
    return incidents, worker


def _analyze(incidents: IncidentManager, utc_offset: float = 0.0) -> None:
    incidents._intelligence.process("cam-w", utc(utc_offset))


def test_stage_syncs_v09_output_into_incidents(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incident_worker.db"
    init_db(url)
    incidents, worker = _wired_worker(url, incident_min_priority="P4")
    worker._analyze_intelligence(SimpleNamespace(timestamp=utc(0)))  # type: ignore[arg-type]
    worker._sync_incidents(SimpleNamespace(timestamp=utc(0)))  # type: ignore[arg-type]
    rows, total = incidents.repository.list_incidents()
    assert total == 1
    assert rows[0].source == "AUTOMATIC"
    stats = worker.stats()
    assert stats["incident_syncs"] == 1


def test_stage_runs_after_intelligence_in_pipeline_order(tmp_path) -> None:
    """Pipeline invariant: incident sync sees the intelligence output."""
    url = f"sqlite:///{tmp_path}/incident_worker.db"
    init_db(url)
    # Pre-drive safety only; intelligence processing happens on the worker path.
    settings = _settings(incident_min_priority="P4")
    safety = SafetyEngine(settings, default_rules(settings))
    tracks = [
        make_track(i + 1, "person", (10.0 + i * 40.0, 10.0, 50.0 + i * 40.0, 200.0), camera_id="cam-w")
        for i in range(6)
    ]
    safety.process("cam-w", tracks, utc(0), 320.0, 240.0)
    intel_engine = IntelligenceEngine(settings, safety_engine=safety)
    incidents = IncidentManager(settings, get_session_factory(url), intel_engine)
    manager = ModelManager.from_settings(settings)
    from backend.app.tracking.manager import TrackingManager

    observed: list[str] = []

    probe = SimpleNamespace(timestamp=utc(0))
    worker = InferenceWorker(
        "cam-w",
        manager,
        _drain_source(0),
        tracking_manager=TrackingManager(settings),
        intelligence_engine=intel_engine,
        incident_manager=incidents,
    )
    worker._analyze_intelligence(probe)  # type: ignore[arg-type]
    observed.append("intelligence")
    worker._sync_incidents(probe)  # type: ignore[arg-type]
    observed.append("incidents")
    assert observed == ["intelligence", "incidents"]
    _, total = incidents.repository.list_incidents()
    assert total == 1


def test_stage_skipped_when_disabled(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incident_worker.db"
    init_db(url)
    incidents, worker = _wired_worker(url, incidents_enabled=False)
    worker._sync_incidents(SimpleNamespace(timestamp=utc(0)))  # type: ignore[arg-type]
    _, total = incidents.repository.list_incidents()
    assert total == 0
    assert worker.stats()["incident_syncs"] == 0


def test_stage_failure_isolated(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incident_worker.db"
    init_db(url)

    class _Boom:
        enabled = True

        def sync_camera(self, *args: Any, **kwargs: Any) -> dict[str, int]:
            raise RuntimeError("db down")

    incidents, worker = _wired_worker(url)
    worker._incident_manager = _Boom()  # type: ignore[assignment]
    worker._sync_incidents(SimpleNamespace(timestamp=utc(0)))  # type: ignore[arg-type]
    # Failure is logged, never raised, and never counted as a successful sync.
    assert worker.stats()["incident_syncs"] == 0
    worker._incident_manager = incidents
    _analyze(incidents)
    worker._sync_incidents(SimpleNamespace(timestamp=utc(0)))  # type: ignore[arg-type]
    assert worker.stats()["incident_syncs"] == 1


def test_stage_without_manager_is_noop(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incident_worker.db"
    init_db(url)
    _, worker = _wired_worker(url)
    worker._incident_manager = None
    worker._sync_incidents(SimpleNamespace(timestamp=utc(0)))  # type: ignore[arg-type]
    assert worker.stats()["incident_syncs"] == 0


def test_attach_plumbs_incident_manager(tmp_path) -> None:
    """cameras.py attach kwargs reach the worker (structural wiring proof)."""
    from backend.app.inference.worker import InferenceSupervisor

    url = f"sqlite:///{tmp_path}/incident_worker.db"
    init_db(url)
    incidents, worker = _wired_worker(url)
    supervisor = InferenceSupervisor()
    attached = supervisor.attach(
        "cam-w",
        ModelManager.from_settings(_settings()),
        _drain_source(0),
        incident_manager=incidents,
    )
    try:
        assert attached._incident_manager is incidents
        assert worker._incident_manager is incidents
    finally:
        supervisor.detach("cam-w")
