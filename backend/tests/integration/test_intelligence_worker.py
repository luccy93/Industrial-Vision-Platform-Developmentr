"""Intelligence worker-stage tests — wiring, disabled skip, failure isolation."""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any, cast

import numpy as np

from backend.app.core.config import AppEnv, Settings
from backend.app.domain.frame import IngestionFrame
from backend.app.inference.manager import ModelManager
from backend.app.inference.worker import InferenceWorker
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


def _wired_worker(**overrides) -> tuple[IntelligenceEngine, InferenceWorker]:
    settings = _settings(**overrides)
    safety = SafetyEngine(settings, default_rules(settings))
    tracks = [
        make_track(i + 1, "person", (10.0 + i * 40.0, 10.0, 50.0 + i * 40.0, 200.0), camera_id="cam-w")
        for i in range(6)
    ]
    safety.process("cam-w", tracks, utc(0), 320.0, 240.0)
    intel = IntelligenceEngine(settings, safety_engine=safety)
    manager = ModelManager.from_settings(settings)
    from backend.app.tracking.manager import TrackingManager

    worker = InferenceWorker(
        "cam-w",
        manager,
        _drain_source(10),
        tracking_manager=TrackingManager(settings),
        intelligence_engine=intel,
    )
    return intel, worker


def test_stage_stores_latest_result() -> None:
    _, worker = _wired_worker()
    worker._analyze_intelligence(SimpleNamespace(timestamp=utc(0)))  # type: ignore[arg-type]
    latest = cast(Any, worker.latest_intelligence())
    assert latest is not None
    assert latest.camera_id == "cam-w"
    assert latest.active_event_count >= 1


def test_stage_disabled_skips() -> None:
    settings = _settings(intelligence_enabled=False)
    intel = IntelligenceEngine(settings)
    manager = ModelManager.from_settings(settings)
    worker = InferenceWorker("cam-w", manager, _drain_source(1), intelligence_engine=intel)
    worker._analyze_intelligence(SimpleNamespace(timestamp=utc(0)))  # type: ignore[arg-type]
    assert worker.latest_intelligence() is None


def test_stage_without_engine_skips() -> None:
    settings = _settings()
    manager = ModelManager.from_settings(settings)
    worker = InferenceWorker("cam-w", manager, _drain_source(1))
    worker._analyze_intelligence(SimpleNamespace(timestamp=utc(0)))  # type: ignore[arg-type]
    assert worker.latest_intelligence() is None


def test_full_pipeline_holds_intelligence_flag() -> None:
    _, worker = _wired_worker()
    try:
        worker.start()
        deadline = time.time() + 10
        while time.time() < deadline and not worker.stats()["intelligence_result_held"]:
            time.sleep(0.05)
        assert worker.stats()["intelligence_result_held"] is True
    finally:
        worker.stop()
    assert not worker.running
