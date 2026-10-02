"""Fixture inspection model + registry tests — scripted, deterministic, no weights."""

from __future__ import annotations

import numpy as np
import pytest

from backend.app.core.config import AppEnv, Settings
from backend.app.quality.fixture import FixtureInspectionModel
from backend.app.quality.inspection import (
    InspectionErrorCode,
    InspectionModelError,
    InspectionModelState,
    RawDefect,
)
from backend.app.quality.registry import resolve_inspection_model

_BOX = (10.0, 10.0, 50.0, 50.0)


def _settings(model: str = "", env: AppEnv = AppEnv.testing) -> Settings:
    return Settings(app_env=env, quality_inspection_model=model, _env_file=None)  # type: ignore[call-arg]


def test_fixture_returns_scripted_observations() -> None:
    model = FixtureInspectionModel(observations=[RawDefect(code="CRACK", box=_BOX, confidence=0.97)])
    model.load()
    assert model.is_ready
    defects = model.predict(
        np.zeros((100, 100, 3), dtype=np.uint8),
        camera_id="cam-01",
        frame_id=None,
        region_id="region-01",
    )
    assert len(defects) == 1
    assert defects[0].code == "CRACK"
    assert defects[0].confidence == 0.97


def test_fixture_empty_observations_is_valid() -> None:
    model = FixtureInspectionModel(observations=[])
    model.load()
    defects = model.predict(
        np.zeros((100, 100, 3), dtype=np.uint8),
        camera_id="cam-01",
        frame_id=None,
        region_id="region-01",
    )
    assert defects == []


def test_fixture_error_mode_raises_with_code() -> None:
    model = FixtureInspectionModel(error_code=InspectionErrorCode.INSPECTION_MODEL_ERROR)
    model.load()
    with pytest.raises(InspectionModelError) as excinfo:
        model.predict(
            np.zeros((100, 100, 3), dtype=np.uint8),
            camera_id="cam-01",
            frame_id=None,
            region_id="region-01",
        )
    assert excinfo.value.code is InspectionErrorCode.INSPECTION_MODEL_ERROR


def test_fixture_rejects_invalid_roi() -> None:
    model = FixtureInspectionModel(observations=[])
    model.load()
    with pytest.raises(InspectionModelError) as excinfo:
        model.predict(
            np.zeros((0, 0, 3), dtype=np.uint8),
            camera_id="cam-01",
            frame_id=None,
            region_id="region-01",
        )
    assert excinfo.value.code is InspectionErrorCode.FRAME_INVALID


def test_fixture_is_deterministic() -> None:
    observations = [RawDefect(code="SCRATCH", box=_BOX, confidence=0.62)]
    first = FixtureInspectionModel(observations=observations)
    second = FixtureInspectionModel(observations=observations)
    first.load()
    second.load()
    frame = np.zeros((100, 100, 3), dtype=np.uint8)
    assert first.predict(frame, camera_id="c", frame_id=None, region_id="r") == second.predict(
        frame, camera_id="c", frame_id=None, region_id="r"
    )


def test_registry_no_model_returns_none() -> None:
    assert resolve_inspection_model(_settings("")) is None


def test_registry_unknown_model_returns_none() -> None:
    assert resolve_inspection_model(_settings("yolo-defect")) is None


def test_registry_fixture_resolves_outside_production() -> None:
    model = resolve_inspection_model(_settings("fixture", AppEnv.development))
    assert isinstance(model, FixtureInspectionModel)


def test_registry_fixture_refused_in_production() -> None:
    assert resolve_inspection_model(_settings("fixture", AppEnv.production)) is None


def test_model_load_failure_marks_not_ready() -> None:
    class Broken(FixtureInspectionModel):
        def _load(self) -> None:
            raise RuntimeError("boom")

    model = Broken()
    with pytest.raises(InspectionModelError) as excinfo:
        model.load()
    assert excinfo.value.code is InspectionErrorCode.INSPECTION_MODEL_ERROR
    assert model.state is InspectionModelState.NOT_READY
    assert not model.is_ready
