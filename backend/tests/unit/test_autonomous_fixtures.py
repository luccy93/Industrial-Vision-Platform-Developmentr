"""Model abstraction tests — ABCs, fixtures, registries, production refusal."""

from __future__ import annotations

import numpy as np
import pytest

from backend.app.autonomous.depth import FixtureDepthEstimator
from backend.app.autonomous.lanes import FixtureLaneDetector, LaneDetector, RawLane
from backend.app.autonomous.registry import (
    resolve_depth_estimator,
    resolve_lane_detector,
    resolve_scene_classifier,
)
from backend.app.autonomous.scene import FixtureSceneClassifier, SceneClassifier
from backend.app.autonomous.schemas import LaneType, ModelState, SceneType
from backend.app.core.config import AppEnv, Settings
from backend.tests.autonomous_helpers import synthetic_frame


def _settings(name: str = "", field: str = "scene", env: AppEnv = AppEnv.testing) -> Settings:
    if field == "scene_classifier":
        return Settings(app_env=env, autonomous_scene_classifier=name, _env_file=None)  # type: ignore[call-arg]
    if field == "lane_detector":
        return Settings(app_env=env, autonomous_lane_detector=name, _env_file=None)  # type: ignore[call-arg]
    return Settings(app_env=env, autonomous_depth_model=name, _env_file=None)  # type: ignore[call-arg]


def test_scene_fixture_returns_scripted_hypothesis() -> None:
    model = FixtureSceneClassifier(scene_type=SceneType.ROAD, confidence=0.8, reason="test")
    model.load()
    assert model.is_ready
    hypothesis = model.classify(camera_id="cam-01", object_classes=["car"], object_count=3, lane_count=2)
    assert hypothesis.scene_type is SceneType.ROAD
    assert hypothesis.confidence == 0.8


def test_scene_fixture_defaults_unknown() -> None:
    model = FixtureSceneClassifier()
    model.load()
    hypothesis = model.classify(camera_id="cam-01", object_classes=[], object_count=0, lane_count=0)
    assert hypothesis.scene_type is SceneType.UNKNOWN


def test_scene_load_failure_marks_not_ready() -> None:
    class Broken(FixtureSceneClassifier):
        def _load(self) -> None:
            raise RuntimeError("boom")

    model = Broken()
    with pytest.raises(RuntimeError):
        model.load()
    assert model.state is ModelState.NOT_READY
    assert not model.is_ready


def test_lane_fixture_returns_scripted_lanes() -> None:
    lanes = [RawLane(points=[(0.2, 0.9), (0.3, 0.2)], confidence=0.9, lane_type=LaneType.SOLID)]
    model = FixtureLaneDetector(lanes=lanes)
    model.load()
    found = model.detect(synthetic_frame(), camera_id="cam-01", frame_id=None)
    assert len(found) == 1
    assert found[0].lane_type is LaneType.SOLID
    assert found[0].to_normalized()[0].x == 0.2


def test_lane_fixture_empty_is_valid() -> None:
    model = FixtureLaneDetector(lanes=[])
    model.load()
    assert model.detect(synthetic_frame(), camera_id="cam-01", frame_id=None) == []


def test_lane_fixture_rejects_invalid_frame() -> None:
    model = FixtureLaneDetector()
    model.load()
    with pytest.raises(ValueError):
        model.detect(np.zeros((0, 0, 3), dtype=np.uint8), camera_id="cam-01", frame_id=None)


def test_model_boundaries_are_abstract() -> None:
    import inspect

    from backend.app.autonomous.depth import DepthEstimator

    assert inspect.isabstract(LaneDetector)
    assert inspect.isabstract(SceneClassifier)
    assert inspect.isabstract(DepthEstimator)


def test_depth_fixture_explicit_values_and_none() -> None:
    model = FixtureDepthEstimator(depths={"track-1": 0.4})
    model.load()
    result = model.estimate(synthetic_frame(), ["track-1", "track-2"], camera_id="c", frame_id=None)
    assert result.source.value == "FIXTURE_SYNTHETIC"
    assert result.readings["track-1"].depth == 0.4
    assert result.readings["track-1"].unit == "relative"
    # Unlisted objects are explicitly unavailable — never fabricated.
    assert result.readings["track-2"].depth is None
    assert result.readings["track-2"].unit is None


def test_depth_fixture_rejects_invalid_frame() -> None:
    model = FixtureDepthEstimator(depths={})
    model.load()
    with pytest.raises(ValueError):
        model.estimate(np.zeros((0, 0, 3), dtype=np.uint8), [], camera_id="c", frame_id=None)


def test_registry_empty_names_return_none() -> None:
    assert resolve_scene_classifier(_settings("", "scene_classifier")) is None
    assert resolve_lane_detector(_settings("", "lane_detector")) is None
    assert resolve_depth_estimator(_settings("", "depth_model")) is None


def test_registry_unknown_names_return_none() -> None:
    assert resolve_scene_classifier(_settings("yolo-scene", "scene_classifier")) is None
    assert resolve_lane_detector(_settings("yolo-lanes", "lane_detector")) is None
    assert resolve_depth_estimator(_settings("midas", "depth_model")) is None


def test_registry_fixture_resolves_outside_production() -> None:
    assert isinstance(
        resolve_scene_classifier(_settings("fixture", "scene_classifier", AppEnv.development)),
        FixtureSceneClassifier,
    )
    assert isinstance(
        resolve_lane_detector(_settings("fixture", "lane_detector", AppEnv.development)),
        FixtureLaneDetector,
    )
    assert isinstance(
        resolve_depth_estimator(_settings("fixture", "depth_model", AppEnv.development)),
        FixtureDepthEstimator,
    )


def test_registry_fixture_refused_in_production() -> None:
    assert resolve_scene_classifier(_settings("fixture", "scene_classifier", AppEnv.production)) is None
    assert resolve_lane_detector(_settings("fixture", "lane_detector", AppEnv.production)) is None
    assert resolve_depth_estimator(_settings("fixture", "depth_model", AppEnv.production)) is None
