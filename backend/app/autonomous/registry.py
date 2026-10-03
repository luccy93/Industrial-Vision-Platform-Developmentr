"""Perception model registry — resolves ``AUTONOMOUS_*`` names honestly.

Rules (mirroring the V07 registry):

* Empty/unknown name -> ``None`` (the engine reports ``NOT_CONFIGURED`` and
  degrades that subsystem — never a silent fake).
* The scripted fixture adapters resolve ONLY outside production, so a missing
  real model is never silently replaced by synthetic outputs.
"""

from __future__ import annotations

import logging

from backend.app.autonomous.depth import DepthEstimator
from backend.app.autonomous.lanes import LaneDetector
from backend.app.autonomous.scene import SceneClassifier
from backend.app.core.config import Settings

logger = logging.getLogger("industrial-vision.autonomous")

FIXTURE_MODEL_NAME = "fixture"


def resolve_scene_classifier(settings: Settings) -> SceneClassifier | None:
    """Return the configured scene classifier, or ``None`` when unavailable."""
    name = (settings.autonomous_scene_classifier or "").strip()
    if not name:
        return None
    if name == FIXTURE_MODEL_NAME:
        if settings.is_production:
            logger.error("fixture scene classifier refused in production")
            return None
        from backend.app.autonomous.scene import FixtureSceneClassifier

        return FixtureSceneClassifier()
    logger.error("unknown scene classifier %r", name)
    return None


def resolve_lane_detector(settings: Settings) -> LaneDetector | None:
    """Return the configured lane detector, or ``None`` when unavailable."""
    name = (settings.autonomous_lane_detector or "").strip()
    if not name:
        return None
    if name == FIXTURE_MODEL_NAME:
        if settings.is_production:
            logger.error("fixture lane detector refused in production")
            return None
        from backend.app.autonomous.lanes import FixtureLaneDetector

        return FixtureLaneDetector()
    logger.error("unknown lane detector %r", name)
    return None


def resolve_depth_estimator(settings: Settings) -> DepthEstimator | None:
    """Return the configured depth estimator, or ``None`` when unavailable."""
    name = (settings.autonomous_depth_model or "").strip()
    if not name:
        return None
    if name == FIXTURE_MODEL_NAME:
        if settings.is_production:
            logger.error("fixture depth estimator refused in production")
            return None
        from backend.app.autonomous.depth import FixtureDepthEstimator

        return FixtureDepthEstimator()
    logger.error("unknown depth estimator %r", name)
    return None
