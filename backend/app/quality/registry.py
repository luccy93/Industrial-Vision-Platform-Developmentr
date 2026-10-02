"""Inspection model registry — resolves ``QUALITY_INSPECTION_MODEL`` honestly.

Rules:

* No configured model -> ``None`` (the engine reports
  ``INSPECTION_MODEL_NOT_CONFIGURED`` and decides ERROR — never PASS).
* Unknown model name -> ``None`` (same honest report; the name is logged).
* The scripted fixture adapter resolves ONLY outside production, so a missing
  real model is never silently replaced by synthetic observations.
"""

from __future__ import annotations

import logging

from backend.app.core.config import Settings
from backend.app.quality.inspection import InspectionModel

logger = logging.getLogger("industrial-vision.quality")

FIXTURE_MODEL_NAME = "fixture"


def resolve_inspection_model(settings: Settings) -> InspectionModel | None:
    """Return the configured inspection model, or ``None`` when unavailable."""
    name = (settings.quality_inspection_model or "").strip()
    if not name:
        return None
    if name == FIXTURE_MODEL_NAME:
        if settings.is_production:
            logger.error("fixture inspection model refused in production")
            return None
        from backend.app.quality.fixture import FixtureInspectionModel

        return FixtureInspectionModel()
    logger.error("unknown inspection model %r", name)
    return None
