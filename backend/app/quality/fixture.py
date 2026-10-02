"""Scripted fixture inspection model — a deterministic test double, never a real model.

The fixture adapter returns explicitly supplied observations. It does NOT
invent defects, use random values, or run a defect model. It exists so the
decision pipeline can be exercised end-to-end without specialized weights:

    FixtureInspectionModel(observations=[...])      -> returns exactly those
    FixtureInspectionModel(error_code="...")        -> raises InspectionModelError

The production registry refuses to resolve this adapter outside dev/testing:
a missing real model must never be silently replaced by synthetic
observations.
"""

from __future__ import annotations

from uuid import UUID

import numpy as np

from backend.app.quality.inspection import (
    InspectionErrorCode,
    InspectionModel,
    InspectionModelError,
    RawDefect,
)


class FixtureInspectionModel(InspectionModel):
    """Returns a scripted list of :class:`RawDefect` observations (or a scripted error)."""

    def __init__(
        self,
        observations: list[RawDefect] | None = None,
        error_code: InspectionErrorCode | None = None,
        name: str = "fixture-inspection",
    ) -> None:
        super().__init__(name=name, version="0.0.0-fixture")
        self._observations = list(observations or [])
        self._error_code = error_code

    def _load(self) -> None:
        return None

    def predict(
        self,
        roi: np.ndarray,
        *,
        camera_id: str,
        frame_id: UUID | None,
        region_id: str,
    ) -> list[RawDefect]:
        if self._error_code is not None:
            raise InspectionModelError(
                self._error_code, f"fixture inspection error: {self._error_code.value}"
            )
        # The fixture never analyzes pixels — it only validates the ROI contract.
        if not isinstance(roi, np.ndarray) or roi.ndim not in (2, 3) or roi.size == 0:
            raise InspectionModelError(
                InspectionErrorCode.FRAME_INVALID, "fixture received an invalid ROI crop"
            )
        return list(self._observations)
