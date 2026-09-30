"""Deterministic mock model — unit/integration tests without weights or GPU."""

from __future__ import annotations

import numpy as np

from backend.app.inference.base import InferenceModel, ModelState, RawDetections


class MockModel(InferenceModel):
    """Returns canned detections scaled to the input frame; never touches disk."""

    def __init__(
        self,
        name: str = "mock",
        detections_per_frame: int = 2,
        device: str = "cpu",
    ) -> None:
        super().__init__(name)
        self._device = device
        self._detections_per_frame = detections_per_frame
        self.load_calls = 0

    @property
    def device(self) -> str:
        return self._device

    @property
    def class_names(self) -> dict[int, str]:
        return {0: "person", 1: "forklift", 2: "helmet"}

    def load(self) -> None:
        self.load_calls += 1
        self._mark_loaded(1.0)
        assert self._state == ModelState.READY

    def unload(self) -> None:
        self._state = ModelState.NOT_LOADED

    def predict_raw(self, image: np.ndarray) -> RawDetections:
        height, width = image.shape[0], image.shape[1]
        names = ["person", "forklift", "helmet"]
        boxes: list[tuple[float, float, float, float]] = []
        class_ids: list[int] = []
        class_names: list[str] = []
        confidences: list[float] = []
        for index in range(self._detections_per_frame):
            boxes.append(
                (
                    width * 0.1 * (index + 1),
                    height * 0.1 * (index + 1),
                    min(width * 0.1 * (index + 1) + 50.0, float(width)),
                    min(height * 0.1 * (index + 1) + 80.0, float(height)),
                )
            )
            class_ids.append(index % 3)
            class_names.append(names[index % 3])
            confidences.append(0.9 - index * 0.05)
        return RawDetections(
            boxes=boxes,
            class_ids=class_ids,
            class_names=class_names,
            confidences=confidences,
            inference_time_ms=0.5,
        )
