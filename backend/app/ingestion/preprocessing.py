"""Basic preprocessing stage — resize / color conversion / normalize hooks.

V02 covers generic frame preparation only. Model-specific preprocessing
(mean/std normalization, letterboxing, NCHW layout) belongs to V03 and can
be added as new ``Step`` callables without changing this interface.

Steps never mutate the input array in place; OpenCV ops allocate their own
output, so no extra defensive copies are made.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import cv2
import numpy as np

Step = Callable[[np.ndarray], np.ndarray]


@dataclass
class PreprocessConfig:
    width: int | None = None
    height: int | None = None
    color: str = "bgr"  # bgr | rgb | gray
    normalize: bool = False  # scale to float32 [0, 1]; V03 extends this
    extra_steps: list[Step] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.color not in ("bgr", "rgb", "gray"):
            raise ValueError("color must be one of bgr|rgb|gray")
        if (self.width is None) != (self.height is None):
            raise ValueError("width and height must be set together")


class Preprocessor:
    """Apply an ordered, extensible chain of frame transformations."""

    def __init__(self, config: PreprocessConfig | None = None) -> None:
        self.config = config or PreprocessConfig()

    def add_step(self, step: Step) -> None:
        """Register a custom transformation (V03 model-specific hooks)."""
        self.config.extra_steps.append(step)

    def process(self, image: np.ndarray) -> np.ndarray:
        cfg = self.config
        out = image
        if cfg.width is not None and cfg.height is not None:
            if (out.shape[1], out.shape[0]) != (cfg.width, cfg.height):
                out = cv2.resize(out, (cfg.width, cfg.height))
        if cfg.color == "rgb":
            out = cv2.cvtColor(out, cv2.COLOR_BGR2RGB)
        elif cfg.color == "gray":
            out = cv2.cvtColor(out, cv2.COLOR_BGR2GRAY)
        for step in cfg.extra_steps:
            out = step(out)
        if cfg.normalize:
            out = (out.astype(np.float32) / 255.0).astype(np.float32)
        return out
