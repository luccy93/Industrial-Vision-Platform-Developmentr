"""Preprocessing tests — resize, color conversion, hooks, validation."""

from __future__ import annotations

import numpy as np
import pytest

from backend.app.ingestion.preprocessing import PreprocessConfig, Preprocessor
from backend.tests.helpers import synthetic_image


def test_resize() -> None:
    processor = Preprocessor(PreprocessConfig(width=160, height=120))
    out = processor.process(synthetic_image(320, 240))
    assert out.shape[1] == 160 and out.shape[0] == 120


def test_no_resize_when_matching() -> None:
    processor = Preprocessor(PreprocessConfig(width=320, height=240))
    image = synthetic_image(320, 240, value=7)
    out = processor.process(image)
    assert out.shape == image.shape
    assert (out == 7).all()


def test_rgb_conversion() -> None:
    processor = Preprocessor(PreprocessConfig(color="rgb"))
    image = np.zeros((4, 4, 3), dtype=np.uint8)
    image[:, :, 0] = 255  # pure blue in BGR
    out = processor.process(image)
    assert out[0, 0, 0] == 0 and out[0, 0, 2] == 255


def test_gray_conversion() -> None:
    processor = Preprocessor(PreprocessConfig(color="gray"))
    out = processor.process(synthetic_image())
    assert out.ndim == 2


def test_normalize_hook() -> None:
    processor = Preprocessor(PreprocessConfig(normalize=True))
    out = processor.process(synthetic_image(value=255))
    assert out.dtype == np.float32
    assert float(out.max()) <= 1.0


def test_custom_step_extensible_for_v03() -> None:
    processor = Preprocessor()
    processor.add_step(lambda image: image[0:120, 0:160])
    out = processor.process(synthetic_image())
    assert out.shape == (120, 160, 3)


def test_invalid_config_rejected() -> None:
    with pytest.raises(ValueError):
        PreprocessConfig(color="hsv")
    with pytest.raises(ValueError):
        PreprocessConfig(width=160, height=None)
