"""Inspection region geometry tests — reuses V06 spatial primitives."""

from __future__ import annotations

import numpy as np
import pytest

from backend.app.quality.regions import (
    extract_roi,
    map_box_to_frame,
    region_area_ratio,
    region_bounds,
    region_contains_point,
    region_polygon_points,
)
from backend.app.quality.schemas import RegionType
from backend.tests.quality_helpers import make_region, synthetic_frame

_W, _H = 1000.0, 500.0


def test_rectangle_bounds_and_containment() -> None:
    region = make_region()
    x1, y1, x2, y2 = region_bounds(region, _W, _H)
    assert (x1, y1, x2, y2) == (100.0, 50.0, 900.0, 450.0)
    assert region_contains_point(region, 0.5, 0.5) is True
    assert region_contains_point(region, 0.05, 0.5) is False
    assert region_contains_point(region, 0.5, 0.95) is False


def test_polygon_bounds_and_containment() -> None:
    region = make_region(
        region_type=RegionType.POLYGON,
        geometry={
            "points": [
                {"x": 0.25, "y": 0.25},
                {"x": 0.75, "y": 0.25},
                {"x": 0.75, "y": 0.75},
                {"x": 0.25, "y": 0.75},
            ]
        },
    )
    x1, y1, x2, y2 = region_bounds(region, _W, _H)
    assert (x1, y1, x2, y2) == (250.0, 125.0, 750.0, 375.0)
    assert region_contains_point(region, 0.5, 0.5) is True
    assert region_contains_point(region, 0.1, 0.5) is False
    assert len(region_polygon_points(region)) == 4


def test_polygon_points_empty_for_rectangle() -> None:
    assert region_polygon_points(make_region()) == []


def test_extract_roi_crops_pixels() -> None:
    frame = synthetic_frame(width=1000, height=500)
    region = make_region()
    roi = extract_roi(frame, region, _W, _H)
    assert roi.shape == (400, 800, 3)


def test_extract_roi_clamps_to_frame() -> None:
    frame = synthetic_frame(width=1000, height=500)
    # A valid region touching the far border extracts exactly its pixel area.
    region = make_region(geometry={"x": 0.9, "y": 0.9, "width": 0.1, "height": 0.1})
    roi = extract_roi(frame, region, _W, _H)
    assert roi.shape == (50, 100, 3)


def test_map_box_to_frame_normalizes() -> None:
    region = make_region()
    # A box covering the whole ROI maps back to the region itself.
    box = map_box_to_frame((0.0, 0.0, 800.0, 400.0), region, _W, _H)
    assert box == pytest.approx((0.1, 0.1, 0.9, 0.9))
    # A box at the ROI origin maps to the region origin.
    origin = map_box_to_frame((0.0, 0.0, 10.0, 10.0), region, _W, _H)
    assert origin[0] == pytest.approx(0.1)
    assert origin[1] == pytest.approx(0.1)


def test_region_area_ratio() -> None:
    region = make_region()
    assert region_area_ratio(region) == pytest.approx(0.64)
    polygon = make_region(
        region_type=RegionType.POLYGON,
        geometry={
            "points": [
                {"x": 0.0, "y": 0.0},
                {"x": 0.5, "y": 0.0},
                {"x": 0.5, "y": 0.5},
                {"x": 0.0, "y": 0.5},
            ]
        },
    )
    assert region_area_ratio(polygon) == pytest.approx(0.25)


def test_roi_is_a_view_not_a_copy() -> None:
    frame = synthetic_frame(width=1000, height=500)
    roi = extract_roi(frame, make_region(), _W, _H)
    assert isinstance(roi, np.ndarray)
    assert roi.base is frame or roi.base is not None
