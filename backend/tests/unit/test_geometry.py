"""Spatial geometry tests — pure functions, deterministic."""

from __future__ import annotations

import pytest

from backend.app.spatial import geometry

_SQUARE = [(0.2, 0.2), (0.8, 0.2), (0.8, 0.8), (0.2, 0.8)]


def test_point_in_polygon_inside_outside() -> None:
    assert geometry.point_in_polygon(0.5, 0.5, _SQUARE) is True
    assert geometry.point_in_polygon(0.05, 0.5, _SQUARE) is False
    assert geometry.point_in_polygon(0.5, 0.95, _SQUARE) is False


def test_point_in_polygon_degenerate() -> None:
    assert geometry.point_in_polygon(0.5, 0.5, []) is False
    assert geometry.point_in_polygon(0.5, 0.5, [(0.0, 0.0), (1.0, 1.0)]) is False


def test_bbox_center_and_bottom_center() -> None:
    assert geometry.bbox_center((100.0, 100.0, 200.0, 300.0)) == (150.0, 200.0)
    assert geometry.bbox_bottom_center((100.0, 100.0, 200.0, 300.0)) == (150.0, 300.0)


def test_iou_and_overlap() -> None:
    assert geometry.bbox_iou((0.0, 0.0, 1.0, 1.0), (0.0, 0.0, 1.0, 1.0)) == 1.0
    assert geometry.bbox_iou((0.0, 0.0, 1.0, 1.0), (2.0, 2.0, 3.0, 3.0)) == 0.0
    assert geometry.bbox_overlap_ratio((0.0, 0.0, 1.0, 1.0), (0.25, 0.25, 0.75, 0.75)) == 1.0


def test_polygon_bbox_overlap_estimates() -> None:
    full = geometry.polygon_bbox_overlap(_SQUARE, (0.3, 0.3, 0.7, 0.7))
    assert full > 0.9
    outside = geometry.polygon_bbox_overlap(_SQUARE, (0.85, 0.85, 0.95, 0.95))
    assert outside < 0.5


def test_distance() -> None:
    assert geometry.distance_between_points((0.0, 0.0), (3.0, 4.0)) == 5.0


def test_normalized_pixel_round_trip() -> None:
    px = geometry.normalized_to_pixel(0.5, 0.25, 640.0, 480.0)
    assert px == (320.0, 120.0)
    back = geometry.pixel_to_normalized(*px, 640.0, 480.0)
    assert back == (0.5, 0.25)
    with pytest.raises(ValueError):
        geometry.pixel_to_normalized(1.0, 1.0, 0.0, 480.0)
