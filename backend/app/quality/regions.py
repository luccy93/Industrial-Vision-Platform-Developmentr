"""Inspection region geometry — reuses the V06 spatial primitives.

V06 owns zone geometry; V07 owns inspection *regions*. Both share the same
normalized-coordinate contract (x, y in [0, 1]) and the same polygon point
validation, so the rules are defined exactly once in
``backend.app.spatial``/``backend.app.spatial.geometry``.
"""

from __future__ import annotations

import numpy as np

from backend.app.quality.schemas import InspectionRegion, RegionType
from backend.app.spatial.geometry import (
    bbox_area,
    normalized_to_pixel,
    pixel_to_normalized,
    point_in_polygon,
    polygon_bbox_overlap,
)


def region_bounds(
    region: InspectionRegion, frame_width: float, frame_height: float
) -> tuple[float, float, float, float]:
    """Pixel-space ``(x1, y1, x2, y2)`` bounds of a region (clamped by caller)."""
    if region.region_type is RegionType.RECTANGLE:
        geometry = region.geometry
        x1, y1 = normalized_to_pixel(float(geometry["x"]), float(geometry["y"]), frame_width, frame_height)
        x2, y2 = normalized_to_pixel(
            float(geometry["x"]) + float(geometry["width"]),
            float(geometry["y"]) + float(geometry["height"]),
            frame_width,
            frame_height,
        )
        return (x1, y1, x2, y2)
    points = region_polygon_points(region)
    xs = [normalized_to_pixel(x, 0.0, frame_width, frame_height)[0] for x, _ in points]
    ys = [normalized_to_pixel(0.0, y, frame_width, frame_height)[1] for _, y in points]
    return (min(xs), min(ys), max(xs), max(ys))


def region_polygon_points(region: InspectionRegion) -> list[tuple[float, float]]:
    """Normalized polygon vertices (empty for rectangles)."""
    if region.region_type is not RegionType.POLYGON:
        return []
    return [(float(p["x"]), float(p["y"])) for p in region.geometry.get("points", [])]


def extract_roi(
    image: np.ndarray, region: InspectionRegion, frame_width: float, frame_height: float
) -> np.ndarray:
    """Crop a region out of a BGR uint8 frame.

    The crop is clamped to the frame so a region touching the border can never
    raise; an empty crop is the caller's signal that the region is degenerate.
    """
    x1, y1, x2, y2 = region_bounds(region, frame_width, frame_height)
    ix1 = max(0, int(x1))
    iy1 = max(0, int(y1))
    ix2 = min(max(1, int(frame_width)), max(ix1 + 1, int(np.ceil(x2))))
    iy2 = min(max(1, int(frame_height)), max(iy1 + 1, int(np.ceil(y2))))
    return image[iy1:iy2, ix1:ix2]


def map_box_to_frame(
    box: tuple[float, float, float, float],
    region: InspectionRegion,
    frame_width: float,
    frame_height: float,
) -> tuple[float, float, float, float]:
    """Map an ROI-pixel box back to full-frame normalized coordinates."""
    x1, y1, _, _ = region_bounds(region, frame_width, frame_height)
    rx1, ry1, rx2, ry2 = box
    left, top = pixel_to_normalized(x1 + rx1, y1 + ry1, frame_width, frame_height)
    right, bottom = pixel_to_normalized(x1 + rx2, y1 + ry2, frame_width, frame_height)
    return (left, top, right, bottom)


def region_contains_point(region: InspectionRegion, x: float, y: float) -> bool:
    """Normalized-coordinate containment test for a region."""
    if region.region_type is RegionType.RECTANGLE:
        geometry = region.geometry
        return float(geometry["x"]) <= x <= float(geometry["x"]) + float(geometry["width"]) and float(
            geometry["y"]
        ) <= y <= float(geometry["y"]) + float(geometry["height"])
    return point_in_polygon(x, y, region_polygon_points(region))


def region_area_ratio(region: InspectionRegion) -> float:
    """Approximate region area as a fraction of the frame (0..1)."""
    if region.region_type is RegionType.RECTANGLE:
        geometry = region.geometry
        return float(geometry["width"]) * float(geometry["height"])
    points = region_polygon_points(region)
    if len(points) < 3:
        return 0.0
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    bbox = (min(xs), min(ys), max(xs), max(ys))
    return polygon_bbox_overlap(points, bbox) * bbox_area(bbox)
