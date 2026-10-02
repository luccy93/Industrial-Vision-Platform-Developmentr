"""Zone geometry engine — pure functions over normalized coordinates.

All inputs/outputs are documented per function. Person/vehicle membership
uses the bounding-box **bottom-center** as a ground-contact approximation
(image-space heuristic). Nothing here knows about cameras, tracks, or events.
"""

from __future__ import annotations


def point_in_polygon(x: float, y: float, polygon: list[tuple[float, float]]) -> bool:
    """Ray-casting containment. Points on edges count as inside."""
    inside = False
    count = len(polygon)
    if count < 3:
        return False
    j = count - 1
    for i in range(count):
        xi, yi = polygon[i]
        xj, yj = polygon[j]
        if (yi > y) != (yj > y):
            intersect = (xj - xi) * (y - yi) / (yj - yi) + xi
            if x <= intersect:
                inside = not inside
        j = i
    return inside


def bbox_center(box: tuple[float, float, float, float]) -> tuple[float, float]:
    x1, y1, x2, y2 = box
    return ((x1 + x2) / 2.0, (y1 + y2) / 2.0)


def bbox_bottom_center(box: tuple[float, float, float, float]) -> tuple[float, float]:
    x1, _y1, x2, y2 = box
    return ((x1 + x2) / 2.0, y2)


def bbox_area(box: tuple[float, float, float, float]) -> float:
    return max(0.0, box[2] - box[0]) * max(0.0, box[3] - box[1])


def bbox_iou(a: tuple[float, float, float, float], b: tuple[float, float, float, float]) -> float:
    inter_w = max(0.0, min(a[2], b[2]) - max(a[0], b[0]))
    inter_h = max(0.0, min(a[3], b[3]) - max(a[1], b[1]))
    inter = inter_w * inter_h
    union = bbox_area(a) + bbox_area(b) - inter
    return inter / union if union > 0 else 0.0


def bbox_overlap_ratio(a: tuple[float, float, float, float], b: tuple[float, float, float, float]) -> float:
    """Intersection over the *smaller* box — containment-sensitive overlap."""
    inter_w = max(0.0, min(a[2], b[2]) - max(a[0], b[0]))
    inter_h = max(0.0, min(a[3], b[3]) - max(a[1], b[1]))
    smaller = min(bbox_area(a), bbox_area(b))
    return (inter_w * inter_h) / smaller if smaller > 0 else 0.0


def polygon_bbox_overlap(polygon: list[tuple[float, float]], box: tuple[float, float, float, float]) -> float:
    """Fraction of sampled box points inside the polygon (0..1, grid estimate)."""
    if not polygon or bbox_area(box) <= 0:
        return 0.0
    nx, ny = 8, 8
    hits = 0
    total = 0
    for ix in range(nx):
        for iy in range(ny):
            x = box[0] + (box[2] - box[0]) * (ix + 0.5) / nx
            y = box[1] + (box[3] - box[1]) * (iy + 0.5) / ny
            total += 1
            if point_in_polygon(x, y, polygon):
                hits += 1
    return hits / total if total else 0.0


def distance_between_points(a: tuple[float, float], b: tuple[float, float]) -> float:
    return ((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2) ** 0.5


def normalized_to_pixel(x: float, y: float, width: float, height: float) -> tuple[float, float]:
    return (x * width, y * height)


def pixel_to_normalized(x: float, y: float, width: float, height: float) -> tuple[float, float]:
    if width <= 0 or height <= 0:
        raise ValueError("frame dimensions must be positive")
    return (
        min(1.0, max(0.0, x / width)),
        min(1.0, max(0.0, y / height)),
    )
