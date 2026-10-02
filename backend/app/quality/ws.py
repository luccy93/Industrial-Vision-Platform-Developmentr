"""Quality WebSocket message builders.

Two typed messages join the existing V02–V06 channels:

* ``quality_event``  — inspection-level (QUALITY_FAIL/REVIEW/ERROR) and
  defect-level (DEFECT_DETECTED) events, delta-only on (event_id, status).
* ``quality_result`` — one message per completed inspection, keyed by
  inspection_id. Never carries image data or base64 payloads.
"""

from __future__ import annotations

from typing import Any

from backend.app.quality.schemas import InspectionResult, QualityEvent


def quality_event_message(camera_id: str, event: QualityEvent) -> dict[str, Any]:
    return {
        "type": "quality_event",
        "camera_id": camera_id,
        "event": event.to_websocket(),
        "quality": {
            "defect_code": event.defect_code,
            "region_id": event.region_id,
            "error_code": event.metadata.get("error_code"),
        },
    }


def quality_result_message(camera_id: str, result: InspectionResult) -> dict[str, Any]:
    return {
        "type": "quality_result",
        "camera_id": camera_id,
        "result": result.to_websocket(),
    }
