"""Autonomous perception WebSocket message builders.

Three typed messages join the existing V02–V07 channels:

* ``autonomous_perception`` — latest scene per frame (objects, lanes, scene
  type); sent when a new frame is perceived, keyed by frame_id.
* ``collision_risk`` — risk assessments, delta-only on (event_id, status).
* ``lane_event`` — lane-departure and lane-related events, delta-only.
  Never carries image data or base64 payloads.
"""

from __future__ import annotations

from typing import Any

from backend.app.autonomous.schemas import AutonomousPerceptionEvent, AutonomousPerceptionResult


def autonomous_perception_message(camera_id: str, result: AutonomousPerceptionResult) -> dict[str, Any]:
    payload = result.to_websocket()
    return {
        "type": "autonomous_perception",
        "camera_id": camera_id,
        "frame_id": result.frame_id,
        "timestamp": result.timestamp.isoformat(),
        "objects": payload["objects"],
        "lanes": payload["lanes"],
        "scene_type": payload["scene_type"],
        "trajectories": payload["trajectories"],
        "collision_risks": payload["collision_risks"],
        "processing_time_ms": payload["processing_time_ms"],
    }


def collision_risk_message(camera_id: str, event: AutonomousPerceptionEvent) -> dict[str, Any]:
    return {
        "type": "collision_risk",
        "camera_id": camera_id,
        "event": event.to_websocket(),
        "perception": {
            "object_ids": event.object_ids,
            "risk_level": event.risk_level.value,
        },
    }


def lane_event_message(camera_id: str, event: AutonomousPerceptionEvent) -> dict[str, Any]:
    return {
        "type": "lane_event",
        "camera_id": camera_id,
        "event": event.to_websocket(),
        "perception": {
            "object_ids": event.object_ids,
            "risk_level": event.risk_level.value,
        },
    }
