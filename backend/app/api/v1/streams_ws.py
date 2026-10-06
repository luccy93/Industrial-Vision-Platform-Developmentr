"""WebSocket foundation — stream telemetry channel (V02).

Contract (JSON text frames only, ~2 Hz):

- ``stream_status`` — lifecycle transitions (CONNECTING/CONNECTED/RUNNING/…)
- ``frame`` — latest frame *metadata* (no image bytes)
- ``stream_error`` — failure detail with stable code

Raw/base64 video, detections, and tracking are explicitly out of scope
until later volumes (video transport will use a browser-appropriate
mechanism, not this channel).
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.app.api.v1.cameras import _fallback_supervisor
from backend.app.domain.common import utcnow
from backend.app.domain.stream import StreamState
from backend.app.ingestion.repository import CameraRepository
from backend.app.safety.schemas import SafetyEvent

logger = logging.getLogger("industrial-vision.ws")

router = APIRouter(tags=["streams"])


def _status_message(camera_id: str, state: StreamState) -> dict:
    return {
        "type": "stream_status",
        "camera_id": camera_id,
        "state": state.value,
        "timestamp": utcnow().isoformat(),
    }


def _spatial_message_type(event: SafetyEvent) -> str:
    """V06 adds typed spatial channels without changing the V05 contract.

    Routing is rule-based, not type-based: the V05 ``person_vehicle_proximity``
    rule emits the same ``PERSON_VEHICLE_PROXIMITY`` type as the V06
    relationship rule, and only the latter belongs on the spatial channels.
    """
    rule = str(event.metadata.get("rule", ""))
    if rule == "restricted_zone":
        return "zone_event"
    if rule == "proximity_relationships":
        return "proximity_event"
    return "safety_event"


@router.websocket("/ws/cameras/{camera_id}")
async def camera_stream_socket(
    websocket: WebSocket,
    camera_id: str,
) -> None:
    await websocket.accept()
    # Resolve dependencies manually (WebSocket routes bypass Depends(get_db)).
    from backend.app.infrastructure.db import get_session_factory

    factory = getattr(websocket.app.state, "session_factory", None)
    if factory is None:
        factory = get_session_factory()
    repository = CameraRepository(factory)
    supervisor = getattr(websocket.app.state, "supervisor", None) or _fallback_supervisor
    inference_supervisor = getattr(websocket.app.state, "inference_supervisor", None)
    safety_engine = getattr(websocket.app.state, "safety_engine", None)
    quality_engine = getattr(websocket.app.state, "quality_engine", None)
    autonomous_engine = getattr(websocket.app.state, "autonomous_engine", None)
    intelligence_engine = getattr(websocket.app.state, "intelligence_engine", None)
    camera = repository.get(camera_id)
    if camera is None:
        await websocket.send_text(
            json.dumps(
                {
                    "type": "stream_error",
                    "camera_id": camera_id,
                    "code": "CAMERA_NOT_FOUND",
                    "message": "Camera is not configured.",
                    "timestamp": utcnow().isoformat(),
                }
            )
        )
        await websocket.close()
        return

    last_state: StreamState | None = None
    last_detection_id: str | None = None
    last_tracked_id: str | None = None
    sent_safety: dict[str, str] = {}
    sent_quality: dict[str, str] = {}
    sent_results: set[str] = set()
    sent_perception: dict[str, str] = {}
    last_perception_id: str | None = None
    sent_intelligence: dict[str, str] = {}
    sent_clusters: dict[str, str] = {}
    sent_risk: dict[str, tuple[str, str]] = {}
    try:
        while True:
            manager = supervisor.get(camera_id)
            state = manager.state if manager else StreamState.DISCONNECTED
            if state != last_state:
                await websocket.send_text(json.dumps(_status_message(camera_id, state)))
                last_state = state
            if inference_supervisor is not None:
                worker = inference_supervisor.get(camera_id)
                latest = worker.latest() if worker else None
                if latest is not None and str(latest.frame_id) != last_detection_id:
                    last_detection_id = str(latest.frame_id)
                    await websocket.send_text(json.dumps(latest.to_websocket()))
                tracked_id, tracks = worker.latest_tracked() if worker else (None, [])
                if tracked_id is not None and str(tracked_id) != last_tracked_id:
                    last_tracked_id = str(tracked_id)
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "tracking",
                                "camera_id": camera_id,
                                "frame_id": str(tracked_id),
                                "timestamp": utcnow().isoformat(),
                                "tracks": [track.to_websocket() for track in tracks],
                            }
                        )
                    )
            if safety_engine is not None:
                # First pass publishes current state; afterwards only deltas
                # (new events, status changes incl. resolutions).
                candidates = list(safety_engine.active_events(camera_id, 50))
                for event in candidates + safety_engine.recent_events(camera_id, 10):
                    key = str(event.event_id)
                    if sent_safety.get(key) == event.status.value:
                        continue
                    sent_safety[key] = event.status.value
                    message = {
                        "type": _spatial_message_type(event),
                        "camera_id": camera_id,
                        "event": event.to_websocket(),
                    }
                    if message["type"] != "safety_event":
                        # V06 keeps V05 payloads intact and adds typed channels.
                        message["spatial"] = event.evidence
                    await websocket.send_text(json.dumps(message))
            if quality_engine is not None:
                # V07: quality events (delta-only) + one message per inspection.
                from backend.app.quality.ws import quality_event_message, quality_result_message

                for event in quality_engine.active_events(camera_id, 50) + quality_engine.recent_events(
                    camera_id, 10
                ):
                    key = str(event.event_id)
                    if sent_quality.get(key) == event.status.value:
                        continue
                    sent_quality[key] = event.status.value
                    await websocket.send_text(json.dumps(quality_event_message(camera_id, event)))
                for result in quality_engine.recent_results(camera_id, 5):
                    key = str(result.inspection_id)
                    if key in sent_results:
                        continue
                    sent_results.add(key)
                    await websocket.send_text(json.dumps(quality_result_message(camera_id, result)))
            if autonomous_engine is not None:
                # V08: latest scene per frame + delta-only perception events.
                # COLLISION_RISK travels on `collision_risk`; every other
                # perception event (departure, approach, crossing, scene
                # change) travels on `lane_event` — the embedded
                # `event.event_type` always identifies the true kind.
                from backend.app.autonomous.ws import (
                    autonomous_perception_message,
                    collision_risk_message,
                    lane_event_message,
                )

                latest = autonomous_engine.latest_result(camera_id)
                if latest is not None and str(latest.scene_id) != last_perception_id:
                    last_perception_id = str(latest.scene_id)
                    await websocket.send_text(json.dumps(autonomous_perception_message(camera_id, latest)))
                for event in autonomous_engine.active_events(camera_id, 50) + autonomous_engine.recent_events(
                    camera_id, 10
                ):
                    key = str(event.event_id)
                    if sent_perception.get(key) == event.status.value:
                        continue
                    sent_perception[key] = event.status.value
                    if event.event_type.value == "COLLISION_RISK":
                        message = collision_risk_message(camera_id, event)
                    else:
                        message = lane_event_message(camera_id, event)
                    await websocket.send_text(json.dumps(message))
            if intelligence_engine is not None:
                # V09: unified-event deltas, cluster deltas (status or risk
                # level changes re-publish so escalation is visible), and a
                # per-camera highest-risk summary whenever it changes.
                from backend.app.intelligence.ws import (
                    intelligence_event_message,
                    risk_cluster_message,
                    risk_update_message,
                )

                for event in intelligence_engine.active_events(
                    camera_id, 50
                ) + intelligence_engine.recent_events(camera_id, 10):
                    key = str(event.event_id)
                    if sent_intelligence.get(key) == event.status.value:
                        continue
                    sent_intelligence[key] = event.status.value
                    await websocket.send_text(json.dumps(intelligence_event_message(camera_id, event)))
                clusters = list(intelligence_engine.active_clusters(camera_id, 50))
                clusters += list(intelligence_engine.recent_clusters(camera_id, 10))
                for cluster in clusters:
                    key = (
                        f"{cluster.cluster_id}:{cluster.status.value}:"
                        f"{cluster.risk_assessment.risk_level.value}"
                    )
                    if sent_clusters.get(str(cluster.cluster_id)) == key:
                        continue
                    sent_clusters[str(cluster.cluster_id)] = key
                    await websocket.send_text(json.dumps(risk_cluster_message(camera_id, cluster)))
                latest = intelligence_engine.latest(camera_id)
                if latest is not None:
                    signature = (latest.highest_risk.risk_level.value, latest.highest_priority.value)
                    if sent_risk.get(camera_id) != signature:
                        sent_risk[camera_id] = signature
                        await websocket.send_text(
                            json.dumps(
                                risk_update_message(
                                    camera_id,
                                    latest.highest_risk,
                                    latest.highest_priority,
                                    latest.timestamp.isoformat(),
                                )
                            )
                        )
            if manager is not None:
                if manager.last_error and state == StreamState.ERROR:
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "stream_error",
                                "camera_id": camera_id,
                                "code": "STREAM_DISCONNECTED",
                                "message": "Camera stream disconnected",
                                "timestamp": utcnow().isoformat(),
                            }
                        )
                    )
                frame = manager.latest_frame()
                metrics = manager.status()
                if frame is not None:
                    payload = frame.model_dump_safe()
                    payload.update(
                        {
                            "type": "frame",
                            "source_fps": metrics.source_fps,
                            "processing_fps": metrics.processing_fps,
                            "latency_ms": metrics.latency_ms,
                            "frames_dropped": metrics.frames_dropped,
                            "stream_state": state.value,
                        }
                    )
                    await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        logger.info("ws closed for camera %s", camera_id)
    except Exception:
        logger.exception("ws error for camera %s", camera_id)
        try:
            await websocket.close()
        except Exception:
            pass
