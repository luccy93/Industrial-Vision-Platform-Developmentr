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

logger = logging.getLogger("industrial-vision.ws")

router = APIRouter(tags=["streams"])


def _status_message(camera_id: str, state: StreamState) -> dict:
    return {
        "type": "stream_status",
        "camera_id": camera_id,
        "state": state.value,
        "timestamp": utcnow().isoformat(),
    }


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
