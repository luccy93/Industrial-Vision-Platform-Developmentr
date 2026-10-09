"""Operations WebSocket — one shared cross-camera feed (V13).

One connection per dashboard session multiplexes lightweight camera
lifecycle deltas plus the existing operational event messages. The
per-camera ``/ws/cameras/{camera_id}`` delta hot loop is untouched;
camera-detail views keep their dedicated sockets.

Sources (all pre-existing contracts, no new wire types):

- ``stream_status`` — camera lifecycle transitions, polled per tick from
  the stream supervisor (reuses the camera-socket builder).
- Bus events — the 18 locked ``BUS_EVENT_TYPES`` delivered through a
  per-connection ``EventBus`` subscription into the bounded manager
  queue (prioritized, backpressure-counted, slow-client isolated).

Never carried: frames, detections, tracking updates, telemetry.
Reconnecting clients re-baseline from REST (the bus is not history).
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.app.api.v1.streams_ws import _parse_subscription
from backend.app.domain.common import utcnow
from backend.app.domain.stream import StreamState

logger = logging.getLogger("industrial-vision.ws-operations")

router = APIRouter(tags=["operations"])

OPERATIONS_TICK_SECONDS = 1.0
OPERATIONS_DRAIN_LIMIT = 50


@router.websocket("/ws/operations")
async def operations_socket(websocket: WebSocket) -> None:
    await websocket.accept()
    app_state = websocket.app.state
    ws_manager = getattr(app_state, "ws_manager", None)
    bus = getattr(app_state, "event_bus", None)
    subscription = _parse_subscription(websocket)
    connection_id: str | None = None
    if ws_manager is not None:
        try:
            connection = ws_manager.connect(
                f"ws-ops-{uuid.uuid4().hex[:12]}",
                camera_id="",
                subscription=subscription,
                websocket=websocket,
            )
            connection_id = connection.connection_id
        except Exception:
            logger.debug("operations socket registration failed", exc_info=True)
            connection_id = None

    def _on_bus_event(envelope: object) -> None:
        # Runs on publisher threads: enqueue only, never block, never raise.
        try:
            event_type = str(getattr(envelope, "event_type", ""))
            camera_id = str(getattr(envelope, "camera_id", "") or "")
            domain = str(getattr(envelope, "domain", "") or "")
            if not subscription.matches(event_type, camera_id, domain):
                return
            raw = envelope.to_bytes() if hasattr(envelope, "to_bytes") else b""
            if ws_manager is not None and connection_id is not None and raw:
                ws_manager.enqueue(connection_id, raw.decode("utf-8"), event_type)
        except Exception:
            logger.debug("operations bus fan-in failed", exc_info=True)

    bus_subscription_id: str | None = None
    if bus is not None:
        try:
            bus_subscription_id = bus.subscribe(_on_bus_event)
        except Exception:
            logger.debug("operations bus subscribe failed", exc_info=True)
            bus_subscription_id = None

    async def _send(payload: dict) -> None:
        text = json.dumps(payload)
        message_type = str(payload.get("type", ""))
        if ws_manager is None or connection_id is None:
            await websocket.send_text(text)
            return
        # Lifecycle signals always pass: a filtered socket must never go
        # silently dark. Only event payloads honor the subscription filter.
        if message_type not in ("stream_status", "stream_error") and not subscription.matches(
            message_type, str(payload.get("camera_id", "") or "")
        ):
            return
        if not ws_manager.enqueue(connection_id, text, message_type):
            return
        try:
            for item in ws_manager.drain(connection_id, limit=OPERATIONS_DRAIN_LIMIT):
                await websocket.send_text(item)
        except Exception:
            ws_manager.record_failed(connection_id)
            raise
        ws_manager.record_sent(connection_id)
        ws_manager.heartbeat(connection_id)

    last_states: dict[str, str] = {}
    try:
        while True:
            supervisor = getattr(app_state, "supervisor", None)
            if supervisor is not None:
                try:
                    statuses = supervisor.statuses()
                except Exception:
                    statuses = {}
                for camera_id in sorted(statuses):
                    try:
                        state = statuses[camera_id].state
                        name = state.value if isinstance(state, StreamState) else str(state)
                    except Exception:
                        continue
                    if last_states.get(camera_id) != name:
                        last_states[camera_id] = name
                        await _send(
                            {
                                "type": "stream_status",
                                "camera_id": camera_id,
                                "state": name,
                                "timestamp": utcnow().isoformat(),
                            }
                        )
            # Drain bus-fed messages enqueued by subscriber callbacks.
            if ws_manager is not None and connection_id is not None:
                try:
                    for item in ws_manager.drain(connection_id, limit=OPERATIONS_DRAIN_LIMIT):
                        await websocket.send_text(item)
                    ws_manager.record_sent(connection_id)
                    ws_manager.heartbeat(connection_id)
                except Exception:
                    ws_manager.record_failed(connection_id)
                    raise
            await asyncio.sleep(OPERATIONS_TICK_SECONDS)
    except WebSocketDisconnect:
        logger.info("operations socket closed")
    except Exception:
        logger.exception("operations socket error")
        try:
            await websocket.close()
        except Exception:
            pass
    finally:
        if bus is not None and bus_subscription_id is not None:
            try:
                bus.unsubscribe(bus_subscription_id)
            except Exception:
                pass
        if ws_manager is not None and connection_id is not None:
            ws_manager.disconnect(connection_id)
