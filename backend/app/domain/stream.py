"""Stream domain contracts: source types, lifecycle states, runtime metrics.

V02 establishes the ingestion vocabulary. Stream state transitions are
explicit and deterministic — see ``StreamState.can_transition_to``.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    usb = "usb"
    rtsp = "rtsp"
    file = "file"


class StreamState(str, Enum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    ERROR = "ERROR"
    RECONNECTING = "RECONNECTING"

    def can_transition_to(self, target: StreamState) -> bool:
        return target in _ALLOWED_TRANSITIONS[self]


_ALLOWED_TRANSITIONS: dict[StreamState, frozenset[StreamState]] = {
    StreamState.DISCONNECTED: frozenset({StreamState.CONNECTING, StreamState.STOPPED}),
    StreamState.CONNECTING: frozenset(
        {StreamState.CONNECTED, StreamState.ERROR, StreamState.STOPPED, StreamState.STOPPING}
    ),
    StreamState.CONNECTED: frozenset(
        {StreamState.RUNNING, StreamState.ERROR, StreamState.STOPPING, StreamState.STOPPED}
    ),
    StreamState.RUNNING: frozenset(
        {
            StreamState.STOPPING,
            StreamState.STOPPED,
            StreamState.ERROR,
            StreamState.RECONNECTING,
        }
    ),
    StreamState.RECONNECTING: frozenset(
        {StreamState.CONNECTING, StreamState.CONNECTED, StreamState.ERROR, StreamState.STOPPED}
    ),
    StreamState.ERROR: frozenset(
        {StreamState.RECONNECTING, StreamState.CONNECTING, StreamState.STOPPED, StreamState.STOPPING}
    ),
    StreamState.STOPPING: frozenset({StreamState.STOPPED, StreamState.ERROR}),
    StreamState.STOPPED: frozenset({StreamState.CONNECTING, StreamState.DISCONNECTED}),
}


class StreamMetrics(BaseModel):
    """Point-in-time runtime telemetry for one stream (memory only, never persisted)."""

    camera_id: str = Field(min_length=1, max_length=128)
    state: StreamState = StreamState.DISCONNECTED
    source_fps: float = Field(default=0.0, ge=0.0)
    processing_fps: float = Field(default=0.0, ge=0.0)
    frames_received: int = Field(default=0, ge=0)
    frames_processed: int = Field(default=0, ge=0)
    frames_dropped: int = Field(default=0, ge=0)
    latency_ms: float = Field(default=0.0, ge=0.0)
    width: int | None = Field(default=None, ge=1)
    height: int | None = Field(default=None, ge=1)
    uptime_seconds: float = Field(default=0.0, ge=0.0)
    reconnect_count: int = Field(default=0, ge=0)

    model_config = {"use_enum_values": False}


def redact_source(source: str) -> str:
    """Redact credentials from RTSP URLs for safe logging / API responses.

    ``rtsp://user:secret@host/stream`` → ``rtsp://user:***@host/stream``.
    Non-credential sources are returned unchanged.
    """
    if "://" not in source or "@" not in source:
        return source
    try:
        scheme, rest = source.split("://", 1)
        userinfo, host = rest.rsplit("@", 1)
        if ":" in userinfo:
            user, _secret = userinfo.split(":", 1)
            return f"{scheme}://{user}:***@{host}"
        return f"{scheme}://***@{host}"
    except ValueError:
        return source
