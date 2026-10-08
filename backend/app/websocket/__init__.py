"""WebSocket infrastructure package (V11, §25–§33)."""

from __future__ import annotations

from backend.app.websocket.manager import (
    Connection,
    MessagePriority,
    Subscription,
    WebSocketManager,
    WebSocketMetrics,
    classify_message,
)

__all__ = [
    "Connection",
    "MessagePriority",
    "Subscription",
    "WebSocketManager",
    "WebSocketMetrics",
    "classify_message",
]
