"""Event bus package — envelopes, fan-out, outbox publisher (V12)."""

from __future__ import annotations

from backend.app.events.bus import DeliveryReport, EventBus
from backend.app.events.envelope import BUS_EVENT_TYPES, EVENT_ENVELOPE_VERSION, EventEnvelope
from backend.app.events.publisher import OutboxPublisher, RedisEventSubscriber
from backend.app.events.store import OperationalEventRepository, OutboxRepository
from backend.app.events.wiring import register_remote_incident_ingest

__all__ = [
    "BUS_EVENT_TYPES",
    "EVENT_ENVELOPE_VERSION",
    "DeliveryReport",
    "EventBus",
    "EventEnvelope",
    "OperationalEventRepository",
    "OutboxPublisher",
    "OutboxRepository",
    "RedisEventSubscriber",
    "register_remote_incident_ingest",
]
