"""Shared outbox/event fixtures for V19 reliability tests.

The outbox publisher validates every stored envelope via
``EventEnvelope.model_validate`` and requires ``envelope.event_id`` to match the
row's ``event_id``. These helpers build complete, valid envelopes so tests
exercise the real serialization/deserialization path instead of bypassing
validation with malformed payloads.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from backend.app.events.envelope import EventEnvelope


def make_event_envelope(
    index: int,
    *,
    event_type: str = "incident_created",
    domain: str = "INCIDENT",
    origin: str = "test-bench",
    camera_id: str = "",
    prefix: str = "evt",
    timestamp: datetime | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one valid, deterministic ``EventEnvelope`` as a JSON-safe dict.

    ``index`` is folded into the event ID so every event is unique, which the
    outbox's idempotent enqueue path depends on.
    """
    event_id = f"{prefix}-{index}"
    envelope = EventEnvelope(
        event_id=event_id,
        event_type=event_type,
        domain=domain,
        camera_id=camera_id,
        timestamp=timestamp or datetime(2026, 1, 1, tzinfo=UTC),
        origin=origin,
        payload=payload if payload is not None else {"seq": index},
    )
    return envelope.model_dump(mode="json")


def drain_all(publisher: Any, *, now: datetime | None = None, max_rounds: int = 1000) -> dict[str, int]:
    """Repeatedly call ``drain_once`` until no rows are claimed.

    ``drain_once`` processes exactly one ``batch_size`` batch; tests that
    enqueue more than one batch must drain repeatedly to reach an empty
    outbox. Returns the summed stats across every round.
    """
    totals = {"claimed": 0, "delivered": 0, "retried": 0, "dead": 0, "invalid": 0}
    rounds = 0
    while rounds < max_rounds:
        stats = publisher.drain_once(now)
        if stats["claimed"] == 0:
            break
        for key in totals:
            totals[key] += stats.get(key, 0)
        rounds += 1
    return totals
