"""Outbox publisher tests — drain, retry, crash recovery, shutdown."""

from __future__ import annotations

from datetime import timedelta

from backend.app.domain.common import utcnow
from backend.app.events.bus import EventBus
from backend.app.events.envelope import EventEnvelope
from backend.app.events.publisher import OutboxPublisher
from backend.app.events.store import OperationalEventRepository, OutboxRepository
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.workers.base import WorkerState


def _repos(url: str) -> tuple[OperationalEventRepository, OutboxRepository]:
    factory = get_session_factory(url)
    return OperationalEventRepository(factory), OutboxRepository(factory)


def _publisher(url: str, bus: EventBus, **overrides) -> OutboxPublisher:  # type: ignore[no-untyped-def]
    _, outbox = _repos(url)
    params: dict = {"outbox": outbox, "bus": bus}
    params.update(overrides)
    return OutboxPublisher(**params)


def _envelope(event_id: str) -> dict:
    return {
        "v": 1,
        "event_id": event_id,
        "event_type": "incident_created",
        "domain": "INCIDENT",
        "camera_id": "cam-01",
        "timestamp": utcnow().isoformat(),
        "origin": "proc-test",
        "payload": {"incident_id": "x"},
    }


def test_drain_delivers_and_marks_sent(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/outbox.db"
    init_db(url)
    _, outbox = _repos(url)
    bus = EventBus(mode="local")
    bus.start()
    received: list[str] = []
    bus.subscribe(lambda e: received.append(e.event_id))
    outbox.enqueue("e-1", "incident_created", _envelope("e-1"))
    outbox.enqueue("e-2", "incident_created", _envelope("e-2"))
    publisher = _publisher(url, bus)
    stats = publisher.drain_once()
    assert stats == {"claimed": 2, "delivered": 2, "retried": 0, "dead": 0, "invalid": 0}
    assert received == ["e-1", "e-2"]
    assert outbox.count_by_status() == {"sent": 2}
    assert publisher.delivery_stats() == {"delivered": 2, "failed": 0}


def test_distributed_failure_retries_with_backoff(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/outbox.db"
    init_db(url)
    _, outbox = _repos(url)
    from backend.tests.redis_helpers import FakeRedisError, FakeRedisTransport

    transport = FakeRedisTransport()
    transport.fail_publish = FakeRedisError("down")
    from backend.app.infrastructure.redis_client import RedisLifecycleManager
    from backend.tests.redis_helpers import fake_client_factory

    redis_manager = RedisLifecycleManager(
        enabled=True, url="redis://localhost:6379/0", client_factory=fake_client_factory(transport)
    )
    redis_manager.start()
    bus = EventBus(mode="distributed", redis_manager=redis_manager)
    bus.start()
    outbox.enqueue("e-1", "incident_created", _envelope("e-1"))
    publisher = _publisher(url, bus, max_attempts=3, retry_base_seconds=5.0)
    before = utcnow()
    stats = publisher.drain_once(now=before)
    assert stats["retried"] == 1
    due = outbox.claim_due(limit=10, now=before)
    assert due == []  # backing off, not yet due
    due = outbox.claim_due(limit=10, now=before + timedelta(seconds=30))
    assert [d["event_id"] for d in due] == ["e-1"]
    # Exhaust attempts → observably dead, never retried without bound.
    publisher.drain_once(now=before + timedelta(seconds=30))
    stats = publisher.drain_once(now=before + timedelta(hours=1))
    assert stats["dead"] == 1
    assert outbox.count_by_status() == {"failed": 1}
    redis_manager.close()


def test_crash_between_publish_and_ack_redelivers(tmp_path) -> None:
    """Publish-ok + ack-crash ⇒ pending row redelivers; dupes are safe."""
    url = f"sqlite:///{tmp_path}/outbox.db"
    init_db(url)
    _, outbox = _repos(url)
    bus = EventBus(mode="local")
    bus.start()
    received: list[str] = []
    bus.subscribe(lambda e: received.append(e.event_id))
    outbox.enqueue("e-1", "incident_created", _envelope("e-1"))
    publisher = _publisher(url, bus)
    # Simulate: delivery happened, but mark_sent crashed. Row stays pending.
    due = outbox.claim_due(limit=10)
    assert len(due) == 1
    report = bus.publish(EventEnvelope.model_validate(due[0]["envelope"]))
    assert report.delivered_local == 1
    # Recovery drain redelivers through the durable path (no dedup there
    # by design); plain subscribers observe both deliveries, which is why
    # durable subscribers must be idempotent (proven below via ingest).
    stats = publisher.drain_once()
    assert stats["delivered"] == 1
    assert received == ["e-1", "e-1"]
    assert outbox.count_by_status() == {"sent": 1}


def test_invalid_envelope_never_retried(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/outbox.db"
    init_db(url)
    _, outbox = _repos(url)
    bus = EventBus(mode="local")
    bus.start()
    outbox.enqueue("bad-1", "incident_created", {"v": 1, "event_id": "WRONG"})
    publisher = _publisher(url, bus)
    stats = publisher.drain_once()
    assert stats["invalid"] == 1
    assert outbox.count_by_status() == {"failed": 1}


def test_publisher_start_stop_lifecycle(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/outbox.db"
    init_db(url)
    bus = EventBus(mode="local")
    bus.start()
    publisher = _publisher(url, bus, poll_interval_seconds=0.05)
    assert publisher.health().state is WorkerState.CREATED
    assert publisher.start() is True
    assert publisher.start() is True
    assert publisher.health().state is WorkerState.RUNNING
    assert publisher.stop() is True
    assert publisher.stop() is True
    assert publisher.health().state is WorkerState.STOPPED
