"""Outbox performance and correctness tests (V19)."""

from __future__ import annotations

import time

from backend.app.events.publisher import OutboxPublisher
from backend.app.events.store import OutboxRepository
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.tests.outbox_fixtures import drain_all, make_event_envelope


def test_outbox_throughput(tmp_path):
    db_url = f"sqlite:///{tmp_path}/o.db"
    init_db(db_url)
    factory = get_session_factory(db_url)
    outbox = OutboxRepository(factory)

    n = 200
    for i in range(n):
        env = make_event_envelope(i)
        outbox.enqueue(env["event_id"], "incident_created", env)

    delivered = {"count": 0}

    class Bus:
        def deliver_durable(self, env):
            delivered["count"] += 1

    pub = OutboxPublisher(outbox=outbox, bus=Bus(), batch_size=50)
    start = time.perf_counter()
    stats = drain_all(pub)
    elapsed = time.perf_counter() - start
    assert stats["claimed"] == n
    assert stats["delivered"] == n
    assert delivered["count"] == n
    # throughput recorded (informational)
    throughput = n / elapsed if elapsed > 0 else 0
    assert throughput >= 1


def test_outbox_duplicate_protection(tmp_path):
    db_url = f"sqlite:///{tmp_path}/o2.db"
    init_db(db_url)
    factory = get_session_factory(db_url)
    outbox = OutboxRepository(factory)
    env = make_event_envelope(1, prefix="dup")
    first = outbox.enqueue(env["event_id"], "incident_created", env)
    second = outbox.enqueue(env["event_id"], "incident_created", env)
    assert first is True
    assert second is False


def test_outbox_retry_on_failure(tmp_path):
    db_url = f"sqlite:///{tmp_path}/o3.db"
    init_db(db_url)
    factory = get_session_factory(db_url)
    outbox = OutboxRepository(factory)
    env = make_event_envelope(2, prefix="retry")
    outbox.enqueue(env["event_id"], "incident_created", env)

    class Bus:
        def deliver_durable(self, env):
            raise RuntimeError("transient")

    pub = OutboxPublisher(outbox=outbox, bus=Bus(), batch_size=10, max_attempts=3)
    stats = pub.drain_once()
    # First failure is below max_attempts: requeued, not dead.
    assert stats["retried"] == 1
    assert stats["dead"] == 0
    assert stats["delivered"] == 0
    counts = outbox.count_by_status()
    assert counts.get("pending", 0) == 1
