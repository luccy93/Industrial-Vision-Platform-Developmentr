"""Outbox throughput tests (V19)."""

from __future__ import annotations

import time

from backend.app.events.publisher import OutboxPublisher
from backend.app.events.store import OutboxRepository
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.tests.outbox_fixtures import drain_all, make_event_envelope


def test_outbox_batch_throughput(tmp_path):
    db_url = f"sqlite:///{tmp_path}/ot.db"
    init_db(db_url)
    factory = get_session_factory(db_url)
    outbox = OutboxRepository(factory)

    n = 500
    for i in range(n):
        env = make_event_envelope(i)
        outbox.enqueue(env["event_id"], "incident_created", env)

    class Bus:
        def deliver_durable(self, env):
            pass

    pub = OutboxPublisher(outbox=outbox, bus=Bus(), batch_size=100)
    start = time.perf_counter()
    stats = drain_all(pub)
    elapsed = time.perf_counter() - start
    assert stats["claimed"] == n
    assert stats["delivered"] == n
    throughput = n / elapsed if elapsed > 0 else 0
    assert throughput > 0
