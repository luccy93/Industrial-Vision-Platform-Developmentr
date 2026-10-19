"""Event processing load tests (V19, opt-in perf)."""

from __future__ import annotations

import pytest

from backend.app.events.publisher import OutboxPublisher
from backend.app.events.store import OutboxRepository
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.tests.outbox_fixtures import drain_all, make_event_envelope
from backend.tests.perf.bench import run_benchmark

pytestmark = pytest.mark.perf


def test_outbox_load(tmp_path):
    db_url = f"sqlite:///{tmp_path}/epl.db"
    init_db(db_url)
    factory = get_session_factory(db_url)
    outbox = OutboxRepository(factory)

    n = 1000
    for i in range(n):
        env = make_event_envelope(i)
        outbox.enqueue(env["event_id"], "incident_created", env)

    class Bus:
        def deliver_durable(self, env):
            pass

    pub = OutboxPublisher(outbox=outbox, bus=Bus(), batch_size=200)
    delivered = {"total": 0}

    def call():
        stats = drain_all(pub)
        delivered["total"] += stats["delivered"]

    res = run_benchmark(call, name="outbox_drain", iterations=1, warmup=0)
    assert res.failures == 0
    assert delivered["total"] == n
    assert res.throughput_ops_per_sec > 0
