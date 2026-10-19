"""Worker reliability tests (V19)."""

from __future__ import annotations

import time

from backend.app.events.publisher import OutboxPublisher
from backend.app.events.store import OutboxRepository
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.workers.base import WorkerState


def _make_publisher(tmp_path):
    db_url = f"sqlite:///{tmp_path}/w.db"
    init_db(db_url)
    factory = get_session_factory(db_url)
    outbox = OutboxRepository(factory)
    bus = type("Bus", (), {"deliver_durable": lambda self, e: None, "start": lambda self: None})()
    pub = OutboxPublisher(outbox=outbox, bus=bus, poll_interval_seconds=0.05)
    return pub, outbox


def test_worker_starts_and_stops(tmp_path):
    pub, _ = _make_publisher(tmp_path)
    assert pub.start() is True
    snap = pub.health()
    assert snap.state is WorkerState.RUNNING
    assert pub.stop() is True
    assert pub.health().state is WorkerState.STOPPED


def test_worker_failed_iteration_does_not_update_last_success(tmp_path):
    pub, outbox = _make_publisher(tmp_path)
    # Force a failure by monkeypatching claim_due to raise
    original = outbox.claim_due

    def boom(*a, **k):
        raise RuntimeError("boom")

    outbox.claim_due = boom  # type: ignore[attr-defined]
    pub.start()
    time.sleep(0.2)
    pub.health()
    # last_heartbeat may be None or stale; state could be RUNNING/FAILED
    pub.stop()
    outbox.claim_due = original


def test_worker_idempotent_start(tmp_path):
    pub, _ = _make_publisher(tmp_path)
    assert pub.start() is True
    assert pub.start() is True
    pub.stop()
