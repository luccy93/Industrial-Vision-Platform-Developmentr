"""Event reliability tests — dedup, concurrency, shutdown, redis smoke."""

from __future__ import annotations

import os
import threading
from typing import Any, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.events.bus import EventBus
from backend.app.events.publisher import OutboxPublisher
from backend.app.events.store import OperationalEventRepository, OutboxRepository
from backend.app.events.wiring import register_remote_incident_ingest
from backend.app.infrastructure.db import get_session_factory, init_db


def _bus() -> EventBus:
    bus = EventBus(mode="local")
    bus.start()
    return bus


def test_no_self_duplication_end_to_end(tmp_path) -> None:
    """Record → outbox → drain with guarded subscriber ⇒ exactly one entry."""
    from backend.app.core.config import Settings
    from backend.app.incidents.manager import IncidentManager

    url = f"sqlite:///{tmp_path}/dedup.db"
    init_db(url)
    factory = get_session_factory(url)
    bus = _bus()
    manager = IncidentManager(
        Settings(_env_file=None),  # type: ignore[call-arg]
        factory,
        event_bus=bus,
        operational_repository=OperationalEventRepository(factory),
        outbox_repository=OutboxRepository(factory),
    )
    register_remote_incident_ingest(bus, manager)
    incident = manager.create_manual(title="dedup", category="OPERATIONAL", priority="P3")
    outbox = OutboxRepository(factory)
    publisher = OutboxPublisher(outbox=outbox, bus=bus)
    stats = publisher.drain_once()
    assert stats["delivered"] >= 1
    entries = [c for c in manager.recent_changes(0) if c["incident_id"] == str(incident.id)]
    assert len(entries) == 1, f"feed duplicated: {len(entries)}"
    # Redelivery (crash recovery) still cannot duplicate the feed.
    publisher.drain_once()
    entries = [c for c in manager.recent_changes(0) if c["incident_id"] == str(incident.id)]
    assert len(entries) == 1


def test_concurrent_outbox_enqueue_single_intent(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/conc.db"
    init_db(url)
    _, outbox = (
        OperationalEventRepository(get_session_factory(url)),
        OutboxRepository(get_session_factory(url)),
    )
    envelope = {
        "v": 1,
        "event_id": "race-1",
        "event_type": "incident_created",
        "domain": "INCIDENT",
        "origin": "p",
        "payload": {},
    }
    results: list[bool] = []
    errors: list[Exception] = []

    def _enqueue() -> None:
        try:
            for _ in range(5):
                results.append(outbox.enqueue("race-1", "incident_created", envelope))
        except Exception as exc:  # pragma: no cover - must never happen
            errors.append(exc)

    threads = [threading.Thread(target=_enqueue) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not errors
    assert sum(results) == 1
    assert outbox.count_by_status() == {"pending": 1}


def test_concurrent_sync_single_history_row(tmp_path) -> None:
    from backend.app.core.config import Settings
    from backend.app.incidents.manager import IncidentManager
    from backend.app.intelligence.engine import IntelligenceEngine
    from backend.app.safety.base import EventDraft, SafetyRule, SceneState
    from backend.app.safety.engine import SafetyEngine
    from backend.app.safety.schemas import SafetyEventType, SafetySeverity
    from backend.tests.incident_helpers import utc

    class StubRule(SafetyRule):
        def __init__(self) -> None:
            super().__init__("stub", enabled=True)

        @property
        def event_type(self) -> SafetyEventType:
            return SafetyEventType.CROWD_WARNING

        def evaluate(self, scene: SceneState) -> list[EventDraft]:
            return [
                EventDraft(
                    dedupe_key="stub:cam-01",
                    event_type=self.event_type,
                    severity=SafetySeverity.CRITICAL,
                    track_ids=[],
                    confidence=0.7,
                    message="s",
                    evidence={},
                )
            ]

    url = f"sqlite:///{tmp_path}/conc.db"
    init_db(url)
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    safety = SafetyEngine(settings, [StubRule()])
    safety.process("cam-01", [], utc(0))
    intel = IntelligenceEngine(settings, safety_engine=safety)
    intel.process("cam-01", utc(0))
    factory = get_session_factory(url)
    manager = IncidentManager(
        settings,
        factory,
        intelligence_engine=intel,
        operational_repository=OperationalEventRepository(factory),
        outbox_repository=OutboxRepository(factory),
    )
    errors: list[Exception] = []

    def _sync() -> None:
        try:
            for _ in range(3):
                manager.sync_camera("cam-01", utc(0))
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=_sync) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not errors
    _, total = manager.repository.list_incidents()
    assert total == 1
    assert manager.metrics()["history_failures"] == 0


def test_distributed_publish_failure_never_silent(tmp_path) -> None:
    """Distributed Redis down ⇒ publish raises; intent stays pending."""
    from backend.tests.redis_helpers import FakeRedisError, FakeRedisTransport

    url = f"sqlite:///{tmp_path}/dist.db"
    init_db(url)
    _, outbox = (
        OperationalEventRepository(get_session_factory(url)),
        OutboxRepository(get_session_factory(url)),
    )
    transport = FakeRedisTransport()
    transport.fail_publish = FakeRedisError("down")
    from backend.app.infrastructure.redis_client import RedisLifecycleManager
    from backend.tests.redis_helpers import fake_client_factory

    redis_manager = RedisLifecycleManager(
        enabled=True, url="redis://localhost:6379/0", client_factory=fake_client_factory(transport)
    )
    assert redis_manager.start() is True
    bus = EventBus(mode="distributed", redis_manager=redis_manager)
    bus.start()
    outbox.enqueue(
        "e-1",
        "incident_created",
        {
            "v": 1,
            "event_id": "e-1",
            "event_type": "incident_created",
            "domain": "INCIDENT",
            "origin": "p",
            "payload": {},
        },
    )
    publisher = OutboxPublisher(outbox=outbox, bus=bus, max_attempts=2)
    stats = publisher.drain_once()
    assert stats["retried"] == 1
    # Nothing silently marked sent; nothing delivered anywhere.
    assert outbox.count_by_status() == {"pending": 1}
    redis_manager.close()


def test_lifespan_starts_and_stops_distribution_threads() -> None:
    import tempfile

    from fastapi.testclient import TestClient as _TestClient

    from backend.app.core.config import AppEnv, Settings
    from backend.app.infrastructure.db import init_db as _init_db
    from backend.app.main import create_app
    from backend.app.workers.base import WorkerState

    tmp = tempfile.mkdtemp().replace("\\", "/")
    settings = Settings(
        app_env=AppEnv.testing,
        database_url=f"sqlite:///{tmp}/life.db",
        _env_file=None,  # type: ignore[call-arg]
    )
    _init_db(settings.database_url)
    app = create_app(settings)
    publisher = app.state.outbox_publisher
    assert publisher.health().state is WorkerState.CREATED
    with _TestClient(app):
        assert publisher.health().state is WorkerState.RUNNING
    assert publisher.health().state is WorkerState.STOPPED
    assert app.state.runtime.state.value == "STOPPED"


def _state(client: TestClient) -> Any:
    return cast(FastAPI, cast(Any, client).app).state


def test_shutdown_phase_order(client: TestClient) -> None:
    state = _state(client)
    results = state.runtime.shutdown()
    names = [r.name for r in results]
    assert names.index("stop_event_bus") < names.index("close_redis")
    assert names.index("close_redis") < names.index("close_database")
    assert names.index("close_websockets") < names.index("close_database")
    assert all(r.ok for r in results)


def test_real_redis_smoke() -> None:
    """Optional real-Redis protocol check; SKIPPED without a service."""
    url = os.environ.get("REDIS_SMOKE_URL", "")
    if not url:
        pytest.skip("REDIS_SMOKE_URL not set; real-Redis smoke not applicable")
    from backend.app.infrastructure.redis_client import RedisLifecycleManager

    manager = RedisLifecycleManager(
        enabled=True, url=url, connect_timeout_seconds=3.0, socket_timeout_seconds=3.0
    )
    try:
        assert manager.start() is True
        assert manager.ping() is True
        assert manager.publish("ivp:smoke", b'{"v": 1}') >= 0
    finally:
        manager.close()
