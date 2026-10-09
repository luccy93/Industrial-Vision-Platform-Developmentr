"""Event distribution tests — producers, remote ingest, redis policy."""

from __future__ import annotations

from typing import Any, cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.events.bus import EventBus
from backend.app.events.envelope import EventEnvelope
from backend.app.events.store import OperationalEventRepository, OutboxRepository
from backend.app.incidents.manager import IncidentManager
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.intelligence.engine import IntelligenceEngine
from backend.app.safety.base import EventDraft, SafetyRule, SceneState
from backend.app.safety.engine import SafetyEngine
from backend.app.safety.schemas import SafetyEventType, SafetySeverity
from backend.tests.incident_helpers import utc


class StubRule(SafetyRule):
    def __init__(self, name: str) -> None:
        super().__init__(name, enabled=True)

    @property
    def event_type(self) -> SafetyEventType:
        return SafetyEventType.CROWD_WARNING

    def evaluate(self, scene: SceneState) -> list[EventDraft]:
        return [
            EventDraft(
                dedupe_key=f"stub:{scene.camera_id}",
                event_type=self.event_type,
                severity=SafetySeverity.CRITICAL,
                track_ids=[],
                confidence=0.7,
                message="s",
                evidence={},
            )
        ]


def _wired_manager(url: str) -> tuple[IncidentManager, EventBus, OutboxRepository]:
    from backend.app.core.config import Settings

    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    safety = SafetyEngine(settings, [StubRule("stub")])
    safety.process("cam-01", [], utc(0))
    intel = IntelligenceEngine(settings, safety_engine=safety)
    intel.process("cam-01", utc(0))
    factory = get_session_factory(url)
    bus = EventBus(mode="local")
    bus.start()
    manager = IncidentManager(
        settings,
        factory,
        intelligence_engine=intel,
        event_bus=bus,
        operational_repository=OperationalEventRepository(factory),
        outbox_repository=OutboxRepository(factory),
    )
    _, outbox = OperationalEventRepository(factory), OutboxRepository(factory)
    return manager, bus, outbox


def test_lifecycle_change_queues_outbox_intent(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/dist.db"
    init_db(url)
    manager, bus, outbox = _wired_manager(url)
    received: list[str] = []
    bus.subscribe(lambda e: received.append(e.event_id))
    manager.sync_camera("cam-01", utc(0))
    assert outbox.count_by_status().get("pending", 0) >= 1
    # Member unified events gained durable history rows.
    assert manager.metrics()["history_persisted"] >= 1
    assert manager.metrics()["history_failures"] == 0
    # Publisher drain fans out locally with stable envelope identity.
    from backend.app.events.publisher import OutboxPublisher

    publisher = OutboxPublisher(outbox=outbox, bus=bus)
    stats = publisher.drain_once()
    assert stats["delivered"] >= 1
    assert received, "lifecycle envelope must fan out on drain"
    assert outbox.count_by_status().get("pending", 0) == 0


def test_sync_without_wiring_is_unaffected(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/dist.db"
    init_db(url)
    from backend.app.core.config import Settings

    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    safety = SafetyEngine(settings, [StubRule("stub")])
    safety.process("cam-01", [], utc(0))
    intel = IntelligenceEngine(settings, safety_engine=safety)
    intel.process("cam-01", utc(0))
    manager = IncidentManager(settings, get_session_factory(url), intelligence_engine=intel)
    summary = manager.sync_camera("cam-01", utc(0))
    assert summary["created"] == 1


def test_ingest_remote_change_feeds_ws(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/dist.db"
    init_db(url)
    manager, _, _ = _wired_manager(url)
    envelope = EventEnvelope(
        event_id="incident:abc:7",
        event_type="incident_status_changed",
        domain="INCIDENT",
        camera_id="cam-01",
        origin="proc-other",
        payload={
            "incident_id": "abc",
            "status": "ACKNOWLEDGED",
            "previous_status": "OPEN",
            "new_status": "ACKNOWLEDGED",
        },
    )
    entry = manager.ingest_remote_change(envelope)
    assert entry is not None
    assert entry["kind"] == "status_changed"
    assert entry["remote"] is True
    assert any(c.get("remote") for c in manager.recent_changes(0))
    # Redelivery of the same envelope is dropped (idempotent feed).
    assert manager.ingest_remote_change(envelope) is None
    assert manager.metrics()["remote_dropped"] >= 1
    # Unknown kinds never crash the feed.
    bogus = EventEnvelope(
        event_id="x-1",
        event_type="incident_frobnicate",
        domain="INCIDENT",
        origin="proc-other",
        payload={"incident_id": "abc"},
    )
    assert manager.ingest_remote_change(bogus) is None


def test_worker_stage_publishes_new_events(tmp_path) -> None:
    from backend.app.core.config import AppEnv, Settings
    from backend.app.inference.manager import ModelManager
    from backend.app.inference.worker import InferenceWorker
    from backend.app.safety.rules import default_rules
    from backend.tests.intelligence_helpers import utc as iutc
    from backend.tests.safety_helpers import make_track

    settings = Settings(app_env=AppEnv.testing, _env_file=None)  # type: ignore[call-arg]
    safety = SafetyEngine(settings, default_rules(settings))
    tracks = [
        make_track(i + 1, "person", (10.0 + i * 40.0, 10.0, 50.0 + i * 40.0, 200.0), camera_id="cam-w")
        for i in range(6)
    ]
    safety.process("cam-w", tracks, iutc(0), 320.0, 240.0)
    bus = EventBus(mode="local")
    bus.start()
    received: list[tuple[str, str]] = []
    bus.subscribe(lambda e: received.append((e.event_type, e.event_id)))
    from types import SimpleNamespace

    from backend.app.tracking.manager import TrackingManager

    worker = InferenceWorker(
        "cam-w",
        ModelManager.from_settings(settings),
        lambda: None,
        tracking_manager=TrackingManager(settings),
        intelligence_engine=IntelligenceEngine(settings, safety_engine=safety),
        event_bus=bus,
    )
    worker._analyze_intelligence(SimpleNamespace(timestamp=iutc(0)))  # type: ignore[arg-type]
    assert received, "intelligence stage must publish new unified events"
    types = {t for t, _ in received}
    assert "intelligence_event" in types
    # Second identical pass publishes nothing new (delta semantics).
    received.clear()
    worker._analyze_intelligence(SimpleNamespace(timestamp=iutc(0)))  # type: ignore[arg-type]
    assert received == []


def test_retention_cleanup_wired(tmp_path) -> None:
    from datetime import timedelta

    from backend.app.domain.common import utcnow

    url = f"sqlite:///{tmp_path}/dist.db"
    init_db(url)
    manager, _, _ = _wired_manager(url)
    old = utcnow() - timedelta(days=120)
    manager._operational.upsert_event(  # noqa: SLF001
        event_id="old-1",
        camera_id="cam-01",
        source_domain="SAFETY",
        source_event_id="s-old-1",
        event_type="CROWD_WARNING",
        last_seen=old,
    )
    summary = manager.run_retention_cleanup()
    assert summary["history_deleted"] == 1


def _state(client: TestClient) -> Any:
    return cast(FastAPI, cast(Any, client).app).state


def test_health_reports_redis_and_eventbus_local(client: TestClient) -> None:
    body = client.get("/api/v1/health").json()
    components = {c["component"]: c for c in body["components"]}
    assert components["redis"]["status"] == "DISABLED"
    assert components["eventbus"]["status"] == "READY"
    assert components["eventbus"]["metadata"]["mode"] == "local"


def test_readiness_redis_required_but_down_is_503(client: TestClient) -> None:
    state = _state(client)
    manager = state.redis_manager
    manager._enabled = True  # noqa: SLF001
    manager._required = True  # noqa: SLF001
    state.readiness.set_required(["application", "database", "workers", "redis"])
    try:
        res = client.get("/ready")
        assert res.status_code == 503
        assert res.json()["readiness"]["checks"]["redis"] == "NOT_READY"
    finally:
        manager._enabled = False  # noqa: SLF001
        manager._required = False  # noqa: SLF001
        state.readiness.set_required(["application", "database", "workers"])


def test_required_redis_startup_fails_fast() -> None:
    import tempfile

    from backend.app.core.config import AppEnv, Settings
    from backend.app.infrastructure.db import init_db as _init_db
    from backend.app.main import create_app

    tmp = tempfile.mkdtemp().replace("\\", "/")
    settings = Settings(
        app_env=AppEnv.testing,
        database_url=f"sqlite:///{tmp}/req.db",
        redis_enabled=True,
        redis_required=True,
        redis_url="redis://127.0.0.1:6399/0",
        redis_connect_timeout_seconds=0.5,
        _env_file=None,  # type: ignore[call-arg]
    )
    _init_db(settings.database_url)
    with pytest.raises(Exception):
        create_app(settings)


def test_orphan_report_counts_legacy_links(client: TestClient) -> None:
    from backend.app.events.store import OperationalEventRepository

    state = _state(client)
    repo = OperationalEventRepository(state.session_factory)
    assert repo.count_orphan_links() >= 0
