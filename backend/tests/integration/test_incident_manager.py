"""Incident manager tests — auto-creation, sync, dedup, auto-resolve."""

from __future__ import annotations

from typing import Any

from backend.app.core.config import Settings
from backend.app.incidents.manager import IncidentManager
from backend.app.incidents.schemas import IncidentStatus
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.intelligence.engine import IntelligenceEngine
from backend.app.safety.base import EventDraft, SafetyRule, SceneState
from backend.app.safety.engine import SafetyEngine
from backend.app.safety.schemas import SafetyEventType, SafetySeverity
from backend.tests.incident_helpers import utc
from backend.tests.safety_helpers import make_track


class StubRule(SafetyRule):
    active: bool

    def __init__(self, name: str, severity: SafetySeverity = SafetySeverity.MEDIUM) -> None:
        super().__init__(name, enabled=True)
        self.active = True
        self._severity = severity

    @property
    def event_type(self) -> SafetyEventType:
        return SafetyEventType.CROWD_WARNING

    def evaluate(self, scene: SceneState) -> list[EventDraft]:
        if not self.active:
            return []
        return [
            EventDraft(
                dedupe_key=f"stub:{scene.camera_id}:{self.name}",
                event_type=self.event_type,
                severity=self._severity,
                track_ids=[t.track_id for t in scene.tracks],
                confidence=0.7,
                message="stub",
                evidence={},
            )
        ]


def _settings(**overrides: Any) -> Settings:
    params: dict[str, Any] = {
        "safety_event_resolution_grace_seconds": 30.0,
    }
    params.update(overrides)
    return Settings(_env_file=None, **params)  # type: ignore[call-arg]


def _manager(url: str, safety: SafetyEngine | None = None, **overrides: Any) -> IncidentManager:
    settings = _settings(**overrides)
    intel = IntelligenceEngine(settings, safety_engine=safety)
    return IncidentManager(settings, get_session_factory(url), intelligence_engine=intel)


def _run(manager: IncidentManager, ts=None, camera_id: str = "cam-01") -> dict[str, int]:
    """Run one V09 pass then reconcile, mirroring the worker pipeline."""
    timestamp = ts if ts is not None else utc(0)
    manager._intelligence.process(camera_id, timestamp)
    return manager.sync_camera(camera_id, timestamp)


def _drive(engine: SafetyEngine, camera_id: str = "cam-01", n_tracks: int = 0) -> None:
    tracks = [
        make_track(i + 1, "person", (10.0 + i * 60.0, 10.0, 50.0 + i * 60.0, 200.0)) for i in range(n_tracks)
    ]
    engine.process(camera_id, tracks, utc(0))


def test_auto_create_from_p2_cluster(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incidents.db"
    init_db(url)
    safety = SafetyEngine(_settings(), [StubRule("stub", SafetySeverity.CRITICAL)])
    _drive(safety)
    manager = _manager(url, safety)
    summary = _run(manager, utc(0))
    assert summary["created"] == 1
    incidents, total = manager.repository.list_incidents()
    assert total == 1
    assert incidents[0].priority.value == "P2"
    assert incidents[0].status is IncidentStatus.OPEN
    assert incidents[0].source == "AUTOMATIC"


def test_p3_p4_skipped_by_default(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incidents.db"
    init_db(url)
    safety = SafetyEngine(_settings(), [StubRule("stub", SafetySeverity.LOW)])
    _drive(safety)
    manager = _manager(url, safety)
    summary = _run(manager, utc(0))
    assert summary == {"created": 0, "updated": 0, "resolved": 0, "linked": 0, "checked": 1}


def test_min_priority_configurable(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incidents.db"
    init_db(url)
    safety = SafetyEngine(_settings(), [StubRule("stub", SafetySeverity.LOW)])
    _drive(safety)
    manager = _manager(url, safety, incident_min_priority="P4")
    summary = _run(manager, utc(0))
    assert summary["created"] == 1


def test_p1_created_from_correlated_cluster(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incidents.db"
    init_db(url)
    rules: list[SafetyRule] = [StubRule(f"stub-{i}", SafetySeverity.CRITICAL) for i in range(3)]
    safety = SafetyEngine(_settings(), rules)
    _drive(safety, n_tracks=1)
    manager = _manager(url, safety)
    summary = _run(manager, utc(0))
    assert summary["created"] == 1
    incidents, _ = manager.repository.list_incidents()
    assert incidents[0].priority.value == "P1"


def test_duplicate_cluster_updates_instead(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incidents.db"
    init_db(url)
    safety = SafetyEngine(_settings(), [StubRule("stub", SafetySeverity.CRITICAL)])
    _drive(safety)
    manager = _manager(url, safety)
    assert _run(manager, utc(0))["created"] == 1
    assert _run(manager, utc(1))["created"] == 0
    incidents, total = manager.repository.list_incidents()
    assert total == 1


def test_repeated_updates_refresh_last_seen(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incidents.db"
    init_db(url)
    safety = SafetyEngine(_settings(), [StubRule("stub", SafetySeverity.CRITICAL)])
    _drive(safety)
    manager = _manager(url, safety)
    _run(manager, utc(0))
    first, _ = manager.repository.list_incidents()
    _run(manager, utc(30))
    second, _ = manager.repository.list_incidents()
    assert second[0].last_seen >= first[0].last_seen
    assert second[0].id == first[0].id


def test_resolved_cluster_no_duplicate(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incidents.db"
    init_db(url)
    stub = StubRule("stub", SafetySeverity.CRITICAL)
    safety = SafetyEngine(_settings(safety_event_resolution_grace_seconds=0.5), [stub])
    _drive(safety)
    manager = _manager(url, safety)
    assert _run(manager, utc(0))["created"] == 1
    stub.active = False
    safety.process("cam-01", [], utc(10))
    summary = _run(manager, utc(10))
    assert summary["created"] == 0
    incidents, total = manager.repository.list_incidents()
    assert total == 1


def test_new_cluster_after_closure_creates_new(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incidents.db"
    init_db(url)
    stub = StubRule("stub", SafetySeverity.CRITICAL)
    safety = SafetyEngine(_settings(safety_event_resolution_grace_seconds=0.5), [stub])
    _drive(safety)
    manager = _manager(url, safety)
    _run(manager, utc(0))
    incidents, _ = manager.repository.list_incidents()
    first_id = str(incidents[0].id)
    manager.resolve(first_id, "FALSE_ALARM", actor_id="op-1")
    manager.close(first_id, "Reviewed and closed.", actor_id="op-1")
    # A fresh cluster afterwards is a new incident, never a silent reopen.
    # (Same cluster id, new domain event: the domain mints a new source id.)
    stub.active = True
    safety.process("cam-01", [], utc(40))
    summary = _run(manager, utc(40))
    assert summary["created"] == 1
    _, total = manager.repository.list_incidents()
    assert total == 2
    closed = manager.repository.get_incident(first_id)
    assert closed is not None and closed.status is IncidentStatus.CLOSED


def test_auto_resolve_open_after_grace(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incidents.db"
    init_db(url)
    stub = StubRule("stub", SafetySeverity.CRITICAL)
    safety = SafetyEngine(_settings(safety_event_resolution_grace_seconds=0.5), [stub])
    _drive(safety)
    manager = _manager(url, safety, incident_auto_resolve_grace_seconds=5.0)
    _run(manager, utc(0))
    stub.active = False
    safety.process("cam-01", [], utc(10))
    manager._last_sweep["cam-01"] = 0.0  # bypass the 10s sweep throttle
    summary = _run(manager, utc(20))
    assert summary["resolved"] == 1
    incidents, _ = manager.repository.list_incidents()
    assert incidents[0].status is IncidentStatus.RESOLVED
    assert incidents[0].resolved_at is not None


def test_auto_resolve_disabled_leaves_open(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incidents.db"
    init_db(url)
    stub = StubRule("stub", SafetySeverity.CRITICAL)
    safety = SafetyEngine(_settings(safety_event_resolution_grace_seconds=0.5), [stub])
    _drive(safety)
    manager = _manager(url, safety, incident_auto_resolve_enabled=False)
    _run(manager, utc(0))
    stub.active = False
    safety.process("cam-01", [], utc(10))
    manager._last_sweep["cam-01"] = 0.0  # bypass the 10s sweep throttle
    summary = _run(manager, utc(100))
    assert summary["resolved"] == 0
    incidents, _ = manager.repository.list_incidents()
    assert incidents[0].status is IncidentStatus.OPEN


def test_acknowledged_never_auto_resolved(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incidents.db"
    init_db(url)
    stub = StubRule("stub", SafetySeverity.CRITICAL)
    safety = SafetyEngine(_settings(safety_event_resolution_grace_seconds=0.5), [stub])
    _drive(safety)
    manager = _manager(url, safety)
    _run(manager, utc(0))
    incidents, _ = manager.repository.list_incidents()
    manager.acknowledge(str(incidents[0].id), actor_id="op-1")
    stub.active = False
    safety.process("cam-01", [], utc(10))
    manager._last_sweep["cam-01"] = 0.0  # bypass the 10s sweep throttle
    summary = _run(manager, utc(100))
    assert summary["resolved"] == 0
    current, _ = manager.repository.list_incidents()
    assert current[0].status is IncidentStatus.ACKNOWLEDGED


def test_sync_without_intelligence_is_noop(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incidents.db"
    init_db(url)
    manager = IncidentManager(_settings(), get_session_factory(url), intelligence_engine=None)
    # No V09 engine: sync_camera itself (not the V09-driving helper) is a pure no-op.
    assert manager.sync_camera("cam-01", utc(0)) == {
        "created": 0,
        "updated": 0,
        "resolved": 0,
        "linked": 0,
        "checked": 0,
    }


def test_sync_debounce_skips_unchanged(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/incidents.db"
    init_db(url)
    safety = SafetyEngine(_settings(), [StubRule("stub", SafetySeverity.CRITICAL)])
    _drive(safety)
    manager = _manager(url, safety)
    _run(manager, utc(0))
    metrics_before = manager.metrics()["sync_runs"]
    _run(manager, utc(0))
    assert manager.metrics()["sync_runs"] == metrics_before + 1
