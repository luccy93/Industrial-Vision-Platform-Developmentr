"""Incident performance tests — concurrency dedupe, storm, pagination."""

from __future__ import annotations

import threading
import time
from typing import Any

from backend.app.core.config import Settings
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


def _manager(url: str, **overrides: Any) -> IncidentManager:
    params: dict[str, Any] = {"safety_event_resolution_grace_seconds": 30.0}
    params.update(overrides)
    settings = Settings(_env_file=None, **params)  # type: ignore[call-arg]
    safety = SafetyEngine(settings, [StubRule("stub")])
    safety.process("cam-p", [], utc(0))
    intel = IntelligenceEngine(settings, safety_engine=safety)
    intel.process("cam-p", utc(0))
    return IncidentManager(settings, get_session_factory(url), intel)


def test_concurrent_sync_creates_single_incident(tmp_path) -> None:
    """8 threads racing the same camera still yield exactly one incident."""
    url = f"sqlite:///{tmp_path}/perf.db"
    init_db(url)
    manager = _manager(url)
    errors: list[Exception] = []

    def _sync() -> None:
        try:
            for _ in range(5):
                manager.sync_camera("cam-p", utc(0))
        except Exception as exc:  # pragma: no cover - must never happen
            errors.append(exc)

    threads = [threading.Thread(target=_sync) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not errors
    _, total = manager.repository.list_incidents()
    assert total == 1


def test_repeated_sync_storm_is_fast(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/perf.db"
    init_db(url)
    manager = _manager(url)
    manager.sync_camera("cam-p", utc(0))
    started = time.perf_counter()
    for _ in range(50):
        manager.sync_camera("cam-p", utc(0))
    elapsed = time.perf_counter() - started
    assert elapsed < 15.0, f"50 debounced syncs took {elapsed:.2f}s"
    _, total = manager.repository.list_incidents()
    assert total == 1


def test_list_pagination_scales(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/perf.db"
    init_db(url)
    manager = _manager(url)
    for index in range(60):
        manager.create_manual(
            title=f"perf-{index:03d}",
            category="OPERATIONAL",
            priority="P4",
            camera_id="cam-p",
        )
    started = time.perf_counter()
    page, total = manager.repository.list_incidents(page=2, page_size=20)
    elapsed = time.perf_counter() - started
    assert total == 60
    assert len(page) == 20
    assert elapsed < 5.0, f"paginated list took {elapsed:.2f}s"


def test_recent_changes_feed_stays_bounded(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/perf.db"
    init_db(url)
    manager = _manager(url)
    incident = manager.create_manual(title="feed", category="OPERATIONAL", priority="P4")
    for index in range(80):
        manager.add_note(str(incident.id), f"note {index}", actor_id="op-1")
    feed = manager.recent_changes(0, limit=50)
    assert len(feed) == 50
    # Cursor pagination covers the whole feed without gaps.
    first = manager.recent_changes(0, limit=10**6)
    assert len(first) == len(manager._changes) == 81
    newest_seq = first[-1]["seq"]
    rest = manager.recent_changes(newest_seq, limit=10**6)
    assert rest == []
