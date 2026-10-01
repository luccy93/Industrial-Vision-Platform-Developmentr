"""Safety engine — orchestrates rules with per-camera isolated state.

Continuity model: each rule proposes ``EventDraft``s keyed by a stable
``dedupe_key`` (rule + entity). The engine creates a ``SafetyEvent`` once,
then updates ``last_seen``/confidence while the condition persists, and moves
it to ``RESOLVED`` after ``grace_seconds`` without re-observation. One
continuing condition = one event with a stable ``event_id``.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from datetime import datetime
from uuid import uuid4

from backend.app.core.config import Settings
from backend.app.safety.base import EventDraft, SafetyRule, SceneState
from backend.app.safety.schemas import (
    SafetyAnalysisResult,
    SafetyEvent,
    SafetyEventStatus,
)
from backend.app.tracking.schemas import TrackedObject

logger = logging.getLogger("industrial-vision.safety")


def _ema(previous: float, sample: float, alpha: float = 0.2) -> float:
    return sample if previous <= 0 else (1.0 - alpha) * previous + alpha * sample


class _CameraSafetyState:
    def __init__(self, max_events: int) -> None:
        self.active: dict[str, SafetyEvent] = {}
        self.recent: deque[SafetyEvent] = deque(maxlen=max_events)
        self.evaluations = 0
        self.created = 0
        self.resolved = 0
        self.rule_errors = 0


class SafetyEngine:
    """Rule orchestration with dedup, lifecycle, and per-camera isolation."""

    def __init__(self, settings: Settings, rules: list[SafetyRule] | None = None) -> None:
        self._settings = settings
        self._rules: list[SafetyRule] = list(rules or [])
        self._lock = threading.Lock()
        self._cameras: dict[str, _CameraSafetyState] = {}
        self._latency_ms = 0.0

    @property
    def enabled(self) -> bool:
        return self._settings.safety_enabled

    @property
    def rules(self) -> list[SafetyRule]:
        with self._lock:
            return list(self._rules)

    def register(self, rule: SafetyRule) -> None:
        with self._lock:
            self._rules.append(rule)

    def _camera_state(self, camera_id: str) -> _CameraSafetyState:
        with self._lock:
            state = self._cameras.get(camera_id)
            if state is None:
                state = _CameraSafetyState(self._settings.safety_max_events_per_camera)
                self._cameras[camera_id] = state
            return state

    def reset_camera(self, camera_id: str) -> None:
        with self._lock:
            self._cameras.pop(camera_id, None)

    def process(
        self,
        camera_id: str,
        tracks: list[TrackedObject],
        timestamp: datetime,
    ) -> SafetyAnalysisResult:
        started = time.perf_counter()
        scene = SceneState(camera_id=camera_id, timestamp=timestamp, tracks=list(tracks))
        state = self._camera_state(camera_id)
        with self._lock:
            state.evaluations += 1
            rules = [r for r in self._rules if r.enabled]
        grace = self._settings.safety_event_resolution_grace_seconds

        drafts: dict[str, tuple[str, EventDraft]] = {}
        if self.enabled:
            for rule in rules:
                try:
                    for draft in rule.evaluate(scene) or []:
                        drafts[draft.dedupe_key] = (rule.name, draft)
                except Exception as exc:
                    with self._lock:
                        state.rule_errors += 1
                    logger.warning("rule %s failed for %s: %s", rule.name, camera_id, exc)

        new_events: list[SafetyEvent] = []
        with self._lock:
            for key, (rule_name, draft) in drafts.items():
                existing = state.active.get(key)
                if existing is None:
                    event = SafetyEvent(
                        event_id=uuid4(),
                        camera_id=camera_id,
                        track_ids=list(draft.track_ids),
                        event_type=draft.event_type,
                        severity=draft.severity,
                        status=SafetyEventStatus.ACTIVE,
                        confidence=min(1.0, max(0.0, draft.confidence)),
                        timestamp=timestamp,
                        first_seen=timestamp,
                        last_seen=timestamp,
                        duration_ms=0.0,
                        message=draft.message,
                        evidence=dict(draft.evidence),
                        metadata={"rule": rule_name, "dedupe_key": key},
                    )
                    state.active[key] = event
                    state.created += 1
                    new_events.append(event)
                else:
                    existing.track_ids = list(draft.track_ids)
                    existing.confidence = min(1.0, max(0.0, draft.confidence))
                    existing.message = draft.message
                    existing.evidence = dict(draft.evidence)
                    existing.touch(timestamp)

            resolved_events: list[SafetyEvent] = []
            for key in [k for k, e in state.active.items() if k not in drafts]:
                event = state.active[key]
                idle = (timestamp - event.last_seen).total_seconds()
                if idle >= grace:
                    event.status = SafetyEventStatus.RESOLVED
                    event.touch(event.last_seen)
                    resolved_events.append(event)
                    state.recent.append(event)
                    del state.active[key]
                    state.resolved += 1

            active = list(state.active.values())
            latency_ms = (time.perf_counter() - started) * 1000.0
            self._latency_ms = _ema(self._latency_ms, latency_ms)
            metrics = {
                "evaluations": state.evaluations,
                "events_created": state.created,
                "events_resolved": state.resolved,
                "rule_errors": state.rule_errors,
                "latency_ms": round(latency_ms, 3),
            }
        return SafetyAnalysisResult(
            camera_id=camera_id,
            timestamp=timestamp,
            active_events=active,
            new_events=new_events,
            resolved_events=resolved_events,
            metrics=metrics,
        )

    def suppress(self, camera_id: str, event_id: str) -> SafetyEventStatus:
        """Move an active event to SUPPRESSED. Raises ValueError if unknown."""
        from uuid import UUID

        state = self._cameras.get(camera_id)
        wanted = UUID(event_id)
        if state is None:
            raise ValueError(f"unknown event {event_id}")
        with self._lock:
            for key, event in list(state.active.items()):
                if event.event_id == wanted:
                    event.status = SafetyEventStatus.SUPPRESSED
                    state.recent.append(event)
                    del state.active[key]
                    state.resolved += 1
                    return event.status
        raise ValueError(f"unknown event {event_id}")

    def active_events(self, camera_id: str, limit: int = 50) -> list[SafetyEvent]:
        state = self._cameras.get(camera_id)
        if state is None:
            return []
        with self._lock:
            return list(state.active.values())[: max(1, limit)]

    def recent_events(self, camera_id: str, limit: int = 50) -> list[SafetyEvent]:
        state = self._cameras.get(camera_id)
        if state is None:
            return []
        with self._lock:
            items = list(state.recent)[-max(1, limit) :]
            return list(reversed(items))

    def status(self) -> dict:
        with self._lock:
            cameras = list(self._cameras.keys())
            per_camera = {
                camera_id: {
                    "active": len(self._cameras[camera_id].active),
                    "evaluations": self._cameras[camera_id].evaluations,
                }
                for camera_id in cameras
            }
            rules = [(r.name, r.enabled) for r in self._rules]
        return {
            "enabled": self.enabled,
            "engine_status": "READY" if self.enabled else "DISABLED",
            "rules_loaded": [name for name, _ in rules],
            "rules": [{"name": name, "enabled": enabled} for name, enabled in rules],
            "active_camera_count": len(cameras),
            "active_event_count": sum(info["active"] for info in per_camera.values()),
            "average_latency_ms": round(self._latency_ms, 3),
            "cameras": per_camera,
        }
