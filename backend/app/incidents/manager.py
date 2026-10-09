"""Incident operations service — V09 intelligence in, operational records out.

``IncidentManager`` is the single writer for incident state. It consumes the
public V09 contracts (``RiskIntelligenceResult`` / ``RiskCluster`` /
``UnifiedEvent`` via ``IntelligenceEngine.latest()`` and
``active_clusters()``) and never reaches into V09 private runtime state.

Write discipline (§50): only incident creation, meaningful risk updates,
meaningful event links, lifecycle changes, operator actions, and evidence
metadata persist. Sync is debounced per camera (skipped when V09 produced
nothing new) and every sync path is idempotent.
"""

from __future__ import annotations

import itertools
import json
import logging
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from backend.app.domain.common import utcnow
from backend.app.incidents.repository import (
    DuplicateIncidentError,
    IncidentNotFoundError,
    IncidentRepository,
)
from backend.app.incidents.schemas import (
    ActorType,
    Incident,
    IncidentStatus,
    TimelineEventType,
)
from backend.app.intelligence.schemas import (
    SEVERITY_RANK,
    EventPriority,
    UnifiedEvent,
    UnifiedSeverity,
)

logger = logging.getLogger("industrial-vision.incidents")

_PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}

_TERMINAL_STATES = ("RESOLVED", "CLOSED")

_RECENT_CHANGES_MAX = 200
_RESOLVE_SWEEP_SECONDS = 10.0


def _priority_rank(priority: EventPriority | str) -> int:
    value = priority.value if isinstance(priority, EventPriority) else str(priority)
    return _PRIORITY_RANK.get(value.upper(), 4)


class IncidentManager:
    """Owns incident lifecycle, numbering, timeline, evidence, and WS feed."""

    # Change kinds that map 1:1 onto bus event types ("incident_" + kind).
    LIFECYCLE_CHANGE_KINDS = frozenset(
        {
            "created",
            "updated",
            "status_changed",
            "assigned",
            "resolved",
            "closed",
            "evidence_added",
        }
    )

    def __init__(
        self,
        settings: Any,
        session_factory: Callable[[], Session],
        intelligence_engine: Any = None,
        *,
        event_bus: Any = None,
        operational_repository: Any = None,
        outbox_repository: Any = None,
    ) -> None:
        self._settings = settings
        self._repository = IncidentRepository(session_factory)
        self._intelligence = intelligence_engine
        self._event_bus = event_bus
        self._operational = operational_repository
        self._outbox = outbox_repository
        self._origin = f"incidents-{uuid.uuid4().hex[:12]}"
        # Idempotency for redelivered remote changes (crash recovery may
        # legitimately deliver twice; the feed must not duplicate). The
        # deque is pruned manually so the set never leaks evicted ids.
        self._remote_seen: deque[str] = deque()
        self._remote_seen_set: set[str] = set()
        self._lock = threading.RLock()
        self._open_index: dict[tuple[str, str], str] = {}
        self._last_synced: dict[str, datetime] = {}
        self._last_sweep: dict[str, float] = {}
        self._changes: deque[dict[str, Any]] = deque(maxlen=_RECENT_CHANGES_MAX)
        self._seq = itertools.count(1)
        self._metrics: dict[str, Any] = {
            "incidents_created": 0,
            "incidents_updated": 0,
            "incidents_resolved": 0,
            "incidents_closed": 0,
            "transitions_total": 0,
            "operations_total": 0,
            "sync_runs": 0,
            "processing_latency_ms": 0.0,
            "history_persisted": 0,
            "history_failures": 0,
            "outbox_queued": 0,
            "outbox_failures": 0,
            "remote_ingested": 0,
            "remote_dropped": 0,
        }

    # ------------------------------------------------------------------
    # Properties / reads
    # ------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return bool(self._settings.incidents_enabled)

    @property
    def repository(self) -> IncidentRepository:
        return self._repository

    def configure_distribution(
        self,
        *,
        event_bus: Any = None,
        operational_repository: Any = None,
        outbox_repository: Any = None,
    ) -> None:
        """Attach V12 distribution collaborators (additive; default off).

        Safe to call at any time; takes effect on subsequent syncs and
        operations. All hooks are failure-isolated.
        """
        with self._lock:
            if event_bus is not None:
                self._event_bus = event_bus
            if operational_repository is not None:
                self._operational = operational_repository
            if outbox_repository is not None:
                self._outbox = outbox_repository

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._metrics)

    def recent_changes(self, since_seq: int = 0, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            items = [c for c in self._changes if c["seq"] > since_seq]
            return items[-max(1, limit) :]

    def _record_change(
        self, kind: str, incident: Incident, message: str = "", **extra: Any
    ) -> dict[str, Any]:
        with self._lock:
            entry: dict[str, Any] = {
                "seq": next(self._seq),
                "kind": kind,
                "incident_id": str(incident.id),
                "incident_number": incident.incident_number,
                "camera_id": incident.camera_id,
                "title": incident.title,
                "status": incident.status.value,
                "priority": incident.priority.value,
                "risk_level": incident.risk_level.value,
                "risk_score": incident.risk_score,
                "timestamp": utcnow().isoformat(),
                "message": message,
            }
            entry.update(extra)
            self._changes.append(entry)
        # Durable delivery intent + history live outside the lock (I/O must
        # never hold the manager lock); failures are isolated, never raised.
        self._publish_lifecycle_change(entry)
        return entry

    # ------------------------------------------------------------------
    # V12 durable distribution (§4.4, §5.2)
    # ------------------------------------------------------------------
    def _publish_lifecycle_change(self, entry: dict[str, Any]) -> None:
        """Queue one outbox intent for a lifecycle change (best-effort).

        The incident row + timeline are already durable (V11 atomic move);
        this intent covers downstream notification. No-op without an
        outbox repository. Never raises.
        """
        if self._outbox is None:
            return
        try:
            kind = str(entry.get("kind", ""))
            if kind not in self.LIFECYCLE_CHANGE_KINDS:
                return
            incident_id = str(entry.get("incident_id", ""))
            event_id = f"incident:{incident_id}:{entry.get('seq', 0)}"
            # Origin is the bus (not this manager) so own-bus echoes —
            # local fan-out of our own intent — are skipped by the
            # remote-ingest guard instead of duplicating the feed.
            origin = self._origin
            if self._event_bus is not None:
                try:
                    origin = str(self._event_bus.origin)
                except Exception:
                    pass
            payload: dict[str, Any] = {
                "incident_id": incident_id,
                "incident_number": entry.get("incident_number"),
                "camera_id": entry.get("camera_id"),
                "status": entry.get("status"),
                "priority": entry.get("priority"),
            }
            for key in (
                "previous_status",
                "new_status",
                "resolution_reason",
                "closure_reason",
                "previous_assignee",
                "evidence_id",
                "evidence_type",
            ):
                if entry.get(key) is not None:
                    payload[key] = entry[key]
            from backend.app.events.envelope import EventEnvelope

            envelope = EventEnvelope(
                event_id=event_id,
                event_type=f"incident_{kind}",
                domain="INCIDENT",
                camera_id=str(entry.get("camera_id") or ""),
                origin=origin,
                payload=payload,
            )
            queued = self._outbox.enqueue(
                event_id, f"incident_{kind}", json.loads(envelope.model_dump_json())
            )
            with self._lock:
                if queued:
                    self._metrics["outbox_queued"] += 1
                else:
                    self._metrics["outbox_failures"] += 1
        except Exception as exc:
            logger.warning("incident outbox enqueue failed: %s", type(exc).__name__)
            with self._lock:
                self._metrics["outbox_failures"] += 1

    def _persist_member_events(self, members: list[Any], risk_level: str, risk_score: float) -> int:
        """Upsert member unified events into durable history (best-effort).

        Only incident-linked members persist — never every domain event.
        Returns rows created-or-refreshed. Never raises.
        """
        if self._operational is None:
            return 0
        persisted = 0
        for member in members:
            try:
                _, _created = self._operational.upsert_event(
                    event_id=str(member.event_id),
                    camera_id=str(member.camera_id),
                    source_domain=member.source_domain.value,
                    source_event_id=str(member.source_event_id),
                    event_type=member.event_type.value,
                    severity=member.severity.value,
                    risk_level=str(risk_level),
                    risk_score=float(risk_score),
                    status=member.status.value,
                    first_seen=member.first_seen,
                    last_seen=member.last_seen,
                    metadata={
                        "message": str(getattr(member, "message", "") or "")[:160],
                        "confidence": float(getattr(member, "confidence", 0.0) or 0.0),
                        "priority": str(getattr(getattr(member, "priority", None), "value", "P4")),
                    },
                )
                persisted += 1
            except Exception as exc:
                logger.warning("operational history upsert failed: %s", type(exc).__name__)
                with self._lock:
                    self._metrics["history_failures"] += 1
        if persisted:
            with self._lock:
                self._metrics["history_persisted"] += persisted
        return persisted

    def ingest_remote_change(self, envelope: dict[str, Any] | Any) -> dict[str, Any] | None:
        """Ingest a remotely-published incident change into the feed.

        Used by the distributed WS path: the incident row itself resolves
        from shared PostgreSQL; this entry only carries the feed position
        and display extras. Unknown kinds are dropped (never crash).
        Redeliveries of the same envelope event_id are dropped: crash
        recovery is expected to deliver twice.
        Own-origin echoes must be filtered by the caller.
        """
        try:
            data = dict(envelope) if isinstance(envelope, dict) else envelope.model_dump()
            event_id = str(data.get("event_id", ""))
            event_type = str(data.get("event_type", ""))
            if not event_type.startswith("incident_"):
                return None
            kind = event_type[len("incident_") :]
            if kind not in self.LIFECYCLE_CHANGE_KINDS:
                with self._lock:
                    self._metrics["remote_dropped"] += 1
                return None
            with self._lock:
                if event_id and event_id in self._remote_seen_set:
                    self._metrics["remote_dropped"] += 1
                    return None
                if event_id:
                    self._remote_seen.append(event_id)
                    self._remote_seen_set.add(event_id)
                    while len(self._remote_seen) > 5000:
                        self._remote_seen_set.discard(self._remote_seen.popleft())
            payload = data.get("payload") or {}
            if not isinstance(payload, dict):
                payload = {}
            incident_id = str(payload.get("incident_id") or data.get("incident_id") or "")
            if not incident_id:
                with self._lock:
                    self._metrics["remote_dropped"] += 1
                return None
            with self._lock:
                entry: dict[str, Any] = {
                    "seq": next(self._seq),
                    "kind": kind,
                    "incident_id": incident_id,
                    "incident_number": payload.get("incident_number", ""),
                    "camera_id": str(payload.get("camera_id") or data.get("camera_id") or ""),
                    "title": str(payload.get("title") or ""),
                    "status": str(payload.get("status") or ""),
                    "priority": str(payload.get("priority") or ""),
                    "risk_level": "",
                    "risk_score": 0.0,
                    "timestamp": str(
                        data.get("timestamp")
                        or (payload.get("timestamp") if isinstance(payload, dict) else "")
                        or utcnow().isoformat()
                    ),
                    "message": str(payload.get("message") or ""),
                    "remote": True,
                }
                for key in (
                    "previous_status",
                    "new_status",
                    "resolution_reason",
                    "closure_reason",
                    "previous_assignee",
                    "evidence_id",
                    "evidence_type",
                ):
                    if payload.get(key) is not None:
                        entry[key] = payload[key]
                self._changes.append(entry)
                self._metrics["remote_ingested"] += 1
                return dict(entry)
        except Exception as exc:
            logger.warning("remote change ingest failed: %s", type(exc).__name__)
            with self._lock:
                self._metrics["remote_dropped"] += 1
            return None

    def run_retention_cleanup(self, now: datetime | None = None) -> dict[str, int]:
        """Bounded retention deletes for history + sent outbox intents."""
        reference = now or utcnow()
        summary = {"history_deleted": 0, "outbox_deleted": 0}
        if self._operational is None or self._outbox is None:
            return summary
        try:
            retention_days = int(getattr(self._settings, "operational_event_retention_days", 90))
        except (TypeError, ValueError):
            retention_days = 90
        cutoff = reference - timedelta(days=max(1, retention_days))
        try:
            summary["history_deleted"] = self._operational.delete_older_than(cutoff, limit=500)
            summary["outbox_deleted"] = self._outbox.delete_sent_older_than(cutoff, limit=500)
        except Exception as exc:
            logger.warning("retention cleanup failed: %s", type(exc).__name__)
        return summary

    # ------------------------------------------------------------------
    # Automatic sync from V09 intelligence
    # ------------------------------------------------------------------
    def sync_camera(self, camera_id: str, timestamp: datetime) -> dict[str, int]:
        """Reconcile open incidents with the latest V09 intelligence output.

        Idempotent and debounced: cameras with no new intelligence output
        only run the periodic auto-resolve sweep. Returns operation counts.
        """
        summary = {"created": 0, "updated": 0, "resolved": 0, "linked": 0, "checked": 0}
        if not self.enabled or self._intelligence is None:
            return summary
        started = time.perf_counter()
        with self._lock:
            try:
                latest = self._intelligence.latest(camera_id)
            except Exception as exc:
                logger.warning("incident sync read failed for %s: %s", camera_id, exc)
                return summary
            last = self._last_synced.get(camera_id)
            fresh = latest is not None and (last is None or latest.timestamp > last)
            if fresh and latest is not None:
                self._last_synced[camera_id] = latest.timestamp
                for cluster in self._active_clusters(camera_id):
                    summary["checked"] += 1
                    created, updated, linked = self._reconcile_cluster(camera_id, cluster, timestamp)
                    summary["created"] += created
                    summary["updated"] += updated
                    summary["linked"] += linked
            now = time.monotonic()
            if now - self._last_sweep.get(camera_id, 0.0) >= _RESOLVE_SWEEP_SECONDS:
                self._last_sweep[camera_id] = now
                summary["resolved"] += self._auto_resolve_sweep(camera_id, timestamp)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            self._metrics["sync_runs"] += 1
            previous = self._metrics["processing_latency_ms"]
            self._metrics["processing_latency_ms"] = round(previous + 0.2 * (elapsed_ms - previous), 3)
            return summary

    def _active_clusters(self, camera_id: str) -> list[Any]:
        try:
            return list(self._intelligence.active_clusters(camera_id, 100))
        except Exception as exc:
            logger.warning("incident cluster read failed for %s: %s", camera_id, exc)
            return []

    def _eligible(self, priority: Any) -> bool:
        """Cluster priority at least as urgent as the configured minimum."""
        minimum = str(getattr(self._settings, "incident_min_priority", "P2")).upper()
        value = priority.value if isinstance(priority, EventPriority) else str(priority).upper()
        return _priority_rank(value) <= _priority_rank(minimum)

    def _reconcile_cluster(self, camera_id: str, cluster: Any, timestamp: datetime) -> tuple[int, int, int]:
        """Create or update the incident for one active cluster. Idempotent."""
        cluster_id = str(getattr(cluster, "cluster_id", ""))
        priority = getattr(cluster, "priority", EventPriority.P4)
        if not cluster_id or not self._eligible(priority):
            return 0, 0, 0
        incident = self._find_open(camera_id, cluster_id)
        if incident is None:
            return self._create_from_cluster(camera_id, cluster, timestamp)
        return self._update_from_cluster(incident, cluster, timestamp)

    def _find_open(self, camera_id: str, cluster_id: str) -> Incident | None:
        key = (camera_id, cluster_id)
        incident_id = self._open_index.get(key)
        if incident_id is not None:
            incident = self._repository.get_incident(incident_id)
            if incident is not None and incident.status.value not in ("CLOSED",):
                return incident
            self._open_index.pop(key, None)
        found = self._repository.find_open_for_cluster(camera_id, cluster_id)
        if found is not None:
            self._open_index[key] = str(found.id)
        return found

    def _member_events(self, camera_id: str, cluster: Any) -> list[UnifiedEvent]:
        wanted = set(getattr(cluster, "event_ids", []) or [])
        if not wanted:
            return []
        try:
            active = self._intelligence.active_events(camera_id, 200)
        except Exception:
            return []
        return [e for e in active if f"{e.source_domain.value}:{e.source_event_id}" in wanted]

    def _create_from_cluster(self, camera_id: str, cluster: Any, timestamp: datetime) -> tuple[int, int, int]:
        from backend.app.incidents.statemachine import category_for_domains as _category_for

        members = self._member_events(camera_id, cluster)
        severity = self._worst_severity(members)
        primary = members[0] if members else None
        if primary is not None:
            title = (primary.message or f"{primary.event_type.value} on {camera_id}")[:256]
        else:
            category = _category_for(list(getattr(cluster, "source_domains", []) or []))
            title = f"{category.value.title()} risk on {camera_id}"
        description = (
            f"Auto-created from risk cluster {cluster.cluster_id} "
            f"({cluster.risk_assessment.risk_level.value} {cluster.risk_assessment.risk_score:.2f}, "
            f"{len(members)} correlated event(s))."
        )
        try:
            incident = self._repository.create_manual(
                camera_id=camera_id,
                title=title,
                description=description,
                category=_category_for(list(getattr(cluster, "source_domains", []) or [])),
                priority=cluster.priority,
                metadata={"source": "AUTOMATIC", "cluster_risk_score": cluster.risk_assessment.risk_score},
                source_cluster_id=str(cluster.cluster_id),
                source_event_id=str(primary.event_id) if primary is not None else None,
                source="AUTOMATIC",
            )
        except DuplicateIncidentError:
            # Lost a creation race: another worker created it first. Fall
            # through to the update path instead of erroring.
            existing = self._repository.find_open_for_cluster(camera_id, str(cluster.cluster_id))
            if existing is None:
                raise
            self._open_index[(camera_id, str(cluster.cluster_id))] = str(existing.id)
            return self._update_from_cluster(existing, cluster, timestamp)
        self._repository.add_timeline_entry(
            str(incident.id),
            TimelineEventType.CREATED,
            message=f"Incident {incident.incident_number} created from risk cluster.",
            new_state=IncidentStatus.OPEN.value,
            timestamp=timestamp,
            metadata={"source": "AUTOMATIC", "cluster_id": str(cluster.cluster_id)},
        )
        linked = 0
        for member in members:
            if self._repository.link_event(
                str(incident.id),
                str(member.event_id),
                member.event_type.value,
                member.source_domain.value,
                is_primary=(primary is not None and member.event_id == primary.event_id),
            ):
                linked += 1
        # Durable history for incident-linked members (V12; best-effort).
        self._persist_member_events(
            members,
            cluster.risk_assessment.risk_level.value,
            cluster.risk_assessment.risk_score,
        )
        # Refresh risk/severity from the triggering cluster.
        self._repository.update_incident(
            str(incident.id),
            severity=severity,
            risk_level=cluster.risk_assessment.risk_level,
            risk_score=cluster.risk_assessment.risk_score,
            last_seen=timestamp,
        )
        refreshed = self._repository.get_incident(str(incident.id))
        assert refreshed is not None
        incident = refreshed
        self._open_index[(camera_id, str(cluster.cluster_id))] = str(incident.id)
        self._metrics["incidents_created"] += 1
        self._metrics["operations_total"] += 1
        self._record_change(
            "created", incident, f"Auto-created from {cluster.risk_assessment.risk_level.value} risk cluster."
        )
        return 1, 0, linked

    def _update_from_cluster(
        self, incident: Incident, cluster: Any, timestamp: datetime
    ) -> tuple[int, int, int]:
        members = self._member_events(incident.camera_id, cluster)
        changed = False
        fields: dict[str, Any] = {"last_seen": timestamp}
        assessment = cluster.risk_assessment
        if (
            assessment.risk_score != incident.risk_score
            or assessment.risk_level.value != incident.risk_level.value
        ):
            fields["risk_score"] = assessment.risk_score
            fields["risk_level"] = assessment.risk_level
            changed = True
        severity = self._worst_severity(members)
        if severity.value != incident.severity.value:
            fields["severity"] = severity
            changed = True
        # Priority auto-escalates upward only; never silently de-escalates.
        if _priority_rank(cluster.priority) < _priority_rank(incident.priority):
            old_priority = incident.priority
            fields["priority"] = cluster.priority
            changed = True
            self._repository.add_timeline_entry(
                str(incident.id),
                TimelineEventType.ESCALATED,
                message=f"Priority {old_priority.value} → {cluster.priority.value} on rising risk.",
                previous_state=old_priority.value,
                new_state=cluster.priority.value,
                timestamp=timestamp,
                metadata={"actor_type": ActorType.SYSTEM.value, "trigger": "risk-increase"},
            )
        linked = 0
        for member in members:
            if self._repository.link_event(
                str(incident.id),
                str(member.event_id),
                member.event_type.value,
                member.source_domain.value,
            ):
                linked += 1
        if linked:
            changed = True
            # Durable history for newly linked members (V12; best-effort).
            self._persist_member_events(members, assessment.risk_level.value, assessment.risk_score)
        if changed:
            updated = self._repository.update_incident(str(incident.id), **fields)
            assert updated is not None
            incident = updated
            if self._should_record_risk_update(incident, assessment, timestamp):
                self._repository.add_timeline_entry(
                    str(incident.id),
                    TimelineEventType.RISK_UPDATED,
                    message=f"Risk {assessment.risk_level.value} {assessment.risk_score:.2f}.",
                    timestamp=timestamp,
                    metadata={"risk_level": assessment.risk_level.value, "risk_score": assessment.risk_score},
                )
            self._metrics["incidents_updated"] += 1
            self._metrics["operations_total"] += 1
            self._record_change("updated", incident, "Risk update from correlated cluster.")
            return 0, 1, linked
        return 0, 0, linked

    def _should_record_risk_update(self, incident: Incident, assessment: Any, timestamp: datetime) -> bool:
        if assessment.risk_level.value != incident.risk_level.value:
            return True
        threshold = float(getattr(self._settings, "incident_timeline_update_threshold_seconds", 5.0))
        latest = self._repository.latest_timeline_entry(str(incident.id), TimelineEventType.RISK_UPDATED)
        if latest is None:
            return True
        try:
            return (timestamp - latest.timestamp).total_seconds() >= threshold
        except (TypeError, OverflowError):
            return True

    def _auto_resolve_sweep(self, camera_id: str, timestamp: datetime) -> int:
        """Conservatively resolve OPEN incidents whose clusters went quiet."""
        if not bool(getattr(self._settings, "incident_auto_resolve_enabled", True)):
            return 0
        grace = float(getattr(self._settings, "incident_auto_resolve_grace_seconds", 30.0))
        try:
            active_ids = {str(c.cluster_id) for c in self._intelligence.active_clusters(camera_id, 200)}
        except Exception:
            return 0
        resolved = 0
        open_incidents, _ = self._repository.list_incidents(camera_id=camera_id, status=["OPEN"])
        for incident in open_incidents:
            if incident.source_cluster_id in active_ids or incident.source_cluster_id is None:
                continue
            try:
                idle = (timestamp - incident.last_seen).total_seconds()
            except (TypeError, OverflowError):
                idle = grace
            if idle < grace:
                continue
            resolved_incident = self._move(
                str(incident.id),
                IncidentStatus.RESOLVED,
                TimelineEventType.RESOLVED,
                None,
                "Underlying risk cleared.",
                extra={"resolution_reason": "AUTOMATIC_CLEAR"},
            )
            self._metrics["incidents_resolved"] += 1
            self._record_change(
                "resolved",
                resolved_incident,
                "Resolved (AUTOMATIC_CLEAR).",
                resolution_reason="AUTOMATIC_CLEAR",
                actor_id=None,
            )
            resolved += 1
        # Bounded retention cleanup rides the periodic sweep (V12).
        self.run_retention_cleanup(timestamp)
        return resolved

    @staticmethod
    def _worst_severity(members: list[UnifiedEvent]) -> Any:
        worst = UnifiedSeverity.INFO
        for member in members:
            if SEVERITY_RANK.get(member.severity, 0.0) > SEVERITY_RANK.get(worst, 0.0):
                worst = member.severity
        return worst

    # ------------------------------------------------------------------
    # Operator operations (all timeline-recorded, all validated)
    # ------------------------------------------------------------------
    def _load_open(self, incident_id: str) -> Incident:
        incident = self._repository.get_incident(incident_id)
        if incident is None:
            raise IncidentNotFoundError(incident_id)
        if incident.status is IncidentStatus.CLOSED:
            raise InvalidIncidentStateError(incident_id, incident.status, "operation")
        return incident

    def create_manual(
        self,
        *,
        title: str,
        category: Any,
        priority: Any,
        description: str = "",
        camera_id: str | None = None,
        source_cluster_id: str | None = None,
        source_event_id: str | None = None,
        actor_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Incident:
        from backend.app.incidents.schemas import IncidentCategory
        from backend.app.intelligence.schemas import EventPriority

        clean_title = str(title or "").strip()
        if not clean_title:
            raise ValueError("incident title must not be empty")
        if len(clean_title) > 256:
            raise ValueError("incident title exceeds 256 characters")

        try:
            category_value = (
                category
                if isinstance(category, IncidentCategory)
                else IncidentCategory(str(category).upper())
            )
            priority_value = (
                priority if isinstance(priority, EventPriority) else EventPriority(str(priority).upper())
            )
        except ValueError as exc:
            raise ValueError(f"invalid category or priority: {exc}") from exc
        # Camera existence is validated by the API layer (which owns the
        # request-scoped session); the manager never guesses databases.
        incident = self._repository.create_manual(
            camera_id=camera_id,
            title=clean_title,
            description=description,
            category=category_value,
            priority=priority_value,
            metadata=metadata,
            source_cluster_id=source_cluster_id,
            source_event_id=source_event_id,
        )
        self._repository.add_timeline_entry(
            str(incident.id),
            TimelineEventType.CREATED,
            message=f"Incident {incident.incident_number} created manually.",
            new_state=IncidentStatus.OPEN.value,
            timestamp=utcnow(),
            metadata={"source": "MANUAL", "actor_id": actor_id},
        )
        if source_cluster_id and camera_id:
            self._open_index[(camera_id, source_cluster_id)] = str(incident.id)
        self._metrics["incidents_created"] += 1
        self._metrics["operations_total"] += 1
        self._record_change("created", incident, "Manual incident created.")
        return incident

    def acknowledge(self, incident_id: str, actor_id: str | None = None, reason: str = "") -> Incident:
        return self._move(
            incident_id,
            IncidentStatus.ACKNOWLEDGED,
            TimelineEventType.ACKNOWLEDGED,
            actor_id,
            reason or "Acknowledged by operator.",
        )

    def investigate(self, incident_id: str, actor_id: str | None = None, reason: str = "") -> Incident:
        return self._move(
            incident_id,
            IncidentStatus.INVESTIGATING,
            TimelineEventType.INVESTIGATION_STARTED,
            actor_id,
            reason or "Investigation started.",
        )

    def mitigate(self, incident_id: str, actor_id: str | None = None, reason: str = "") -> Incident:
        if not str(reason or "").strip():
            raise ValueError("mitigation requires a reason")
        return self._move(
            incident_id,
            IncidentStatus.MITIGATED,
            TimelineEventType.MITIGATED,
            actor_id,
            str(reason).strip(),
        )

    def resolve(
        self,
        incident_id: str,
        reason: Any,
        actor_id: str | None = None,
        detail: str = "",
    ) -> Incident:
        from backend.app.incidents.schemas import ResolutionReason

        try:
            resolution = (
                reason if isinstance(reason, ResolutionReason) else ResolutionReason(str(reason).upper())
            )
        except ValueError as exc:
            raise ValueError(f"invalid resolution reason: {reason!r}") from exc
        incident = self._move(
            incident_id,
            IncidentStatus.RESOLVED,
            TimelineEventType.RESOLVED,
            actor_id,
            detail.strip() or f"Resolved ({resolution.value}).",
            extra={"resolution_reason": resolution.value},
        )
        self._metrics["incidents_resolved"] += 1
        self._record_change(
            "resolved",
            incident,
            f"Resolved ({resolution.value}).",
            resolution_reason=resolution.value,
            actor_id=actor_id,
        )
        return incident

    def close(self, incident_id: str, closure_reason: str, actor_id: str | None = None) -> Incident:
        if not str(closure_reason or "").strip():
            raise ValueError("closure requires a closure_reason")
        incident = self._move(
            incident_id,
            IncidentStatus.CLOSED,
            TimelineEventType.CLOSED,
            actor_id,
            str(closure_reason).strip(),
            extra={"closure_reason": str(closure_reason).strip()},
        )
        self._open_index.pop((incident.camera_id, incident.source_cluster_id or ""), None)
        self._metrics["incidents_closed"] += 1
        self._record_change(
            "closed",
            incident,
            "Incident closed.",
            closure_reason=str(closure_reason).strip(),
            actor_id=actor_id,
        )
        return incident

    def assign(self, incident_id: str, assignee: str, actor_id: str | None = None) -> Incident:
        if not str(assignee or "").strip():
            raise ValueError("assignment requires a non-empty assignee")
        incident = self._load_open(incident_id)
        previous = incident.assigned_to
        self._repository.record_assignment(
            str(incident.id),
            str(assignee).strip(),
            previous,
            actor_id=actor_id,
            actor_type=ActorType.OPERATOR if actor_id else ActorType.SYSTEM,
        )
        self._repository.add_timeline_entry(
            str(incident.id),
            TimelineEventType.ASSIGNED,
            message=f"Assigned to {assignee.strip()} (was {previous or 'unassigned'}).",
            actor_id=actor_id,
            actor_type=ActorType.OPERATOR if actor_id else ActorType.SYSTEM,
            previous_state=previous,
            new_state=str(assignee).strip(),
        )
        updated = self._repository.get_incident(str(incident.id))
        assert updated is not None
        self._metrics["operations_total"] += 1
        self._record_change(
            "assigned",
            updated,
            f"Assigned to {assignee.strip()}.",
            previous_assignee=previous,
            actor_id=actor_id,
        )
        return updated

    def unassign(self, incident_id: str, actor_id: str | None = None) -> Incident:
        incident = self._load_open(incident_id)
        previous = incident.assigned_to
        self._repository.record_assignment(
            str(incident.id),
            None,
            previous,
            actor_id=actor_id,
            actor_type=ActorType.OPERATOR if actor_id else ActorType.SYSTEM,
        )
        self._repository.add_timeline_entry(
            str(incident.id),
            TimelineEventType.UNASSIGNED,
            message=f"Unassigned (was {previous or 'unassigned'}).",
            actor_id=actor_id,
            actor_type=ActorType.OPERATOR if actor_id else ActorType.SYSTEM,
            previous_state=previous,
            new_state=None,
        )
        updated = self._repository.get_incident(str(incident.id))
        assert updated is not None
        self._metrics["operations_total"] += 1
        self._record_change(
            "assigned",
            updated,
            "Unassigned.",
            previous_assignee=previous,
            actor_id=actor_id,
        )
        return updated

    def escalate(self, incident_id: str, priority: Any, reason: str, actor_id: str | None = None) -> Incident:
        from backend.app.intelligence.schemas import EventPriority

        try:
            target = priority if isinstance(priority, EventPriority) else EventPriority(str(priority).upper())
        except ValueError as exc:
            raise ValueError(f"invalid priority: {priority!r}") from exc
        if not str(reason or "").strip():
            raise ValueError("escalation requires a reason")
        incident = self._load_open(incident_id)
        if target.value == incident.priority.value:
            from backend.app.incidents.statemachine import InvalidTransitionError

            raise InvalidTransitionError(incident.status, incident.status)
        previous = incident.priority
        updated = self._repository.update_incident(str(incident.id), priority=target.value)
        assert updated is not None
        self._repository.add_timeline_entry(
            str(incident.id),
            TimelineEventType.ESCALATED,
            message=f"Priority {previous.value} → {target.value}: {str(reason).strip()}",
            actor_id=actor_id,
            actor_type=ActorType.OPERATOR if actor_id else ActorType.SYSTEM,
            previous_state=previous.value,
            new_state=target.value,
            metadata={"reason": str(reason).strip()},
        )
        self._metrics["operations_total"] += 1
        self._record_change("updated", updated, f"Priority {previous.value} → {target.value}.")
        return updated

    def add_note(
        self, incident_id: str, message: str, kind: Any = "NOTE", actor_id: str | None = None
    ) -> Incident:
        from backend.app.incidents.schemas import NoteKind

        try:
            note_kind = kind if isinstance(kind, NoteKind) else NoteKind(str(kind).upper())
        except ValueError as exc:
            raise ValueError(f"invalid note kind: {kind!r}") from exc
        if not str(message or "").strip():
            raise ValueError("note message must not be empty")
        incident = self._load_open(incident_id)
        self._repository.add_timeline_entry(
            str(incident.id),
            TimelineEventType.NOTE_ADDED,
            message=str(message).strip(),
            actor_id=actor_id,
            actor_type=ActorType.OPERATOR if actor_id else ActorType.SYSTEM,
            metadata={"kind": note_kind.value},
        )
        self._metrics["operations_total"] += 1
        self._record_change("updated", incident, f"{note_kind.value} recorded.")
        return incident

    def add_evidence(
        self,
        incident_id: str,
        evidence_type: Any,
        uri: str,
        description: str = "",
        frame_id: str | None = None,
        checksum: str | None = None,
        actor_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Any:
        from backend.app.incidents.schemas import EvidenceType

        try:
            etype = (
                evidence_type
                if isinstance(evidence_type, EvidenceType)
                else EvidenceType(str(evidence_type).upper())
            )
        except ValueError as exc:
            raise ValueError(f"invalid evidence type: {evidence_type!r}") from exc
        cleaned = str(uri or "").strip()
        if not cleaned:
            raise ValueError("evidence uri must not be empty")
        if len(cleaned) > 2048:
            raise ValueError("evidence uri exceeds 2048 characters")
        incident = self._load_open(incident_id)
        evidence = self._repository.add_evidence(
            str(incident.id),
            incident.camera_id,
            etype,
            cleaned,
            description=description,
            frame_id=frame_id,
            checksum=checksum,
            metadata=metadata,
        )
        self._repository.add_timeline_entry(
            str(incident.id),
            TimelineEventType.EVIDENCE_ADDED,
            message=f"Evidence added ({etype.value}): {cleaned[:160]}",
            actor_id=actor_id,
            actor_type=ActorType.OPERATOR if actor_id else ActorType.SYSTEM,
            metadata={"evidence_id": str(evidence.id)},
        )
        self._metrics["operations_total"] += 1
        self._record_change(
            "evidence_added",
            incident,
            f"Evidence added ({etype.value}).",
            evidence_id=str(evidence.id),
            evidence_type=etype.value,
            actor_id=actor_id,
        )
        return evidence

    def delete_evidence(self, incident_id: str, evidence_id: str, actor_id: str | None = None) -> None:
        incident = self._load_open(incident_id)
        if not self._repository.delete_evidence(str(incident.id), evidence_id):
            raise IncidentNotFoundError(f"evidence not found: {evidence_id} on incident {incident_id}")
        self._repository.add_timeline_entry(
            str(incident.id),
            TimelineEventType.NOTE_ADDED,
            message=f"Evidence {evidence_id} metadata deleted by {actor_id or 'system'}.",
            actor_id=actor_id,
            actor_type=ActorType.OPERATOR if actor_id else ActorType.SYSTEM,
            metadata={"evidence_id": evidence_id},
        )
        self._metrics["operations_total"] += 1
        self._record_change("updated", incident, "Evidence metadata deleted.")

    def patch(
        self,
        incident_id: str,
        title: str | None = None,
        description: str | None = None,
        metadata: dict[str, Any] | None = None,
        actor_id: str | None = None,
    ) -> Incident:
        incident = self._load_open(incident_id)
        fields: dict[str, Any] = {}
        if title is not None:
            if not str(title).strip():
                raise ValueError("title must not be empty")
            fields["title"] = str(title).strip()
        if description is not None:
            fields["description"] = str(description)
        if metadata is not None:
            fields["metadata"] = dict(metadata)
        if not fields:
            return incident
        updated = self._repository.update_incident(str(incident.id), **fields)
        assert updated is not None
        self._repository.add_timeline_entry(
            str(incident.id),
            TimelineEventType.NOTE_ADDED,
            message=f"Incident details updated ({', '.join(sorted(fields))}).",
            actor_id=actor_id,
            actor_type=ActorType.OPERATOR if actor_id else ActorType.SYSTEM,
        )
        self._metrics["operations_total"] += 1
        self._record_change("updated", updated, "Incident details updated.")
        return updated

    def get_detail(self, incident_id: str) -> dict[str, Any] | None:
        from backend.app.incidents.statemachine import allowed_actions

        incident = self._repository.get_incident(incident_id)
        if incident is None:
            return None
        timeline = self._repository.list_timeline(str(incident.id))
        linked = self._repository.list_linked_events(str(incident.id))
        evidence = self._repository.list_evidence(str(incident.id))
        assignments = self._repository.list_assignments(str(incident.id))
        return {
            "incident": {
                "id": str(incident.id),
                "incident_number": incident.incident_number,
                "camera_id": incident.camera_id,
                "title": incident.title,
                "description": incident.description,
                "source_cluster_id": incident.source_cluster_id,
                "primary_event_id": incident.primary_event_id,
                "severity": incident.severity.value,
                "risk_level": incident.risk_level.value,
                "risk_score": incident.risk_score,
                "priority": incident.priority.value,
                "status": incident.status.value,
                "category": incident.category.value,
                "source": incident.source,
                "first_seen": incident.first_seen.isoformat(),
                "last_seen": incident.last_seen.isoformat(),
                "created_at": incident.created_at.isoformat(),
                "updated_at": incident.updated_at.isoformat(),
                "acknowledged_at": incident.acknowledged_at.isoformat() if incident.acknowledged_at else None,
                "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
                "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
                "assigned_to": incident.assigned_to,
                "metadata": incident.metadata,
            },
            "timeline": [
                {
                    "id": str(e.id),
                    "event_type": e.event_type.value,
                    "actor_id": e.actor.actor_id,
                    "actor_type": e.actor.actor_type.value,
                    "message": e.message,
                    "previous_state": e.previous_state,
                    "new_state": e.new_state,
                    "timestamp": e.timestamp.isoformat(),
                    "metadata": e.metadata,
                }
                for e in timeline
            ],
            "linked_events": [{**e, "created_at": e["created_at"].isoformat()} for e in linked],
            "evidence": [
                {
                    "id": str(e.id),
                    "camera_id": e.camera_id,
                    "evidence_type": e.evidence_type.value,
                    "uri": e.uri,
                    "timestamp": e.timestamp.isoformat(),
                    "frame_id": e.frame_id,
                    "description": e.description,
                    "checksum": e.checksum,
                    "created_at": e.created_at.isoformat(),
                }
                for e in evidence
            ],
            "assignment": {
                "assigned_to": incident.assigned_to,
                "history": [
                    {
                        "assignee": a.assignee,
                        "previous_assignee": a.previous_assignee,
                        "actor_id": a.actor.actor_id,
                        "timestamp": a.timestamp.isoformat(),
                    }
                    for a in assignments
                ],
            },
            "risk_summary": {
                "risk_level": incident.risk_level.value,
                "risk_score": incident.risk_score,
                "priority": incident.priority.value,
                "severity": incident.severity.value,
            },
            "allowed_actions": list(allowed_actions(incident.status)),
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _move(
        self,
        incident_id: str,
        new_status: Any,
        timeline_type: Any,
        actor_id: str | None,
        message: str,
        extra: dict[str, Any] | None = None,
    ) -> Incident:
        incident = self._load_open(incident_id)
        previous = incident.status
        # Single transaction for state + audit row: no partial updates (§20).
        moved = self._repository.transition_with_timeline(
            str(incident.id),
            new_status,
            timeline_type,
            message=message,
            actor_id=actor_id,
            actor_type=ActorType.OPERATOR if actor_id else ActorType.SYSTEM,
            previous_state=previous.value,
            new_state=new_status.value,
            metadata=dict(extra or {}),
        )
        assert moved is not None
        self._metrics["transitions_total"] += 1
        self._metrics["operations_total"] += 1
        self._record_change(
            "status_changed",
            moved,
            message,
            previous_status=previous.value,
            new_status=new_status.value,
            actor_id=actor_id,
        )
        return moved


class InvalidIncidentStateError(ValueError):
    """An operation was attempted on an incident in a state that forbids it."""

    def __init__(self, incident_id: str, status: Any, operation: str) -> None:
        super().__init__(f"incident {incident_id} in status {status} forbids {operation}")
        self.incident_id = incident_id
        self.status = status
        self.operation = operation
