"""Event & risk intelligence engine — orchestration over domain engines.

The engine pulls active + recent events from the safety (V05+V06), quality
(V07), and autonomous (V08) engines, normalizes them into
:class:`UnifiedEvent`, deduplicates by source identity, correlates them into
:class:`RiskCluster` on shared identity/location/time, and scores everything
with explainable risk factors. It owns no detectors, trackers, geometry, or
models — only the intelligence derived from domain outputs.

Continuity model: domain engines already dedupe per frame, so a repeated
source event updates its unified event in place. Sources that vanish past
the resolution grace resolve without flapping. Clusters recompute every pass
from current members, so risk escalates and de-escalates deterministically.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any

from backend.app.domain.common import utcnow
from backend.app.intelligence.correlate import cluster_match_score
from backend.app.intelligence.normalize import ADAPTERS, is_spatial_safety_event
from backend.app.intelligence.risk import RiskEngine, max_priority, max_risk_level, priority_for
from backend.app.intelligence.schemas import (
    EventPriority,
    EventSourceDomain,
    RiskAssessment,
    RiskCluster,
    RiskIntelligenceResult,
    UnifiedEvent,
    UnifiedEventStatus,
    UnifiedSeverity,
)

logger = logging.getLogger("industrial-vision.intelligence")

RECENT_CLUSTERS_MAX = 20


def _ema(previous: float, sample: float, alpha: float = 0.2) -> float:
    return previous + alpha * (sample - previous)


class _CameraIntelState:
    """Per-camera intelligence state (memory only, bounded)."""

    def __init__(self, max_events: int, max_clusters: int) -> None:
        self.unified: dict[tuple[str, str], UnifiedEvent] = {}
        self.clusters: dict[str, RiskCluster] = {}
        self.recent: deque[UnifiedEvent] = deque(maxlen=max_events)
        self.recent_clusters: deque[RiskCluster] = deque(maxlen=RECENT_CLUSTERS_MAX)
        self.latest: RiskIntelligenceResult | None = None
        self.max_events = max_events
        self.max_clusters = max_clusters
        self.events_processed = 0
        self.events_normalized = 0
        self.events_deduplicated = 0
        self.clusters_created = 0
        self.clusters_resolved = 0
        self.risk_updates = 0
        self.latency_ms = 0.0


class IntelligenceEngine:
    """One engine for all cameras; per-camera state stays isolated."""

    def __init__(
        self,
        settings: Any,
        safety_engine: Any = None,
        quality_engine: Any = None,
        autonomous_engine: Any = None,
    ) -> None:
        self._settings = settings
        self._risk = RiskEngine.from_settings(settings)
        self._domains: dict[EventSourceDomain, Any] = {}
        if safety_engine is not None:
            self._domains[EventSourceDomain.SAFETY] = safety_engine
        if quality_engine is not None:
            self._domains[EventSourceDomain.QUALITY] = quality_engine
        if autonomous_engine is not None:
            self._domains[EventSourceDomain.AUTONOMOUS] = autonomous_engine
        self._lock = threading.RLock()
        self._cameras: dict[str, _CameraIntelState] = {}

    @property
    def enabled(self) -> bool:
        return bool(self._settings.intelligence_enabled)

    @property
    def risk_engine(self) -> RiskEngine:
        return self._risk

    def _camera_state(self, camera_id: str) -> _CameraIntelState:
        with self._lock:
            state = self._cameras.get(camera_id)
            if state is None:
                state = _CameraIntelState(
                    self._settings.intelligence_max_events_per_camera,
                    self._settings.intelligence_max_clusters_per_camera,
                )
                self._cameras[camera_id] = state
            return state

    def domain_availability(self) -> dict[str, dict[str, Any]]:
        """Honest per-domain availability (engine present and enabled)."""
        availability: dict[str, dict[str, Any]] = {}
        for domain in (
            EventSourceDomain.SAFETY,
            EventSourceDomain.SPATIAL,
            EventSourceDomain.QUALITY,
            EventSourceDomain.AUTONOMOUS,
        ):
            if domain is EventSourceDomain.SPATIAL:
                engine = self._domains.get(EventSourceDomain.SAFETY)
            else:
                engine = self._domains.get(domain)
            available = engine is not None and bool(getattr(engine, "enabled", True))
            availability[domain.value] = {"available": available, "active_events": 0}
        return availability

    # ------------------------------------------------------------------
    # Perception pass
    # ------------------------------------------------------------------
    def process(self, camera_id: str, timestamp: datetime) -> RiskIntelligenceResult:
        """Pull domain events, normalize, dedupe, correlate, and score."""
        started = time.perf_counter()
        state = self._camera_state(camera_id)
        if not self.enabled:
            return RiskIntelligenceResult(timestamp=timestamp, camera_id=camera_id)

        with self._lock:
            pulled = self._pull(camera_id)
            state.events_processed += len(pulled)
            seen: set[tuple[str, str]] = set()
            for domain, source in pulled:
                try:
                    adapter = ADAPTERS[domain]
                    unified = adapter.normalize(source)
                except ValueError as exc:
                    logger.warning("intelligence dropped malformed %s event: %s", domain.value, exc)
                    continue
                state.events_normalized += 1
                key = (unified.source_domain.value, unified.source_event_id)
                seen.add(key)
                existing = state.unified.get(key)
                if existing is None:
                    if unified.status is not UnifiedEventStatus.ACTIVE:
                        state.recent.append(unified)
                    else:
                        assessment = self._risk.assess_event(unified, timestamp=timestamp)
                        unified.risk_score = assessment.risk_score
                        unified.priority = priority_for(assessment.risk_level, unified.severity)
                        unified.reason = assessment.reason
                        state.unified[key] = unified
                else:
                    self._refresh(state, key, unified)
                    state.events_deduplicated += 1
            self._resolve_missing(state, seen, timestamp)
            self._enforce_event_cap(state)
            self._correlate(state, camera_id, timestamp)
            result = self._assemble(state, camera_id, timestamp)
            state.latest = result
            state.risk_updates += 1
            state.latency_ms = _ema(state.latency_ms, (time.perf_counter() - started) * 1000.0)
            return result

    def _pull(self, camera_id: str) -> list[tuple[EventSourceDomain, Any]]:
        """Snapshot active + recent source events from every wired domain."""
        pulled: list[tuple[EventSourceDomain, Any]] = []
        safety = self._domains.get(EventSourceDomain.SAFETY)
        if safety is not None:
            try:
                events = list(safety.active_events(camera_id, 50))
                events += [e for e in safety.recent_events(camera_id, 10) if e not in events]
            except Exception as exc:
                logger.warning("intelligence safety pull failed for %s: %s", camera_id, exc)
                events = []
            for event in events:
                domain = (
                    EventSourceDomain.SPATIAL if is_spatial_safety_event(event) else EventSourceDomain.SAFETY
                )
                pulled.append((domain, event))
        quality = self._domains.get(EventSourceDomain.QUALITY)
        if quality is not None:
            try:
                events = list(quality.active_events(camera_id, 50))
                events += [e for e in quality.recent_events(camera_id, 10) if e not in events]
            except Exception as exc:
                logger.warning("intelligence quality pull failed for %s: %s", camera_id, exc)
                events = []
            for event in events:
                pulled.append((EventSourceDomain.QUALITY, event))
        autonomous = self._domains.get(EventSourceDomain.AUTONOMOUS)
        if autonomous is not None:
            try:
                events = list(autonomous.active_events(camera_id, 50))
                events += [e for e in autonomous.recent_events(camera_id, 10) if e not in events]
            except Exception as exc:
                logger.warning("intelligence autonomous pull failed for %s: %s", camera_id, exc)
                events = []
            for event in events:
                pulled.append((EventSourceDomain.AUTONOMOUS, event))
        return pulled

    def _refresh(self, state: _CameraIntelState, key: tuple[str, str], fresh: UnifiedEvent) -> None:
        """Update a unified event from a fresh normalization.

        Terminal source states (RESOLVED/SUPPRESSED) finalize the unified
        event into the recent ring, mirroring domain-engine semantics: a
        reactivated source later creates a new unified event, exactly as the
        domain engine mints a new source event.
        """
        existing = state.unified[key]
        existing.confidence = fresh.confidence
        existing.severity = fresh.severity
        existing.message = fresh.message
        existing.evidence = fresh.evidence
        existing.track_ids = list(fresh.track_ids)
        existing.object_ids = list(fresh.object_ids)
        if fresh.location:
            existing.location = fresh.location
        if fresh.status is UnifiedEventStatus.ACTIVE:
            existing.status = UnifiedEventStatus.ACTIVE
            existing.touch(fresh.last_seen)
            assessment = self._risk.assess_event(existing, timestamp=fresh.last_seen)
            existing.risk_score = assessment.risk_score
            existing.priority = priority_for(assessment.risk_level, existing.severity)
            existing.reason = assessment.reason
        else:
            existing.status = fresh.status
            existing.touch(fresh.last_seen)
            state.recent.append(existing)
            del state.unified[key]

    def _resolve_missing(
        self, state: _CameraIntelState, seen: set[tuple[str, str]], timestamp: datetime
    ) -> None:
        """Resolve unified events whose sources vanished past the grace period."""
        grace = self._settings.event_resolution_grace_seconds
        for key in [k for k, e in state.unified.items() if k not in seen]:
            event = state.unified[key]
            if event.status is not UnifiedEventStatus.ACTIVE:
                continue
            try:
                idle = (timestamp - event.last_seen).total_seconds()
            except (TypeError, OverflowError):
                idle = grace
            if idle >= grace:
                event.status = UnifiedEventStatus.RESOLVED
                event.touch(event.last_seen)
                state.recent.append(event)
                del state.unified[key]

    def _enforce_event_cap(self, state: _CameraIntelState) -> None:
        """Bound unified events: resolved-first, then oldest active, with cluster fixup."""
        while len(state.unified) > state.max_events:
            candidates = sorted(
                state.unified.items(),
                key=lambda kv: (
                    kv[1].status is UnifiedEventStatus.ACTIVE,
                    kv[1].last_seen if isinstance(kv[1].last_seen, datetime) else utcnow(),
                ),
            )
            (domain, source_id), _ = candidates[0]
            del state.unified[(domain, source_id)]
            gone = f"{domain}:{source_id}"
            for cluster in state.clusters.values():
                if gone in cluster.event_ids:
                    cluster.event_ids = [mid for mid in cluster.event_ids if mid != gone]

    # ------------------------------------------------------------------
    # Correlation + cluster lifecycle
    # ------------------------------------------------------------------
    def _correlate(self, state: _CameraIntelState, camera_id: str, timestamp: datetime) -> None:
        window = self._settings.event_correlation_window_seconds
        for key in sorted(state.unified, key=lambda k: (k[0], k[1])):
            event = state.unified[key]
            if event.status is not UnifiedEventStatus.ACTIVE:
                continue
            if self._member_of_active_cluster(state, key):
                continue
            best_id: str | None = None
            best_score = 0.0
            for cluster_id in sorted(state.clusters):
                cluster = state.clusters[cluster_id]
                if cluster.status is not UnifiedEventStatus.ACTIVE:
                    continue
                members = self._cluster_members(state, cluster)
                fraction, linked = cluster_match_score(event, members, window)
                if linked > 0 and fraction > best_score:
                    best_score = fraction
                    best_id = cluster_id
            if best_id is None:
                self._create_cluster(state, camera_id, [event], timestamp)
            else:
                self._attach(state, best_id, event, timestamp)
        self._recompute_clusters(state, timestamp)
        self._resolve_clusters(state, timestamp)
        self._enforce_cluster_cap(state)

    def _member_key(self, event: UnifiedEvent) -> str:
        return f"{event.source_domain.value}:{event.source_event_id}"

    def _member_of_active_cluster(self, state: _CameraIntelState, key: tuple[str, str]) -> bool:
        member_key = f"{key[0]}:{key[1]}"
        for cluster in state.clusters.values():
            if cluster.status is UnifiedEventStatus.ACTIVE and member_key in cluster.event_ids:
                return True
        return False

    def _cluster_members(self, state: _CameraIntelState, cluster: RiskCluster) -> list[UnifiedEvent]:
        members: list[UnifiedEvent] = []
        for member_key in cluster.event_ids:
            for (domain, source_id), event in state.unified.items():
                if f"{domain}:{source_id}" == member_key and event.status is UnifiedEventStatus.ACTIVE:
                    members.append(event)
                    break
        return members

    def _create_cluster(
        self, state: _CameraIntelState, camera_id: str, members: list[UnifiedEvent], timestamp: datetime
    ) -> RiskCluster:
        cluster = RiskCluster(camera_id=camera_id, first_seen=timestamp, last_seen=timestamp)
        for event in members:
            member_key = self._member_key(event)
            if member_key not in cluster.event_ids:
                cluster.event_ids.append(member_key)
            event.related_event_ids = sorted({m for m in cluster.event_ids if m != member_key})
        self._refresh_cluster(state, cluster, timestamp)
        state.clusters[str(cluster.cluster_id)] = cluster
        state.clusters_created += 1
        return cluster

    def _attach(
        self, state: _CameraIntelState, cluster_id: str, event: UnifiedEvent, timestamp: datetime
    ) -> None:
        cluster = state.clusters[cluster_id]
        member_key = self._member_key(event)
        if member_key not in cluster.event_ids:
            cluster.event_ids.append(member_key)
        for member in self._cluster_members(state, cluster):
            member.related_event_ids = sorted({m for m in cluster.event_ids if m != self._member_key(member)})
        cluster.touch(timestamp)

    def _refresh_cluster(self, state: _CameraIntelState, cluster: RiskCluster, timestamp: datetime) -> None:
        members = self._cluster_members(state, cluster)
        if not members:
            # No touch: an emptied cluster must keep its last active time so
            # the grace-based resolver can retire it instead of refreshing
            # it alive forever.
            return
        assessment = self._risk.assess_cluster(members, cluster.first_seen, timestamp=timestamp)
        cluster.risk_assessment = assessment
        worst_severity = UnifiedSeverity.INFO
        for member in members:
            rank = self._severity_rank(member.severity)
            if rank > self._severity_rank(worst_severity):
                worst_severity = member.severity
        cluster.priority = priority_for(assessment.risk_level, worst_severity)
        cluster.track_ids = sorted({t for m in members for t in m.track_ids})
        cluster.object_ids = sorted({o for m in members for o in m.object_ids if o})
        cluster.source_domains = sorted({m.source_domain for m in members}, key=lambda d: d.value)
        cluster.event_count = max(cluster.event_count, len(cluster.event_ids))
        cluster.touch(timestamp)

    @staticmethod
    def _severity_rank(severity: UnifiedSeverity) -> float:
        from backend.app.intelligence.schemas import SEVERITY_RANK

        return SEVERITY_RANK.get(severity, 0.0)

    def _recompute_clusters(self, state: _CameraIntelState, timestamp: datetime) -> None:
        for cluster in state.clusters.values():
            if cluster.status is not UnifiedEventStatus.ACTIVE:
                continue
            self._refresh_cluster(state, cluster, timestamp)

    def _resolve_clusters(self, state: _CameraIntelState, timestamp: datetime) -> None:
        grace = self._settings.event_resolution_grace_seconds
        for cluster_id in [cid for cid, c in state.clusters.items() if c.status is UnifiedEventStatus.ACTIVE]:
            cluster = state.clusters[cluster_id]
            if self._cluster_members(state, cluster):
                continue
            try:
                idle = (timestamp - cluster.last_seen).total_seconds()
            except (TypeError, OverflowError):
                idle = grace
            if idle >= grace:
                cluster.status = UnifiedEventStatus.RESOLVED
                cluster.touch(cluster.last_seen)
                state.recent_clusters.append(cluster)
                del state.clusters[cluster_id]
                state.clusters_resolved += 1

    def _enforce_cluster_cap(self, state: _CameraIntelState) -> None:
        while len(state.clusters) > state.max_clusters:
            victim = sorted(
                state.clusters.items(),
                key=lambda kv: (kv[1].status is UnifiedEventStatus.ACTIVE, kv[1].last_seen),
            )[0][0]
            evicted = state.clusters.pop(victim)
            # Cap eviction preserves visibility: the cluster leaves the
            # active set but stays readable in the recent ring.
            state.recent_clusters.append(evicted)

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def _assemble(
        self, state: _CameraIntelState, camera_id: str, timestamp: datetime
    ) -> RiskIntelligenceResult:
        from backend.app.intelligence.schemas import RiskIntelligenceResult as Result

        active_events = sorted(
            (e for e in state.unified.values() if e.status is UnifiedEventStatus.ACTIVE),
            key=lambda e: (e.source_domain.value, e.source_event_id),
        )
        active_clusters = sorted(
            (c for c in state.clusters.values() if c.status is UnifiedEventStatus.ACTIVE),
            key=lambda c: str(c.cluster_id),
        )
        assessments = [c.risk_assessment for c in active_clusters]
        highest_risk: RiskAssessment | None = None
        for assessment in assessments:
            if highest_risk is None or (
                assessment.risk_level == max_risk_level(highest_risk.risk_level, assessment.risk_level)
                and assessment.risk_score >= highest_risk.risk_score
            ):
                highest_risk = assessment
        if highest_risk is None:
            highest_risk = RiskAssessment(timestamp=timestamp)
        highest_priority = EventPriority.P4
        for cluster in active_clusters:
            highest_priority = max_priority(highest_priority, cluster.priority)
        return Result(
            timestamp=timestamp,
            camera_id=camera_id,
            events=active_events,
            clusters=active_clusters,
            risk_assessments=assessments,
            highest_risk=highest_risk,
            highest_priority=highest_priority,
            active_event_count=len(active_events),
            active_cluster_count=len(active_clusters),
            metrics=self._metrics(state),
            metadata={},
        )

    def _metrics(self, state: _CameraIntelState) -> dict[str, Any]:
        return {
            "events_processed": state.events_processed,
            "events_normalized": state.events_normalized,
            "events_deduplicated": state.events_deduplicated,
            "clusters_created": state.clusters_created,
            "clusters_resolved": state.clusters_resolved,
            "risk_updates": state.risk_updates,
            "processing_latency_ms": round(state.latency_ms, 3),
        }

    def latest(self, camera_id: str) -> RiskIntelligenceResult | None:
        state = self._cameras.get(camera_id)
        return state.latest if state else None

    def active_events(self, camera_id: str, limit: int = 50) -> list[UnifiedEvent]:
        state = self._cameras.get(camera_id)
        if state is None:
            return []
        with self._lock:
            events = [e for e in state.unified.values() if e.status is UnifiedEventStatus.ACTIVE]
            events.sort(key=lambda e: (e.source_domain.value, e.source_event_id))
            return events[: max(1, limit)]

    def recent_events(self, camera_id: str, limit: int = 50) -> list[UnifiedEvent]:
        state = self._cameras.get(camera_id)
        if state is None:
            return []
        with self._lock:
            return list(state.recent)[-max(1, limit) :]

    def active_clusters(self, camera_id: str, limit: int = 50) -> list[RiskCluster]:
        state = self._cameras.get(camera_id)
        if state is None:
            return []
        with self._lock:
            clusters = [c for c in state.clusters.values() if c.status is UnifiedEventStatus.ACTIVE]
            clusters.sort(key=lambda c: str(c.cluster_id))
            return clusters[: max(1, limit)]

    def recent_clusters(self, camera_id: str, limit: int = 20) -> list[RiskCluster]:
        state = self._cameras.get(camera_id)
        if state is None:
            return []
        with self._lock:
            return list(state.recent_clusters)[-max(1, limit) :]

    def reset_camera(self, camera_id: str) -> None:
        with self._lock:
            self._cameras.pop(camera_id, None)

    def status(self) -> dict[str, Any]:
        with self._lock:
            cameras = sorted(self._cameras)
            per_camera: dict[str, Any] = {}
            total_events = 0
            total_clusters = 0
            highest_risk: RiskAssessment | None = None
            highest_priority = EventPriority.P4
            latency_total = 0.0
            latency_count = 0
            for camera_id in cameras:
                state = self._cameras[camera_id]
                active_events = [e for e in state.unified.values() if e.status is UnifiedEventStatus.ACTIVE]
                active_clusters = [
                    c for c in state.clusters.values() if c.status is UnifiedEventStatus.ACTIVE
                ]
                total_events += len(active_events)
                total_clusters += len(active_clusters)
                latest = state.latest
                if latest is not None:
                    if highest_risk is None:
                        highest_risk = latest.highest_risk
                    elif latest.highest_risk.risk_score > highest_risk.risk_score:
                        highest_risk = latest.highest_risk
                    highest_priority = max_priority(highest_priority, latest.highest_priority)
                if state.risk_updates:
                    latency_total += state.latency_ms
                    latency_count += 1
                per_camera[camera_id] = {
                    "active_events": len(active_events),
                    "active_clusters": len(active_clusters),
                    "highest_risk": latest.highest_risk.risk_score if latest else 0.0,
                    "highest_priority": latest.highest_priority.value if latest else EventPriority.P4.value,
                }
            if highest_risk is None:
                highest_risk = RiskAssessment(timestamp=utcnow())
            domains = self.domain_availability()
            for domain, engine in (
                (EventSourceDomain.SAFETY, self._domains.get(EventSourceDomain.SAFETY)),
                (EventSourceDomain.QUALITY, self._domains.get(EventSourceDomain.QUALITY)),
                (EventSourceDomain.AUTONOMOUS, self._domains.get(EventSourceDomain.AUTONOMOUS)),
            ):
                if engine is None:
                    continue
                try:
                    count = sum(len(engine.active_events(camera_id, 50)) for camera_id in cameras)
                except Exception:
                    count = 0
                domains[domain.value]["active_events"] = count
            try:
                safety = self._domains.get(EventSourceDomain.SAFETY)
                spatial_active = 0
                if safety is not None:
                    for camera_id in cameras:
                        try:
                            spatial_active += sum(
                                1 for e in safety.active_events(camera_id, 50) if is_spatial_safety_event(e)
                            )
                        except Exception:
                            continue
                domains[EventSourceDomain.SPATIAL.value]["active_events"] = spatial_active
            except Exception:
                pass
            return {
                "enabled": self.enabled,
                "engine_status": "READY" if self.enabled else "DISABLED",
                "active_events": total_events,
                "active_clusters": total_clusters,
                "highest_risk": {
                    "risk_score": highest_risk.risk_score,
                    "risk_level": highest_risk.risk_level.value,
                    "confidence": highest_risk.confidence,
                },
                "highest_priority": highest_priority.value,
                "metrics": {
                    "events_processed": sum(s.events_processed for s in self._cameras.values()),
                    "events_normalized": sum(s.events_normalized for s in self._cameras.values()),
                    "events_deduplicated": sum(s.events_deduplicated for s in self._cameras.values()),
                    "clusters_created": sum(s.clusters_created for s in self._cameras.values()),
                    "clusters_resolved": sum(s.clusters_resolved for s in self._cameras.values()),
                    "risk_updates": sum(s.risk_updates for s in self._cameras.values()),
                    "processing_latency_ms": round(latency_total / latency_count, 3)
                    if latency_count
                    else 0.0,
                },
                "configuration": {
                    "risk_low_threshold": self._settings.risk_low_threshold,
                    "risk_medium_threshold": self._settings.risk_medium_threshold,
                    "risk_high_threshold": self._settings.risk_high_threshold,
                    "risk_critical_threshold": self._settings.risk_critical_threshold,
                    "event_correlation_window_seconds": self._settings.event_correlation_window_seconds,
                    "event_resolution_grace_seconds": self._settings.event_resolution_grace_seconds,
                    "risk_base_score": self._settings.risk_base_score,
                    "risk_severity_weight": self._settings.risk_severity_weight,
                    "risk_persistence_weight": self._settings.risk_persistence_weight,
                    "risk_correlation_weight": self._settings.risk_correlation_weight,
                    "risk_confidence_weight": self._settings.risk_confidence_weight,
                    "intelligence_max_events_per_camera": (self._settings.intelligence_max_events_per_camera),
                    "intelligence_max_clusters_per_camera": (
                        self._settings.intelligence_max_clusters_per_camera
                    ),
                },
                "domains": domains,
                "cameras": per_camera,
            }
