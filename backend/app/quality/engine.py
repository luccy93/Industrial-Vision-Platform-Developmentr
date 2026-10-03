"""Quality inspection engine — orchestrates inspection, decisions, events, sessions.

The engine owns the runtime half of V07: per-camera configuration snapshots,
ROI extraction, model invocation, observation mapping, decision policy,
event lifecycle, sessions, and metrics. Configuration comes from PostgreSQL
(see ``backend.app.quality.repository``); nothing frame-level is persisted.

Event hierarchy: ``DefectObservation → QualityDecision → QualityEvent``.
DEFECT_DETECTED events originate from actual observations (dedupe identity
``profile_id + defect_code + region_id``); QUALITY_FAIL/REVIEW/ERROR are the
inspection-level decision events. Consecutive failures touch one event instead
of creating per-frame spam.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from backend.app.core.config import Settings
from backend.app.domain.frame import IngestionFrame
from backend.app.quality.inspection import (
    InspectionErrorCode,
    InspectionModel,
    InspectionModelError,
)
from backend.app.quality.policy import decide, effective_thresholds
from backend.app.quality.regions import extract_roi, map_box_to_frame
from backend.app.quality.schemas import (
    DefectCategory,
    DefectObservation,
    DefectSeverity,
    InspectionProfile,
    InspectionRegion,
    InspectionResult,
    InspectionSession,
    ProfileDefectCategory,
    QualityDecision,
    QualityEvent,
    QualityEventStatus,
    QualityEventType,
)
from backend.app.spatial.geometry import pixel_to_normalized

logger = logging.getLogger("industrial-vision.quality")

FULL_FRAME_REGION = "full_frame"


def _ema(previous: float, sample: float, alpha: float = 0.2) -> float:
    return previous + alpha * (sample - previous)


class _CameraQualityState:
    """Per-camera runtime state (memory only, bounded)."""

    def __init__(self, settings: Settings) -> None:
        self.profiles: dict[str, InspectionProfile] = {}
        self.regions: dict[str, InspectionRegion] = {}
        self.categories: dict[str, DefectCategory] = {}
        self.associations: dict[str, dict[str, ProfileDefectCategory]] = {}
        self.sessions: dict[str, InspectionSession] = {}
        self.active: dict[str, QualityEvent] = {}
        self.recent: deque[QualityEvent] = deque(maxlen=settings.quality_max_events_per_camera)
        self.results: deque[InspectionResult] = deque(maxlen=settings.quality_max_results_per_camera)
        self.inspections = 0
        self.pass_count = 0
        self.fail_count = 0
        self.review_count = 0
        self.error_count = 0
        self.defect_count = 0
        self.frames_skipped = 0
        self.queue_depth = 0
        self.last_decision: QualityDecision | None = None
        self.last_inspection_at: datetime | None = None
        self.latency_ms = 0.0


class QualityInspectionEngine:
    """One engine for all cameras; per-camera state stays isolated."""

    def __init__(self, settings: Settings, model: InspectionModel | None = None) -> None:
        self._settings = settings
        self._model = model
        self._lock = threading.RLock()
        self._cameras: dict[str, _CameraQualityState] = {}
        self._inspection_times: deque[float] = deque(maxlen=50)

    @property
    def enabled(self) -> bool:
        return self._settings.quality_enabled

    @property
    def model(self) -> InspectionModel | None:
        return self._model

    @property
    def inspection_interval(self) -> int:
        return max(1, int(self._settings.quality_inspection_interval_frames))

    # ------------------------------------------------------------------
    # Configuration snapshot (loaded from PostgreSQL, never queried at runtime)
    # ------------------------------------------------------------------
    def set_profiles(
        self,
        camera_id: str,
        profiles: list[InspectionProfile],
        regions: list[InspectionRegion],
        categories: list[DefectCategory],
        associations: dict[str, dict[str, ProfileDefectCategory]] | None = None,
    ) -> None:
        state = self._camera_state(camera_id)
        with self._lock:
            state.profiles = {p.profile_id: p for p in profiles}
            state.regions = {r.region_id: r for r in regions}
            state.categories = {c.code.upper(): c for c in categories}
            state.associations = {
                profile_id: {code.upper(): assoc for code, assoc in items.items()}
                for profile_id, items in (associations or {}).items()
            }

    def _camera_state(self, camera_id: str) -> _CameraQualityState:
        with self._lock:
            state = self._cameras.get(camera_id)
            if state is None:
                state = _CameraQualityState(self._settings)
                self._cameras[camera_id] = state
            return state

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------
    def process(
        self,
        camera_id: str,
        frame: IngestionFrame,
        timestamp: datetime,
        frame_id: UUID | None,
    ) -> list[InspectionResult]:
        """Inspect one frame against every enabled profile of the camera."""
        state = self._camera_state(camera_id)
        with self._lock:
            profiles = sorted((p for p in state.profiles.values() if p.enabled), key=lambda p: p.profile_id)
        return [self.inspect(camera_id, profile, frame, timestamp, frame_id) for profile in profiles]

    def inspect(
        self,
        camera_id: str,
        profile: InspectionProfile,
        frame: IngestionFrame,
        timestamp: datetime,
        frame_id: UUID | None,
    ) -> InspectionResult:
        """Run one inspection pass for one profile. Never raises — an
        inspection that cannot complete reliably decides ERROR."""
        started = time.perf_counter()
        state = self._camera_state(camera_id)
        inspection_id = uuid4()
        error_code: str | None = None
        observations: list[DefectObservation] = []
        regions_evaluated: list[str] = []
        model_name: str | None = None
        model_version: str | None = None

        try:
            model = self._require_model()
            model_name = model.name
            model_version = model.version
            width, height = self._frame_dimensions(frame)
            regions = self._enabled_regions(state, profile)
            associations = state.associations.get(profile.profile_id, {})
            # A profile with explicit associations is an allowlist: only
            # associated codes are inspected. A profile with no associations
            # inspects every category the model reports.
            strict_allowlist = len(associations) > 0
            supported = model.supports(frozenset(state.categories))
            if regions:
                for region in regions:
                    roi = extract_roi(frame.image, region, width, height)
                    if roi.size == 0:
                        continue
                    raw = model.predict(
                        roi, camera_id=camera_id, frame_id=frame_id, region_id=region.region_id
                    )
                    regions_evaluated.append(region.region_id)
                    observations.extend(
                        self._to_observations(
                            raw,
                            region,
                            state,
                            strict_allowlist,
                            associations,
                            supported,
                            camera_id,
                            frame_id,
                            timestamp,
                            inspection_id,
                            width,
                            height,
                        )
                    )
            else:
                # No regions configured: inspect the full frame explicitly.
                raw = model.predict(
                    frame.image, camera_id=camera_id, frame_id=frame_id, region_id=FULL_FRAME_REGION
                )
                regions_evaluated.append(FULL_FRAME_REGION)
                observations.extend(
                    self._to_observations(
                        raw,
                        None,
                        state,
                        strict_allowlist,
                        associations,
                        supported,
                        camera_id,
                        frame_id,
                        timestamp,
                        inspection_id,
                        width,
                        height,
                    )
                )
            observations = observations[: self._settings.quality_max_observations_per_inspection]
            decision, reason, severity, evidence = decide(
                observations, profile.decision_policy, regions_evaluated
            )
        except InspectionModelError as exc:
            error_code = exc.code.value
            decision, reason, severity = (
                QualityDecision.ERROR,
                f"{exc.code.value}: {exc.message}",
                DefectSeverity.HIGH,
            )
            evidence = {"error_code": error_code}
        except Exception as exc:  # noqa: BLE001 — an inspection must never raise
            error_code = InspectionErrorCode.INSPECTION_MODEL_ERROR.value
            decision, reason, severity = (
                QualityDecision.ERROR,
                f"{error_code}: {type(exc).__name__}: {exc}",
                DefectSeverity.HIGH,
            )
            evidence = {"error_code": error_code}

        result = InspectionResult(
            inspection_id=inspection_id,
            camera_id=camera_id,
            profile_id=profile.profile_id,
            frame_id=str(frame_id) if frame_id is not None else None,
            timestamp=timestamp,
            decision=decision,
            decision_reason=reason,
            severity=severity,
            observations=observations,
            inspection_time_ms=round((time.perf_counter() - started) * 1000.0, 3),
            model_name=model_name,
            model_version=model_version,
            regions_evaluated=regions_evaluated,
            error_code=error_code,
            metadata=dict(evidence),
        )
        self._record(state, profile, timestamp, result)
        return result

    def _require_model(self) -> InspectionModel:
        if not self.enabled:
            raise InspectionModelError(
                InspectionErrorCode.INSPECTION_CONFIG_INVALID, "quality inspection is disabled"
            )
        model = self._model
        if model is None:
            raise InspectionModelError(
                InspectionErrorCode.INSPECTION_MODEL_NOT_CONFIGURED,
                "no inspection model configured (QUALITY_INSPECTION_MODEL is empty)",
            )
        if not model.is_ready:
            try:
                model.load()
            except InspectionModelError as exc:
                raise InspectionModelError(
                    InspectionErrorCode.INSPECTION_MODEL_NOT_READY, exc.message
                ) from exc
        return model

    def _frame_dimensions(self, frame: IngestionFrame) -> tuple[int, int]:
        width = int(frame.width)
        height = int(frame.height)
        if width <= 0 or height <= 0:
            raise InspectionModelError(InspectionErrorCode.FRAME_INVALID, "frame dimensions must be positive")
        return width, height

    def _enabled_regions(
        self, state: _CameraQualityState, profile: InspectionProfile
    ) -> list[InspectionRegion]:
        return sorted(
            (r for r in state.regions.values() if r.profile_id == profile.profile_id and r.enabled),
            key=lambda r: r.region_id,
        )

    def _to_observations(
        self,
        raw_defects: list[Any],
        region: InspectionRegion | None,
        state: _CameraQualityState,
        strict_allowlist: bool,
        associations: dict[str, ProfileDefectCategory],
        supported: frozenset[str],
        camera_id: str,
        frame_id: UUID | None,
        timestamp: datetime,
        inspection_id: UUID,
        width: int,
        height: int,
    ) -> list[DefectObservation]:
        observations: list[DefectObservation] = []
        for raw in raw_defects:
            code = str(getattr(raw, "code", "")).strip().upper()
            if not code:
                continue
            if supported and code not in supported:
                continue
            association = associations.get(code)
            if association is not None and not association.enabled:
                continue
            if strict_allowlist and association is None:
                continue
            category = self._category(state, code)
            _, review_threshold = effective_thresholds(category, association)
            confidence = min(1.0, max(0.0, float(raw.confidence)))
            if confidence < review_threshold:
                continue
            if region is not None:
                box = map_box_to_frame(raw.box, region, width, height)
            else:
                left, top = pixel_to_normalized(raw.box[0], raw.box[1], width, height)
                right, bottom = pixel_to_normalized(raw.box[2], raw.box[3], width, height)
                box = (left, top, right, bottom)
            observations.append(
                DefectObservation(
                    inspection_id=inspection_id,
                    camera_id=camera_id,
                    frame_id=str(frame_id) if frame_id is not None else None,
                    timestamp=timestamp,
                    defect_code=category.code,
                    defect_name=category.name,
                    severity=category.severity,
                    confidence=confidence,
                    bounding_box=box,
                    region_id=region.region_id if region is not None else FULL_FRAME_REGION,
                    evidence={"model_code": getattr(raw, "class_name", None) or code},
                    metadata=dict(getattr(raw, "metadata", {}) or {}),
                )
            )
        return observations

    def _category(self, state: _CameraQualityState, code: str) -> DefectCategory:
        category = state.categories.get(code)
        if category is None:
            # Uncatalogued code reported by a model: an explicit placeholder,
            # never a silent drop and never a fabricated category.
            category = DefectCategory(
                defect_id=f"unknown-{code.lower()}",
                code=code,
                name=f"{code.title()} (uncatalogued)",
                description="Uncatalogued defect code reported by the inspection model",
                severity=DefectSeverity.MEDIUM,
                enabled=True,
                confidence_threshold=self._settings.quality_default_confidence_threshold,
                review_threshold=self._settings.quality_default_review_threshold,
            )
            state.categories[code] = category
        return category

    # ------------------------------------------------------------------
    # Recording: sessions, counters, results, events
    # ------------------------------------------------------------------
    def _record(
        self,
        state: _CameraQualityState,
        profile: InspectionProfile,
        timestamp: datetime,
        result: InspectionResult,
    ) -> None:
        with self._lock:
            state.inspections += 1
            state.last_decision = result.decision
            state.last_inspection_at = timestamp
            state.latency_ms = _ema(state.latency_ms, result.inspection_time_ms)
            state.defect_count += len(result.observations)
            state.results.append(result)
            self._inspection_times.append(time.monotonic())
            if result.decision is QualityDecision.PASS:
                state.pass_count += 1
            elif result.decision is QualityDecision.FAIL:
                state.fail_count += 1
            elif result.decision is QualityDecision.REVIEW:
                state.review_count += 1
            else:
                state.error_count += 1

            session = state.sessions.get(profile.profile_id)
            if session is None:
                session = InspectionSession(camera_id=result.camera_id, profile_id=profile.profile_id)
                state.sessions[profile.profile_id] = session
            session.last_inspection_at = timestamp
            session.inspection_count += 1
            if result.decision is QualityDecision.PASS:
                session.pass_count += 1
            elif result.decision is QualityDecision.FAIL:
                session.fail_count += 1
            elif result.decision is QualityDecision.REVIEW:
                session.review_count += 1
            else:
                session.error_count += 1

            self._process_events(state, profile, timestamp, result)

    def _process_events(
        self,
        state: _CameraQualityState,
        profile: InspectionProfile,
        timestamp: datetime,
        result: InspectionResult,
    ) -> None:
        grace = self._settings.quality_event_resolution_grace_seconds
        touched: set[str] = set()

        if result.decision is QualityDecision.ERROR:
            decision_type = QualityEventType.QUALITY_ERROR
        elif result.decision is QualityDecision.FAIL:
            decision_type = QualityEventType.QUALITY_FAIL
        elif result.decision is QualityDecision.REVIEW:
            decision_type = QualityEventType.QUALITY_REVIEW
        else:
            decision_type = None
        if decision_type is not None:
            key = f"{profile.profile_id}|{decision_type.value}"
            touched.add(key)
            event = state.active.get(key)
            confidence = max((o.confidence for o in result.observations), default=0.0)
            if event is None:
                state.active[key] = QualityEvent(
                    inspection_id=result.inspection_id,
                    camera_id=result.camera_id,
                    event_type=decision_type,
                    decision=result.decision,
                    severity=result.severity,
                    confidence=confidence,
                    timestamp=timestamp,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    message=result.decision_reason,
                    observations=list(result.observations),
                    metadata={"profile_id": profile.profile_id, "error_code": result.error_code},
                )
            else:
                event.touch(timestamp)
                event.inspection_id = result.inspection_id
                event.confidence = max(event.confidence, confidence)
                event.message = result.decision_reason
                event.observations = list(result.observations)
                event.metadata["error_code"] = result.error_code

        seen: set[tuple[str, str]] = set()
        for observation in result.observations:
            identity = (observation.defect_code, observation.region_id or FULL_FRAME_REGION)
            if identity in seen:
                continue
            seen.add(identity)
            key = f"{profile.profile_id}|{QualityEventType.DEFECT_DETECTED.value}|{identity[0]}|{identity[1]}"
            touched.add(key)
            event = state.active.get(key)
            policy = profile.decision_policy
            defect_decision = (
                QualityDecision.FAIL
                if observation.confidence >= policy.fail_threshold
                and observation.severity in policy.fail_severities
                else QualityDecision.REVIEW
            )
            if event is None:
                state.active[key] = QualityEvent(
                    inspection_id=result.inspection_id,
                    camera_id=result.camera_id,
                    event_type=QualityEventType.DEFECT_DETECTED,
                    decision=defect_decision,
                    severity=observation.severity,
                    confidence=observation.confidence,
                    defect_code=observation.defect_code,
                    region_id=observation.region_id,
                    track_id=observation.track_id,
                    timestamp=timestamp,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    message=f"{observation.defect_name} observed in {identity[1]}",
                    observations=[observation],
                    metadata={"profile_id": profile.profile_id},
                )
            else:
                event.touch(timestamp)
                event.confidence = max(event.confidence, observation.confidence)
                event.decision = defect_decision
                event.observations = [observation]
                event.track_id = observation.track_id

        for key in [k for k, event in state.active.items() if k not in touched]:
            event = state.active[key]
            idle = (timestamp - event.last_seen).total_seconds()
            if idle >= grace:
                event.status = QualityEventStatus.RESOLVED
                event.touch(event.last_seen)
                state.recent.append(event)
                del state.active[key]

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def latest_result(self, camera_id: str) -> InspectionResult | None:
        state = self._cameras.get(camera_id)
        if state is None:
            return None
        with self._lock:
            return state.results[-1] if state.results else None

    def recent_results(self, camera_id: str, limit: int = 10) -> list[InspectionResult]:
        state = self._cameras.get(camera_id)
        if state is None:
            return []
        with self._lock:
            return list(state.results)[-max(1, limit) :]

    def active_events(self, camera_id: str, limit: int = 50) -> list[QualityEvent]:
        state = self._cameras.get(camera_id)
        if state is None:
            return []
        with self._lock:
            return list(state.active.values())[: max(1, limit)]

    def recent_events(self, camera_id: str, limit: int = 10) -> list[QualityEvent]:
        state = self._cameras.get(camera_id)
        if state is None:
            return []
        with self._lock:
            return list(state.recent)[-max(1, limit) :]

    def session(self, camera_id: str, profile_id: str) -> InspectionSession | None:
        state = self._cameras.get(camera_id)
        if state is None:
            return None
        with self._lock:
            return state.sessions.get(profile_id)

    def suppress(self, camera_id: str, event_id: str) -> QualityEventStatus:
        """Move an active event to SUPPRESSED. Raises ValueError if unknown."""
        state = self._cameras.get(camera_id)
        if state is None:
            raise ValueError(f"unknown event {event_id}")
        with self._lock:
            for key, event in list(state.active.items()):
                if str(event.event_id) == event_id:
                    event.status = QualityEventStatus.SUPPRESSED
                    state.recent.append(event)
                    del state.active[key]
                    return event.status
        raise ValueError(f"unknown event {event_id}")

    # ------------------------------------------------------------------
    # Runtime notes from the worker
    # ------------------------------------------------------------------
    def note_skipped(self, camera_id: str) -> None:
        state = self._camera_state(camera_id)
        with self._lock:
            state.frames_skipped += 1

    def note_queue_depth(self, camera_id: str, depth: int) -> None:
        state = self._camera_state(camera_id)
        with self._lock:
            state.queue_depth = max(0, int(depth))

    def reset_camera(self, camera_id: str) -> None:
        with self._lock:
            self._cameras.pop(camera_id, None)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        with self._lock:
            cameras: dict[str, Any] = {}
            inspections = passes = fails = reviews = errors = defects = skipped = 0
            active_profiles = active_sessions = 0
            last_inspection_at: datetime | None = None
            for camera_id, state in sorted(self._cameras.items()):
                cameras[camera_id] = {
                    "profiles": len(state.profiles),
                    "sessions": len(state.sessions),
                    "inspections": state.inspections,
                    "last_decision": state.last_decision.value if state.last_decision else None,
                    "last_inspection_at": (
                        state.last_inspection_at.isoformat() if state.last_inspection_at else None
                    ),
                    "frames_skipped": state.frames_skipped,
                    "queue_depth": state.queue_depth,
                }
                inspections += state.inspections
                passes += state.pass_count
                fails += state.fail_count
                reviews += state.review_count
                errors += state.error_count
                defects += state.defect_count
                skipped += state.frames_skipped
                active_profiles += len(state.profiles)
                active_sessions += len(state.sessions)
                if state.last_inspection_at is not None and (
                    last_inspection_at is None or state.last_inspection_at > last_inspection_at
                ):
                    last_inspection_at = state.last_inspection_at
            times = self._inspection_times
            fps = 0.0
            if len(times) >= 2:
                span = times[-1] - times[0]
                if span > 0:
                    fps = round((len(times) - 1) / span, 2)
            model_status = "NOT_CONFIGURED" if self._model is None else self._model.state.value
            return {
                "enabled": self.enabled,
                "engine_status": "READY" if self.enabled else "DISABLED",
                "model_status": model_status,
                "model_name": self._model.name if self._model else None,
                "model_version": self._model.version if self._model else None,
                "active_profiles": active_profiles,
                "active_sessions": active_sessions,
                "inspection_count": inspections,
                "pass_count": passes,
                "fail_count": fails,
                "review_count": reviews,
                "error_count": errors,
                "defect_count": defects,
                "average_inspection_ms": round(self._average_latency(), 3),
                "last_inspection_timestamp": (last_inspection_at.isoformat() if last_inspection_at else None),
                "frames_skipped": skipped,
                "inspection_fps": fps,
                "cameras": cameras,
            }

    def _average_latency(self) -> float:
        total = 0.0
        count = 0
        for state in self._cameras.values():
            if state.inspections:
                total += state.latency_ms
                count += 1
        return total / count if count else 0.0
