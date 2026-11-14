"""Persistence for V37 governance intelligence.

Only the four V37 tables are written here. Existing V35 governance and V36
automation records are read through their own repositories. No method deletes a
row, cascades a delete, or mutates evidence, cases, custody, governance
workflow, automation jobs, or audit history.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.core.redaction import redact_structure, redact_text
from backend.app.domain.common import utcnow
from backend.app.forensics.custody import datetime_to_iso
from backend.app.governance.intelligence.constants import (
    DEFAULT_FACTOR_POINTS,
    DEFAULT_MODEL_ID,
    DEFAULT_MODEL_NAME,
    DEFAULT_MODEL_VERSION,
    DEFAULT_RISK_THRESHOLDS,
    DEFAULT_SLA_EFFECTIVE_FROM,
    DEFAULT_SLA_TARGETS,
    MAX_PAGE_SIZE,
    MAX_RECOMMENDATION_EVENTS,
    MAX_RECOMMENDATION_RATIONALE_LENGTH,
    MAX_RECOMMENDATION_TITLE_LENGTH,
    RECOMMENDATION_STATUS_VALUES,
    RECOMMENDATION_TRANSITIONS,
    SLA_TARGET_KEYS,
    RecommendationStatus,
    recommendation_id,
    recommendation_key,
    risk_model_row_id,
    sla_target_row_id,
    validate_factor_points,
    validate_sla_target,
    validate_thresholds,
)
from backend.app.governance.intelligence.errors import (
    RecommendationNotFoundError,
    RecommendationStateError,
    RecommendationVersionConflictError,
    RiskModelVersionConflictError,
    SlaTargetVersionConflictError,
)
from backend.app.models.governance_intelligence_orm import (
    GovernanceRecommendationEventORM,
    GovernanceRecommendationORM,
    GovernanceRiskModelORM,
    GovernanceSlaTargetORM,
)


def _new_id() -> str:
    return str(uuid.uuid4())


def _iso(value: datetime | None) -> str | None:
    return datetime_to_iso(value) if value is not None else None


def _safe_text(value: Any, limit: int) -> str:
    return redact_text(str(value or "")).strip()[:limit]


def _safe_dict(value: Any) -> dict[str, Any]:
    redacted = redact_structure(value if isinstance(value, Mapping) else {})
    return dict(redacted) if isinstance(redacted, Mapping) else {}


def _safe_list(value: Any, limit: int = 100) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    return sorted({_safe_text(item, 160) for item in value if str(item).strip()})[:limit]


def _normalize_dt(value: Any, fallback: datetime | None = None) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    if value:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None:
            return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    return fallback or utcnow()


def _model_to_dict(row: GovernanceRiskModelORM) -> dict[str, Any]:
    return {
        "model_id": row.model_id,
        "version": int(row.version),
        "name": row.name,
        "state": row.state,
        "thresholds": _safe_dict(row.thresholds),
        "factor_points": _safe_dict(row.factor_points),
        "effective_from": _iso(row.effective_from),
        "actor_id": row.actor_id,
        "actor_role": row.actor_role,
        "reason": row.reason,
        "idempotency_key": row.idempotency_key,
        "created_at": _iso(row.created_at),
    }


def _sla_to_dict(row: GovernanceSlaTargetORM) -> dict[str, Any]:
    return {
        "target_key": row.target_key,
        "version": int(row.version),
        "target_hours": int(row.target_hours),
        "warning_hours": int(row.warning_hours),
        "effective_from": _iso(row.effective_from),
        "actor_id": row.actor_id,
        "actor_role": row.actor_role,
        "reason": row.reason,
        "idempotency_key": row.idempotency_key,
        "created_at": _iso(row.created_at),
    }


def _recommendation_to_dict(row: GovernanceRecommendationORM) -> dict[str, Any]:
    return {
        "recommendation_id": row.id,
        "recommendation_key": row.recommendation_key,
        "rule_id": row.rule_id,
        "scope_type": row.scope_type,
        "scope_id": row.scope_id,
        "case_id": row.case_id,
        "severity": row.severity,
        "risk_level": row.risk_level,
        "title": row.title,
        "rationale": row.rationale,
        "source_refs": list(row.source_refs or []),
        "status": row.status,
        "version": int(row.version),
        "first_seen_at": _iso(row.first_seen_at),
        "last_evaluated_at": _iso(row.last_evaluated_at),
        "acknowledged_by": row.acknowledged_by,
        "acknowledged_at": _iso(row.acknowledged_at),
        "acknowledgement_reason": row.acknowledgement_reason,
        "dismissed_by": row.dismissed_by,
        "dismissed_at": _iso(row.dismissed_at),
        "dismissal_reason": row.dismissal_reason,
        "resolved_by": row.resolved_by,
        "resolved_at": _iso(row.resolved_at),
        "resolution_reason": row.resolution_reason,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
    }


def _event_to_dict(row: GovernanceRecommendationEventORM) -> dict[str, Any]:
    return {
        "event_id": row.id,
        "recommendation_id": row.recommendation_id,
        "event_type": row.event_type,
        "from_status": row.from_status,
        "to_status": row.to_status,
        "actor_id": row.actor_id,
        "actor_role": row.actor_role,
        "reason": row.reason,
        "detail": _safe_dict(row.detail),
        "created_at": _iso(row.created_at),
    }


class GovernanceIntelligenceRepository:
    """Governance-owned risk-model, SLA-target, and recommendation persistence."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------
    # Defaults
    # ------------------------------------------------------------------
    def ensure_defaults(self, *, now: datetime | None = None) -> dict[str, int]:
        """Seed default risk model and SLA targets idempotently."""
        moment = _normalize_dt(now, utcnow())
        created_models = 0
        created_targets = 0
        with self._session_factory() as session:
            existing_model = (
                session.query(GovernanceRiskModelORM)
                .filter_by(model_id=DEFAULT_MODEL_ID)
                .order_by(GovernanceRiskModelORM.version.desc())
                .first()
            )
            if existing_model is None:
                session.add(
                    GovernanceRiskModelORM(
                        id=risk_model_row_id(DEFAULT_MODEL_ID, DEFAULT_MODEL_VERSION),
                        model_id=DEFAULT_MODEL_ID,
                        version=DEFAULT_MODEL_VERSION,
                        name=DEFAULT_MODEL_NAME,
                        state="ENABLED",
                        thresholds={k: dict(v) for k, v in DEFAULT_RISK_THRESHOLDS.items()},
                        factor_points=dict(DEFAULT_FACTOR_POINTS),
                        effective_from=DEFAULT_SLA_EFFECTIVE_FROM,
                        actor_id="SYSTEM",
                        actor_role="SYSTEM",
                        reason="Seeded platform default risk model.",
                        created_at=moment,
                    )
                )
                created_models += 1
            for target_key in SLA_TARGET_KEYS:
                existing = (
                    session.query(GovernanceSlaTargetORM)
                    .filter_by(target_key=target_key)
                    .order_by(GovernanceSlaTargetORM.version.desc())
                    .first()
                )
                if existing is not None:
                    continue
                defaults = DEFAULT_SLA_TARGETS[target_key]
                session.add(
                    GovernanceSlaTargetORM(
                        id=sla_target_row_id(target_key, 1),
                        target_key=target_key,
                        version=1,
                        target_hours=int(defaults["target_hours"]),
                        warning_hours=int(defaults["warning_hours"]),
                        effective_from=DEFAULT_SLA_EFFECTIVE_FROM,
                        actor_id="SYSTEM",
                        actor_role="SYSTEM",
                        reason="Seeded platform default operational SLA target.",
                        created_at=moment,
                    )
                )
                created_targets += 1
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
        return {"risk_models": created_models, "sla_targets": created_targets}

    # ------------------------------------------------------------------
    # Risk models
    # ------------------------------------------------------------------
    def latest_risk_model(self) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceRiskModelORM)
                .filter_by(model_id=DEFAULT_MODEL_ID)
                .order_by(GovernanceRiskModelORM.version.desc())
                .first()
            )
            return _model_to_dict(row) if row is not None else None

    def list_risk_models(self, *, page: int = 1, page_size: int = 20) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(MAX_PAGE_SIZE, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernanceRiskModelORM).filter_by(model_id=DEFAULT_MODEL_ID)
            total = int(query.count())
            rows = (
                query.order_by(GovernanceRiskModelORM.version.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_model_to_dict(row) for row in rows], total

    def get_risk_model_version(self, version: int) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceRiskModelORM)
                .filter_by(model_id=DEFAULT_MODEL_ID, version=int(version))
                .one_or_none()
            )
            return _model_to_dict(row) if row is not None else None

    def create_risk_model(
        self,
        *,
        name: str,
        thresholds: Mapping[str, Any],
        factor_points: Mapping[str, Any] | None,
        effective_from: datetime | None,
        actor_id: str | None,
        actor_role: str,
        reason: str,
        idempotency_key: str | None = None,
        expected_version: int | None = None,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bool]:
        normalized_thresholds = validate_thresholds(thresholds)
        normalized_points = validate_factor_points(factor_points)
        moment = _normalize_dt(now, utcnow())
        effective = _normalize_dt(effective_from, moment)
        with self._session_factory() as session:
            if idempotency_key:
                existing = (
                    session.query(GovernanceRiskModelORM)
                    .filter_by(idempotency_key=str(idempotency_key))
                    .one_or_none()
                )
                if existing is not None:
                    return _model_to_dict(existing), False
            latest = (
                session.query(GovernanceRiskModelORM)
                .filter_by(model_id=DEFAULT_MODEL_ID)
                .order_by(GovernanceRiskModelORM.version.desc())
                .first()
            )
            latest_version = int(latest.version) if latest is not None else 0
            if expected_version is not None and int(expected_version) != latest_version:
                raise RiskModelVersionConflictError(int(expected_version), latest_version)
            next_version = latest_version + 1
            row = GovernanceRiskModelORM(
                id=risk_model_row_id(DEFAULT_MODEL_ID, next_version),
                model_id=DEFAULT_MODEL_ID,
                version=next_version,
                name=_safe_text(name, 128) or DEFAULT_MODEL_NAME,
                state="ENABLED",
                thresholds=normalized_thresholds,
                factor_points=normalized_points,
                effective_from=effective,
                actor_id=_safe_text(actor_id or "SYSTEM", 256),
                actor_role=_safe_text(actor_role or "SYSTEM", 16).upper(),
                reason=_safe_text(reason, 2048),
                idempotency_key=_safe_text(idempotency_key, 128) or None,
                created_at=moment,
            )
            session.add(row)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = (
                    session.query(GovernanceRiskModelORM)
                    .filter_by(model_id=DEFAULT_MODEL_ID, version=next_version)
                    .one_or_none()
                )
                if existing is None:
                    raise
                raise RiskModelVersionConflictError(next_version - 1, next_version) from None
            session.refresh(row)
            return _model_to_dict(row), True

    # ------------------------------------------------------------------
    # SLA targets
    # ------------------------------------------------------------------
    def latest_sla_targets(self) -> dict[str, dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceSlaTargetORM)
                .order_by(
                    GovernanceSlaTargetORM.target_key.asc(),
                    GovernanceSlaTargetORM.version.desc(),
                )
                .all()
            )
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            if row.target_key not in result:
                result[row.target_key] = _sla_to_dict(row)
        return result

    def list_sla_targets(
        self, *, target_key: str | None = None, page: int = 1, page_size: int = 20
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(MAX_PAGE_SIZE, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernanceSlaTargetORM)
            if target_key:
                query = query.filter_by(target_key=str(target_key).upper())
            total = int(query.count())
            rows = (
                query.order_by(
                    GovernanceSlaTargetORM.target_key.asc(),
                    GovernanceSlaTargetORM.version.desc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_sla_to_dict(row) for row in rows], total

    def sla_target_versions(self, target_key: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceSlaTargetORM)
                .filter_by(target_key=str(target_key).upper())
                .order_by(
                    GovernanceSlaTargetORM.effective_from.asc(),
                    GovernanceSlaTargetORM.version.asc(),
                )
                .all()
            )
            return [_sla_to_dict(row) for row in rows]

    def create_sla_target(
        self,
        *,
        target_key: str,
        target_hours: int,
        warning_hours: int,
        effective_from: datetime | None,
        actor_id: str | None,
        actor_role: str,
        reason: str,
        idempotency_key: str | None = None,
        expected_version: int | None = None,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bool]:
        normalized_key = str(target_key or "").upper()
        if normalized_key not in SLA_TARGET_KEYS:
            raise ValueError(f"unknown SLA target key: {target_key}")
        target, warning = validate_sla_target(target_hours, warning_hours)
        moment = _normalize_dt(now, utcnow())
        effective = _normalize_dt(effective_from, moment)
        with self._session_factory() as session:
            if idempotency_key:
                existing = (
                    session.query(GovernanceSlaTargetORM)
                    .filter_by(idempotency_key=str(idempotency_key))
                    .one_or_none()
                )
                if existing is not None:
                    return _sla_to_dict(existing), False
            latest = (
                session.query(GovernanceSlaTargetORM)
                .filter_by(target_key=normalized_key)
                .order_by(GovernanceSlaTargetORM.version.desc())
                .first()
            )
            latest_version = int(latest.version) if latest is not None else 0
            if expected_version is not None and int(expected_version) != latest_version:
                raise SlaTargetVersionConflictError(normalized_key, int(expected_version), latest_version)
            next_version = latest_version + 1
            row = GovernanceSlaTargetORM(
                id=sla_target_row_id(normalized_key, next_version),
                target_key=normalized_key,
                version=next_version,
                target_hours=target,
                warning_hours=warning,
                effective_from=effective,
                actor_id=_safe_text(actor_id or "SYSTEM", 256),
                actor_role=_safe_text(actor_role or "SYSTEM", 16).upper(),
                reason=_safe_text(reason, 2048),
                idempotency_key=_safe_text(idempotency_key, 128) or None,
                created_at=moment,
            )
            session.add(row)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = (
                    session.query(GovernanceSlaTargetORM)
                    .filter_by(target_key=normalized_key, version=next_version)
                    .one_or_none()
                )
                if existing is None:
                    raise
                raise SlaTargetVersionConflictError(normalized_key, next_version - 1, next_version) from None
            session.refresh(row)
            return _sla_to_dict(row), True

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------
    def sync_recommendations(
        self,
        candidates: Sequence[Mapping[str, Any]],
        *,
        now: datetime | None = None,
        max_items: int = 500,
    ) -> dict[str, Any]:
        """Upsert deterministic recommendations and auto-resolve cleared ones."""
        moment = _normalize_dt(now, utcnow())
        bounded = list(candidates)[: max(1, int(max_items))]
        candidate_map: dict[str, Mapping[str, Any]] = {}
        for candidate in bounded:
            key = recommendation_key(
                str(candidate.get("rule_id") or ""),
                str(candidate.get("scope_type") or ""),
                str(candidate.get("scope_id") or ""),
            )
            candidate_map[key] = candidate
        summary = {
            "created": 0,
            "refreshed": 0,
            "reopened": 0,
            "auto_resolved": 0,
            "suppressed": 0,
            "truncated": len(candidates) > len(bounded),
        }
        with self._session_factory() as session:
            existing_rows = (
                session.query(GovernanceRecommendationORM)
                .order_by(GovernanceRecommendationORM.updated_at.desc())
                .limit(max(1, int(max_items)) * 4)
                .all()
            )
            existing_by_key = {str(row.recommendation_key): row for row in existing_rows}

            for key, candidate in candidate_map.items():
                row = existing_by_key.get(key)
                if row is None:
                    row = GovernanceRecommendationORM(
                        id=recommendation_id(
                            str(candidate.get("rule_id") or ""),
                            str(candidate.get("scope_type") or ""),
                            str(candidate.get("scope_id") or ""),
                        ),
                        recommendation_key=key,
                        rule_id=_safe_text(candidate.get("rule_id"), 64).upper(),
                        scope_type=_safe_text(candidate.get("scope_type"), 32).upper(),
                        scope_id=_safe_text(candidate.get("scope_id"), 64),
                        case_id=_safe_text(candidate.get("case_id"), 36) or None,
                        severity=_safe_text(candidate.get("severity"), 16).upper(),
                        risk_level=_safe_text(candidate.get("risk_level"), 16).upper() or None,
                        title=_safe_text(candidate.get("title"), MAX_RECOMMENDATION_TITLE_LENGTH),
                        rationale=_safe_text(candidate.get("rationale"), MAX_RECOMMENDATION_RATIONALE_LENGTH),
                        source_refs=_safe_list(candidate.get("source_refs")),
                        status=RecommendationStatus.OPEN.value,
                        version=1,
                        first_seen_at=moment,
                        last_evaluated_at=moment,
                        created_at=moment,
                        updated_at=moment,
                    )
                    session.add(row)
                    session.flush()
                    session.add(
                        GovernanceRecommendationEventORM(
                            id=_new_id(),
                            recommendation_id=row.id,
                            event_type="CREATED",
                            from_status=None,
                            to_status=RecommendationStatus.OPEN.value,
                            actor_id="SYSTEM",
                            actor_role="SYSTEM",
                            reason="Recommendation created by deterministic refresh.",
                            detail={"rule_id": row.rule_id},
                            created_at=moment,
                        )
                    )
                    summary["created"] += 1
                    continue

                if row.status == RecommendationStatus.DISMISSED.value:
                    row.last_evaluated_at = moment
                    summary["suppressed"] += 1
                    continue
                if row.status == RecommendationStatus.RESOLVED.value:
                    previous = row.status
                    row.status = RecommendationStatus.OPEN.value
                    row.version = int(row.version) + 1
                    row.last_evaluated_at = moment
                    row.updated_at = moment
                    row.dismissed_by = None
                    row.dismissed_at = None
                    row.dismissal_reason = None
                    row.resolved_by = None
                    row.resolved_at = None
                    row.resolution_reason = None
                    row.acknowledged_by = None
                    row.acknowledged_at = None
                    row.acknowledgement_reason = None
                    session.add(
                        GovernanceRecommendationEventORM(
                            id=_new_id(),
                            recommendation_id=row.id,
                            event_type="REOPENED",
                            from_status=previous,
                            to_status=RecommendationStatus.OPEN.value,
                            actor_id="SYSTEM",
                            actor_role="SYSTEM",
                            reason="The source condition recurred after resolution.",
                            detail={"rule_id": row.rule_id},
                            created_at=moment,
                        )
                    )
                    summary["reopened"] += 1
                else:
                    summary["refreshed"] += 1
                row.severity = _safe_text(candidate.get("severity"), 16).upper()
                row.risk_level = _safe_text(candidate.get("risk_level"), 16).upper() or None
                row.title = _safe_text(candidate.get("title"), MAX_RECOMMENDATION_TITLE_LENGTH)
                row.rationale = _safe_text(candidate.get("rationale"), MAX_RECOMMENDATION_RATIONALE_LENGTH)
                row.source_refs = _safe_list(candidate.get("source_refs"))
                row.case_id = _safe_text(candidate.get("case_id"), 36) or None
                row.last_evaluated_at = moment
                row.updated_at = moment

            for key, row in existing_by_key.items():
                if key in candidate_map:
                    continue
                if row.status not in {
                    RecommendationStatus.OPEN.value,
                    RecommendationStatus.ACKNOWLEDGED.value,
                    RecommendationStatus.DISMISSED.value,
                }:
                    continue
                previous = row.status
                row.status = RecommendationStatus.RESOLVED.value
                row.version = int(row.version) + 1
                row.resolved_by = "SYSTEM"
                row.resolved_at = moment
                row.resolution_reason = "Source condition cleared."
                row.updated_at = moment
                session.add(
                    GovernanceRecommendationEventORM(
                        id=_new_id(),
                        recommendation_id=row.id,
                        event_type="AUTO_RESOLVED",
                        from_status=previous,
                        to_status=RecommendationStatus.RESOLVED.value,
                        actor_id="SYSTEM",
                        actor_role="SYSTEM",
                        reason="Source condition cleared.",
                        detail={"rule_id": row.rule_id},
                        created_at=moment,
                    )
                )
                summary["auto_resolved"] += 1
            session.commit()
        return summary

    def get_recommendation(self, recommendation_id_value: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.get(GovernanceRecommendationORM, str(recommendation_id_value))
            return _recommendation_to_dict(row) if row is not None else None

    def list_recommendations(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(MAX_PAGE_SIZE, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernanceRecommendationORM)
            if status:
                query = query.filter_by(status=str(status).upper())
            if severity:
                query = query.filter_by(severity=str(severity).upper())
            if rule_id:
                query = query.filter_by(rule_id=str(rule_id).upper())
            total = int(query.count())
            rows = (
                query.order_by(
                    GovernanceRecommendationORM.last_evaluated_at.desc(),
                    GovernanceRecommendationORM.id.asc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_recommendation_to_dict(row) for row in rows], total

    def recommendation_events(
        self, recommendation_id_value: str, *, limit: int = MAX_RECOMMENDATION_EVENTS
    ) -> list[dict[str, Any]]:
        limit = max(1, min(MAX_RECOMMENDATION_EVENTS, int(limit)))
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceRecommendationEventORM)
                .filter_by(recommendation_id=str(recommendation_id_value))
                .order_by(
                    GovernanceRecommendationEventORM.created_at.asc(),
                    GovernanceRecommendationEventORM.id.asc(),
                )
                .limit(limit)
                .all()
            )
            return [_event_to_dict(row) for row in rows]

    def transition_recommendation(
        self,
        recommendation_id_value: str,
        *,
        target_status: str,
        expected_version: int | None,
        actor_id: str | None,
        actor_role: str,
        reason: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        moment = _normalize_dt(now, utcnow())
        normalized_target = str(target_status).upper()
        if normalized_target not in RECOMMENDATION_STATUS_VALUES:
            raise RecommendationStateError(f"unsupported recommendation status: {target_status}")
        with self._session_factory() as session:
            row = session.get(GovernanceRecommendationORM, str(recommendation_id_value))
            if row is None:
                raise RecommendationNotFoundError(str(recommendation_id_value))
            if expected_version is not None and int(expected_version) != int(row.version):
                raise RecommendationVersionConflictError(
                    str(recommendation_id_value), int(expected_version), int(row.version)
                )
            current = str(row.status).upper()
            allowed = RECOMMENDATION_TRANSITIONS.get(current, frozenset())
            if normalized_target not in allowed:
                raise RecommendationStateError(
                    f"recommendation transition {current} -> {normalized_target} is not allowed"
                )
            previous = current
            row.status = normalized_target
            row.version = int(row.version) + 1
            row.updated_at = moment
            if normalized_target == RecommendationStatus.ACKNOWLEDGED.value:
                row.acknowledged_by = _safe_text(actor_id or "SYSTEM", 256)
                row.acknowledged_at = moment
                row.acknowledgement_reason = _safe_text(reason, 2048) or None
            elif normalized_target == RecommendationStatus.DISMISSED.value:
                row.dismissed_by = _safe_text(actor_id or "SYSTEM", 256)
                row.dismissed_at = moment
                row.dismissal_reason = _safe_text(reason, 500)
            elif normalized_target == RecommendationStatus.RESOLVED.value:
                row.resolved_by = _safe_text(actor_id or "SYSTEM", 256)
                row.resolved_at = moment
                row.resolution_reason = _safe_text(reason, 2048) or None
            elif normalized_target == RecommendationStatus.OPEN.value:
                row.dismissed_by = None
                row.dismissed_at = None
                row.dismissal_reason = None
                row.resolved_by = None
                row.resolved_at = None
                row.resolution_reason = None
                row.acknowledged_by = None
                row.acknowledged_at = None
                row.acknowledgement_reason = None
            event_type = {
                RecommendationStatus.ACKNOWLEDGED.value: "ACKNOWLEDGED",
                RecommendationStatus.DISMISSED.value: "DISMISSED",
                RecommendationStatus.RESOLVED.value: "RESOLVED",
                RecommendationStatus.OPEN.value: "REOPENED",
            }[normalized_target]
            session.add(
                GovernanceRecommendationEventORM(
                    id=_new_id(),
                    recommendation_id=row.id,
                    event_type=event_type,
                    from_status=previous,
                    to_status=normalized_target,
                    actor_id=_safe_text(actor_id or "SYSTEM", 256),
                    actor_role=_safe_text(actor_role or "SYSTEM", 16).upper(),
                    reason=_safe_text(reason, 2048),
                    detail={"rule_id": row.rule_id},
                    created_at=moment,
                )
            )
            session.commit()
            session.refresh(row)
            return _recommendation_to_dict(row)

    def recommendation_counts(self) -> dict[str, Any]:
        with self._session_factory() as session:
            by_status = {
                str(status): int(count)
                for status, count in (
                    session.query(
                        GovernanceRecommendationORM.status,
                        func.count(GovernanceRecommendationORM.id),
                    )
                    .group_by(GovernanceRecommendationORM.status)
                    .all()
                )
            }
            by_severity = {
                str(severity): int(count)
                for severity, count in (
                    session.query(
                        GovernanceRecommendationORM.severity,
                        func.count(GovernanceRecommendationORM.id),
                    )
                    .group_by(GovernanceRecommendationORM.severity)
                    .all()
                )
            }
            by_status_severity: dict[str, dict[str, int]] = {}
            for status, severity, count in (
                session.query(
                    GovernanceRecommendationORM.status,
                    GovernanceRecommendationORM.severity,
                    func.count(GovernanceRecommendationORM.id),
                )
                .group_by(
                    GovernanceRecommendationORM.status,
                    GovernanceRecommendationORM.severity,
                )
                .all()
            ):
                by_status_severity.setdefault(str(status), {})[str(severity)] = int(count)
            return {
                "total": sum(by_status.values()),
                "by_status": by_status,
                "by_severity": by_severity,
                "by_status_severity": by_status_severity,
            }

    def count_recommendations(self) -> int:
        with self._session_factory() as session:
            return int(session.query(GovernanceRecommendationORM).count())

    def recommendation_timestamps_in_range(
        self, start: datetime, end: datetime, *, limit: int = 5000
    ) -> list[dict[str, Any]]:
        """Return bounded recommendation lifecycle timestamps for trends."""
        limit = max(1, min(5000, int(limit)))
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceRecommendationEventORM)
                .filter(
                    GovernanceRecommendationEventORM.created_at >= start,
                    GovernanceRecommendationEventORM.created_at < end,
                )
                .order_by(GovernanceRecommendationEventORM.created_at.asc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "event_type": row.event_type,
                    "recommendation_id": row.recommendation_id,
                    "created_at": _iso(row.created_at),
                }
                for row in rows
            ]


__all__ = ["GovernanceIntelligenceRepository"]
