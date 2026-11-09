"""Forensic case persistence (V34).

All multi-row case mutations commit atomically in one session. The custody
ledger is append-only from the application's perspective: events are inserted
and the case's recorded head/count advance in the same transaction. Reads never
mutate protected source artifacts.
"""

from __future__ import annotations

import posixpath
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Any, cast

from sqlalchemy import func, or_, select
from sqlalchemy import update as sa_update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from backend.app.core.redaction import contains_sensitive_material, redact_structure, redact_text
from backend.app.domain.common import utcnow
from backend.app.forensics.constants import (
    CaseSeverity,
    CaseSource,
    CaseStatus,
    CaseType,
    CustodyEventType,
    EvidenceArtifactType,
    NoteType,
    NoteVisibility,
    VerificationOutcome,
)
from backend.app.forensics.custody import (
    GENESIS_HASH,
    build_event,
    datetime_to_iso,
    verify_custody_chain,
)
from backend.app.forensics.errors import (
    CaseVersionConflictError,
    EvidenceReferenceError,
    ForensicCaseNotFoundError,
    ForensicExportNotFoundError,
    ForensicNoteNotFoundError,
    NoteVersionConflictError,
    ResolutionRequirementsError,
    UnresolvedCriticalFindingError,
)
from backend.app.forensics.state import validate_case_transition
from backend.app.models.forensic_orm import (
    ForensicActionORM,
    ForensicAssignmentORM,
    ForensicCaseCounterORM,
    ForensicCaseORM,
    ForensicCorrelationORM,
    ForensicCustodyEventORM,
    ForensicEvidenceObservationORM,
    ForensicEvidenceReferenceORM,
    ForensicExportORM,
    ForensicIncidentLinkORM,
    ForensicNoteORM,
    ForensicNoteRevisionORM,
    ForensicVerificationRunORM,
)

_SHA256 = re.compile(r"^(?:sha256:)?([0-9a-fA-F]{64})$")
_SAFE_ARTIFACT = re.compile(r"[^A-Za-z0-9_.:/@+-]+")


def _new_id() -> str:
    return str(uuid.uuid4())


def _iso(value: datetime | None) -> str | None:
    return datetime_to_iso(value) if value is not None else None


def _safe_text(value: Any, limit: int) -> str:
    return redact_text(str(value or "")).strip()[:limit]


def normalize_sha256(value: Any, *, required: bool = False) -> str:
    text = str(value or "").strip()
    if not text:
        if required:
            raise EvidenceReferenceError("a SHA-256 digest is required for this reference")
        return ""
    match = _SHA256.match(text)
    if match is None:
        raise EvidenceReferenceError("invalid SHA-256 digest")
    return match.group(1).lower()


def validate_relative_path(value: Any) -> str:
    """Accept only safe POSIX-style relative paths; never absolute/traversal."""
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return ""
    if "\x00" in text or ":" in text.split("/")[0]:
        raise EvidenceReferenceError("evidence path must be relative and free of drive/stream prefixes")
    if text.startswith("/"):
        raise EvidenceReferenceError("evidence path must not be absolute")
    normalized = posixpath.normpath(text)
    if normalized in {"", ".", ".."} or normalized.startswith("../") or "/../" in normalized:
        raise EvidenceReferenceError("evidence path must not contain parent traversal")
    if normalized.startswith("/"):
        raise EvidenceReferenceError("evidence path must not be absolute")
    return normalized[:2048]


def _sanitize_artifact_id(value: Any) -> str:
    text = redact_text(str(value or "")).strip()
    text = _SAFE_ARTIFACT.sub("_", text)
    return text[:512]


def _case_to_dict(row: ForensicCaseORM) -> dict[str, Any]:
    return redact_structure(
        {
            "case_id": row.id,
            "case_number": row.case_number,
            "title": row.title,
            "description": row.description,
            "case_type": row.case_type,
            "severity": row.severity,
            "status": row.status,
            "priority": row.priority,
            "source": row.source,
            "originating_incident_id": row.originating_incident_id,
            "originating_audit_run_id": row.originating_audit_run_id,
            "created_by": row.created_by,
            "assigned_to": row.assigned_to,
            "version": int(row.version or 1),
            "resolution_summary": row.resolution_summary,
            "correlation_key": row.correlation_key,
            "custody_event_count": int(row.custody_event_count or 0),
            "custody_head_hash": row.custody_head_hash,
            "metadata": dict(row.meta or {}),
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
            "closed_at": _iso(row.closed_at),
        }
    )


def _correlation_to_dict(row: ForensicCorrelationORM) -> dict[str, Any]:
    return redact_structure(
        {
            "correlation_id": row.id,
            "case_id": row.case_id,
            "correlation_key": row.correlation_key,
            "finding_id": row.finding_id,
            "audit_run_id": row.audit_run_id,
            "artifact_id": row.artifact_id,
            "evidence_identifier": row.evidence_identifier,
            "checkpoint_id": row.checkpoint_id,
            "transparency_log_id": row.transparency_log_id,
            "manifest_id": row.manifest_id,
            "reason_code": row.reason_code,
            "classification": row.classification,
            "severity": row.severity,
            "resolved": bool(row.resolved),
            "metadata": dict(row.meta or {}),
            "created_at": _iso(row.created_at),
        }
    )


def _link_to_dict(row: ForensicIncidentLinkORM) -> dict[str, Any]:
    return redact_structure(
        {
            "link_id": row.id,
            "case_id": row.case_id,
            "incident_id": row.incident_id,
            "linked_by": row.linked_by,
            "linked_at": _iso(row.linked_at),
            "metadata": dict(row.meta or {}),
        }
    )


def _evidence_to_dict(row: ForensicEvidenceReferenceORM) -> dict[str, Any]:
    return redact_structure(
        {
            "reference_id": row.id,
            "case_id": row.case_id,
            "artifact_type": row.artifact_type,
            "artifact_id": row.artifact_id,
            "original_relative_path": row.original_relative_path,
            "expected_sha256": row.expected_sha256,
            "observed_sha256": row.observed_sha256,
            "source_audit_run_id": row.source_audit_run_id,
            "source_finding_id": row.source_finding_id,
            "capture_timestamp": _iso(row.capture_timestamp),
            "verification_status": row.verification_status,
            "verification_outcome": row.verification_outcome,
            "verification_detail": row.verification_detail,
            "reference_created_at": _iso(row.reference_created_at),
            "metadata": dict(row.meta or {}),
        }
    )


def _observation_to_dict(row: ForensicEvidenceObservationORM) -> dict[str, Any]:
    return redact_structure(
        {
            "observation_id": row.id,
            "reference_id": row.reference_id,
            "case_id": row.case_id,
            "observed_sha256": row.observed_sha256,
            "size_bytes": int(row.size_bytes or 0),
            "outcome": row.outcome,
            "detail": row.detail,
            "observed_at": _iso(row.observed_at),
            "metadata": dict(row.meta or {}),
        }
    )


def _event_to_dict(row: ForensicCustodyEventORM) -> dict[str, Any]:
    return redact_structure(
        {
            "event_id": row.id,
            "case_id": row.case_id,
            "sequence": int(row.sequence),
            "event_type": row.event_type,
            "timestamp": _iso(row.timestamp),
            "actor_id": row.actor_id,
            "actor_role": row.actor_role,
            "artifact_id": row.artifact_id,
            "previous_hash": row.previous_hash,
            "event_hash": row.event_hash,
            "metadata": dict(row.meta or {}),
        }
    )


def _note_to_dict(row: ForensicNoteORM) -> dict[str, Any]:
    return redact_structure(
        {
            "note_id": row.id,
            "case_id": row.case_id,
            "author_id": row.author_id,
            "note_type": row.note_type,
            "content": row.content,
            "visibility": row.visibility,
            "related_evidence_ids": list(row.related_evidence_ids or []),
            "version": int(row.version or 1),
            "edited_by": row.edited_by,
            "metadata": dict(row.meta or {}),
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
        }
    )


def _revision_to_dict(row: ForensicNoteRevisionORM) -> dict[str, Any]:
    return redact_structure(
        {
            "revision_id": row.id,
            "note_id": row.note_id,
            "case_id": row.case_id,
            "revision": int(row.revision),
            "content": row.content,
            "editor_id": row.editor_id,
            "edited_at": _iso(row.edited_at),
            "metadata": dict(row.meta or {}),
        }
    )


def _action_to_dict(row: ForensicActionORM) -> dict[str, Any]:
    return redact_structure(
        {
            "action_id": row.id,
            "case_id": row.case_id,
            "actor_id": row.actor_id,
            "action_type": row.action_type,
            "description": row.description,
            "related_finding_ids": list(row.related_finding_ids or []),
            "action_timestamp": _iso(row.action_timestamp),
            "result": row.result,
            "approval_reference": row.approval_reference,
            "metadata": dict(row.meta or {}),
        }
    )


def _assignment_to_dict(row: ForensicAssignmentORM) -> dict[str, Any]:
    return redact_structure(
        {
            "assignment_id": row.id,
            "case_id": row.case_id,
            "assignee": row.assignee,
            "previous_assignee": row.previous_assignee,
            "actor_id": row.actor_id,
            "reason": row.reason,
            "timestamp": _iso(row.timestamp),
            "metadata": dict(row.meta or {}),
        }
    )


def _export_to_dict(row: ForensicExportORM) -> dict[str, Any]:
    return redact_structure(
        {
            "export_id": row.id,
            "case_id": row.case_id,
            "filename": row.filename,
            "storage_relative_path": row.storage_relative_path,
            "sha256": row.sha256,
            "size_bytes": int(row.size_bytes),
            "file_count": int(row.file_count),
            "schema_version": row.schema_version,
            "policy_version": row.policy_version,
            "created_by": row.created_by,
            "created_at": _iso(row.created_at),
            "verified_at": _iso(row.verified_at),
            "verification_outcome": row.verification_outcome,
            "verification_detail": row.verification_detail,
            "manifest_digest": row.manifest_digest,
            "root_digest": row.root_digest,
            "evidence_bytes_included": bool(row.evidence_bytes_included),
            "metadata": dict(row.meta or {}),
        }
    )


def _verification_to_dict(row: ForensicVerificationRunORM) -> dict[str, Any]:
    return redact_structure(
        {
            "verification_id": row.id,
            "case_id": row.case_id,
            "actor_id": row.actor_id,
            "outcome": row.outcome,
            "report": dict(row.report or {}),
            "created_at": _iso(row.created_at),
            "metadata": dict(row.meta or {}),
        }
    )


def next_case_number(session: Session, year: int, retries: int = 5) -> str:
    """Allocate ``CASE-YYYY-XXXXXX`` with an atomic counter increment."""
    last_error: Exception | None = None
    for _ in range(max(1, retries)):
        try:
            incremented = cast(
                CursorResult,
                session.execute(
                    sa_update(ForensicCaseCounterORM)
                    .where(ForensicCaseCounterORM.year == year)
                    .values(last_number=ForensicCaseCounterORM.last_number + 1)
                ),
            ).rowcount
            if incremented == 0:
                session.add(ForensicCaseCounterORM(year=year, last_number=0))
                session.flush()
                continue
            session.flush()
            last_number = session.execute(
                select(ForensicCaseCounterORM.last_number).where(ForensicCaseCounterORM.year == year)
            ).scalar_one()
            number = f"CASE-{year}-{last_number:06d}"
            exists = session.query(ForensicCaseORM).filter_by(case_number=number).one_or_none()
            if exists is None:
                return number
            session.rollback()
        except (IntegrityError, OperationalError) as exc:
            last_error = exc
            session.rollback()
    raise last_error if last_error is not None else RuntimeError("case numbering exhausted")


class ForensicRepository:
    """Durable forensic case store behind one session factory."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------
    # Custody
    # ------------------------------------------------------------------
    def _append_custody(
        self,
        session: Session,
        case: ForensicCaseORM,
        event_type: CustodyEventType,
        *,
        actor_id: str,
        actor_role: str,
        artifact_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> dict[str, Any]:
        moment = timestamp or utcnow()
        sequence = int(case.custody_event_count or 0) + 1
        event = build_event(
            event_id=_new_id(),
            case_id=case.id,
            sequence=sequence,
            event_type=event_type,
            timestamp=moment,
            actor_id=actor_id or "SYSTEM",
            actor_role=(actor_role or "SYSTEM").upper(),
            previous_hash=case.custody_head_hash or GENESIS_HASH,
            artifact_id=artifact_id,
            metadata=metadata,
        )
        session.add(
            ForensicCustodyEventORM(
                id=event["event_id"],
                case_id=case.id,
                sequence=sequence,
                event_type=event["event_type"],
                timestamp=moment,
                actor_id=event["actor_id"],
                actor_role=event["actor_role"],
                artifact_id=event["artifact_id"] or None,
                previous_hash=event["previous_hash"],
                event_hash=event["event_hash"],
                meta=dict(event["metadata"]),
            )
        )
        case.custody_event_count = sequence
        case.custody_head_hash = event["event_hash"]
        case.updated_at = moment
        return event

    def list_custody_events(self, case_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(ForensicCustodyEventORM)
                .filter_by(case_id=str(case_id))
                .order_by(ForensicCustodyEventORM.sequence.asc())
                .all()
            )
            return [_event_to_dict(row) for row in rows]

    def verify_custody(self, case_id: str) -> dict[str, Any]:
        case = self.get_case(case_id)
        if case is None:
            raise ForensicCaseNotFoundError(case_id)
        events = self.list_custody_events(case_id)
        return verify_custody_chain(case=case, events=events).to_dict()

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------
    def create_case(
        self,
        *,
        title: str,
        description: str = "",
        case_type: CaseType | str = CaseType.FORENSIC_REVIEW,
        severity: CaseSeverity | str = CaseSeverity.MEDIUM,
        priority: str = "P4",
        source: CaseSource | str = CaseSource.MANUAL,
        originating_incident_id: str | None = None,
        originating_audit_run_id: str | None = None,
        created_by: str | None = None,
        assigned_to: str | None = None,
        correlation_key: str | None = None,
        idempotency_key: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        actor_id: str | None = None,
        actor_role: str = "SYSTEM",
        correlation: Mapping[str, Any] | None = None,
        incident_ids: Sequence[str] = (),
        evidence_refs: Sequence[Mapping[str, Any]] = (),
    ) -> tuple[dict[str, Any], bool]:
        """Create a case atomically with custody, links, and references.

        Returns ``(case, created)``. Duplicate idempotency/correlation keys
        return the existing case with ``created=False``.
        """
        now = utcnow()
        case_type_value = case_type.value if isinstance(case_type, CaseType) else str(case_type).upper()
        severity_value = severity.value if isinstance(severity, CaseSeverity) else str(severity).upper()
        source_value = source.value if isinstance(source, CaseSource) else str(source).upper()
        with self._session_factory() as session:
            if idempotency_key:
                existing = (
                    session.query(ForensicCaseORM)
                    .filter_by(idempotency_key=str(idempotency_key))
                    .one_or_none()
                )
                if existing is not None:
                    return _case_to_dict(existing), False
            if correlation_key:
                existing = (
                    session.query(ForensicCaseORM)
                    .filter_by(correlation_key=str(correlation_key))
                    .one_or_none()
                )
                if existing is not None:
                    return _case_to_dict(existing), False
            number = next_case_number(session, now.year)
            row = ForensicCaseORM(
                id=_new_id(),
                case_number=number,
                title=_safe_text(title, 256) or "Forensic investigation",
                description=_safe_text(description, 8192),
                case_type=case_type_value,
                severity=severity_value,
                status=CaseStatus.OPEN.value,
                priority=str(priority or "P4")[:8],
                source=source_value,
                originating_incident_id=str(originating_incident_id) if originating_incident_id else None,
                originating_audit_run_id=str(originating_audit_run_id) if originating_audit_run_id else None,
                created_by=_safe_text(created_by, 256) or None,
                assigned_to=_safe_text(assigned_to, 256) or None,
                version=1,
                correlation_key=str(correlation_key) if correlation_key else None,
                idempotency_key=str(idempotency_key) if idempotency_key else None,
                meta=dict(redact_structure(dict(metadata or {}))),
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.flush()
            self._append_custody(
                session,
                row,
                CustodyEventType.CASE_CREATED,
                actor_id=actor_id or "SYSTEM",
                actor_role=actor_role,
                metadata={
                    "case_number": row.case_number,
                    "case_type": row.case_type,
                    "severity": row.severity,
                    "source": row.source,
                },
                timestamp=now,
            )
            if row.assigned_to:
                session.add(
                    ForensicAssignmentORM(
                        id=_new_id(),
                        case_id=row.id,
                        assignee=row.assigned_to,
                        previous_assignee=None,
                        actor_id=actor_id or "SYSTEM",
                        reason="initial assignment",
                        timestamp=now,
                        meta={},
                    )
                )
                self._append_custody(
                    session,
                    row,
                    CustodyEventType.INVESTIGATOR_ASSIGNED,
                    actor_id=actor_id or "SYSTEM",
                    actor_role=actor_role,
                    metadata={"assignee": row.assigned_to},
                    timestamp=now,
                )
            for incident_id in incident_ids:
                self._insert_incident_link(
                    session,
                    row,
                    str(incident_id),
                    actor_id=actor_id or "SYSTEM",
                    actor_role=actor_role,
                    timestamp=now,
                )
            if correlation:
                self._insert_correlation(
                    session,
                    row,
                    correlation,
                    actor_id=actor_id or "SYSTEM",
                    actor_role=actor_role,
                    timestamp=now,
                )
            for ref in evidence_refs:
                self._insert_evidence_reference(
                    session,
                    row,
                    ref,
                    actor_id=actor_id or "SYSTEM",
                    actor_role=actor_role,
                    timestamp=now,
                )
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = None
                if idempotency_key:
                    existing = (
                        session.query(ForensicCaseORM)
                        .filter_by(idempotency_key=str(idempotency_key))
                        .one_or_none()
                    )
                if existing is None and correlation_key:
                    existing = (
                        session.query(ForensicCaseORM)
                        .filter_by(correlation_key=str(correlation_key))
                        .one_or_none()
                    )
                if existing is not None:
                    return _case_to_dict(existing), False
                raise
            session.refresh(row)
            return _case_to_dict(row), True

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.query(ForensicCaseORM).filter_by(id=str(case_id)).one_or_none()
            return _case_to_dict(row) if row is not None else None

    def get_case_row(self, session: Session, case_id: str) -> ForensicCaseORM:
        row = session.query(ForensicCaseORM).filter_by(id=str(case_id)).one_or_none()
        if row is None:
            raise ForensicCaseNotFoundError(case_id)
        return row

    def list_cases(
        self,
        *,
        status: Sequence[str] | None = None,
        severity: Sequence[str] | None = None,
        case_type: Sequence[str] | None = None,
        assigned_to: str | None = None,
        source: str | None = None,
        originating_incident_id: str | None = None,
        search: str | None = None,
        updated_from: datetime | None = None,
        updated_to: datetime | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(ForensicCaseORM)
            if status:
                query = query.filter(ForensicCaseORM.status.in_([str(v).upper() for v in status]))
            if severity:
                query = query.filter(ForensicCaseORM.severity.in_([str(v).upper() for v in severity]))
            if case_type:
                query = query.filter(ForensicCaseORM.case_type.in_([str(v).upper() for v in case_type]))
            if assigned_to is not None:
                query = query.filter(ForensicCaseORM.assigned_to == str(assigned_to))
            if source:
                query = query.filter(ForensicCaseORM.source == str(source).upper())
            if originating_incident_id:
                query = query.filter(ForensicCaseORM.originating_incident_id == str(originating_incident_id))
            if search:
                token = f"%{str(search).strip()}%"
                query = query.filter(
                    or_(
                        ForensicCaseORM.case_number.ilike(token),
                        ForensicCaseORM.title.ilike(token),
                        ForensicCaseORM.description.ilike(token),
                    )
                )
            if updated_from is not None:
                query = query.filter(ForensicCaseORM.updated_at >= updated_from)
            if updated_to is not None:
                query = query.filter(ForensicCaseORM.updated_at <= updated_to)
            total = int(query.count())
            rows = (
                query.order_by(ForensicCaseORM.updated_at.desc(), ForensicCaseORM.case_number.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_case_to_dict(row) for row in rows], total

    def summary(self) -> dict[str, Any]:
        with self._session_factory() as session:
            total = int(session.query(func.count(ForensicCaseORM.id)).scalar() or 0)
            status_rows = (
                session.query(ForensicCaseORM.status, func.count(ForensicCaseORM.id))
                .group_by(ForensicCaseORM.status)
                .all()
            )
            severity_rows = (
                session.query(ForensicCaseORM.severity, func.count(ForensicCaseORM.id))
                .group_by(ForensicCaseORM.severity)
                .all()
            )
            type_rows = (
                session.query(ForensicCaseORM.case_type, func.count(ForensicCaseORM.id))
                .group_by(ForensicCaseORM.case_type)
                .all()
            )
            recent = (
                session.query(ForensicCaseORM).order_by(ForensicCaseORM.updated_at.desc()).limit(10).all()
            )
        by_status = {str(status): int(count) for status, count in status_rows}
        by_severity = {str(sev): int(count) for sev, count in severity_rows}
        by_type = {str(kind): int(count) for kind, count in type_rows}
        return {
            "total": total,
            "open": by_status.get(CaseStatus.OPEN.value, 0),
            "triaged": by_status.get(CaseStatus.TRIAGED.value, 0),
            "investigating": by_status.get(CaseStatus.INVESTIGATING.value, 0),
            "containment_recommended": by_status.get(CaseStatus.CONTAINMENT_RECOMMENDED.value, 0),
            "awaiting_review": by_status.get(CaseStatus.AWAITING_REVIEW.value, 0),
            "resolved": by_status.get(CaseStatus.RESOLVED.value, 0),
            "closed": by_status.get(CaseStatus.CLOSED.value, 0),
            "critical": by_severity.get(CaseSeverity.CRITICAL.value, 0),
            "by_status": by_status,
            "by_severity": by_severity,
            "by_type": by_type,
            "recent": [_case_to_dict(row) for row in recent],
        }

    # ------------------------------------------------------------------
    # Correlation and incident links
    # ------------------------------------------------------------------
    def _insert_correlation(
        self,
        session: Session,
        case: ForensicCaseORM,
        correlation: Mapping[str, Any],
        *,
        actor_id: str,
        actor_role: str,
        timestamp: datetime,
    ) -> ForensicCorrelationORM:
        row = ForensicCorrelationORM(
            id=_new_id(),
            case_id=case.id,
            correlation_key=str(correlation.get("correlation_key") or "")[:64],
            finding_id=str(correlation.get("finding_id") or "") or None,
            audit_run_id=str(correlation.get("audit_run_id") or "") or None,
            artifact_id=_sanitize_artifact_id(correlation.get("artifact_id")) or None,
            evidence_identifier=_sanitize_artifact_id(correlation.get("evidence_identifier")) or None,
            checkpoint_id=_sanitize_artifact_id(correlation.get("checkpoint_id")) or None,
            transparency_log_id=_sanitize_artifact_id(correlation.get("transparency_log_id")) or None,
            manifest_id=_sanitize_artifact_id(correlation.get("manifest_id")) or None,
            reason_code=str(correlation.get("reason_code") or "")[:64] or None,
            classification=str(correlation.get("classification") or "SUSPICIOUS")[:32],
            severity=str(correlation.get("severity") or "MEDIUM")[:16],
            resolved=bool(correlation.get("resolved") or False),
            meta=dict(redact_structure(dict(correlation.get("metadata") or {}))),
            created_at=timestamp,
        )
        session.add(row)
        self._append_custody(
            session,
            case,
            CustodyEventType.FINDING_CORRELATED,
            actor_id=actor_id,
            actor_role=actor_role,
            artifact_id=row.artifact_id,
            metadata={
                "finding_id": row.finding_id,
                "audit_run_id": row.audit_run_id,
                "reason_code": row.reason_code,
                "classification": row.classification,
                "correlation_key": row.correlation_key,
            },
            timestamp=timestamp,
        )
        return row

    def _insert_incident_link(
        self,
        session: Session,
        case: ForensicCaseORM,
        incident_id: str,
        *,
        actor_id: str,
        actor_role: str,
        timestamp: datetime,
    ) -> ForensicIncidentLinkORM | None:
        if not incident_id:
            return None
        existing = (
            session.query(ForensicIncidentLinkORM)
            .filter_by(case_id=case.id, incident_id=str(incident_id))
            .one_or_none()
        )
        if existing is not None:
            return existing
        row = ForensicIncidentLinkORM(
            id=_new_id(),
            case_id=case.id,
            incident_id=str(incident_id),
            linked_by=actor_id,
            linked_at=timestamp,
            meta={},
        )
        session.add(row)
        self._append_custody(
            session,
            case,
            CustodyEventType.INCIDENT_LINKED,
            actor_id=actor_id,
            actor_role=actor_role,
            artifact_id=str(incident_id),
            metadata={"incident_id": str(incident_id)},
            timestamp=timestamp,
        )
        return row

    def link_incident(
        self,
        case_id: str,
        incident_id: str,
        *,
        actor_id: str,
        actor_role: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._session_factory() as session:
            case = self.get_case_row(session, case_id)
            row = self._insert_incident_link(
                session,
                case,
                incident_id,
                actor_id=actor_id,
                actor_role=actor_role,
                timestamp=utcnow(),
            )
            session.commit()
            assert row is not None
            session.refresh(row)
            return _link_to_dict(row)

    def link_correlation(
        self,
        case_id: str,
        correlation: Mapping[str, Any],
        *,
        actor_id: str,
        actor_role: str,
    ) -> dict[str, Any]:
        with self._session_factory() as session:
            case = self.get_case_row(session, case_id)
            finding_id = str(correlation.get("finding_id") or "")
            if finding_id:
                existing = (
                    session.query(ForensicCorrelationORM).filter_by(finding_id=finding_id).one_or_none()
                )
            else:
                existing = (
                    session.query(ForensicCorrelationORM)
                    .filter_by(correlation_key=str(correlation.get("correlation_key") or ""))
                    .first()
                )
            if existing is not None:
                return _correlation_to_dict(existing)
            row = self._insert_correlation(
                session,
                case,
                correlation,
                actor_id=actor_id,
                actor_role=actor_role,
                timestamp=utcnow(),
            )
            session.commit()
            session.refresh(row)
            return _correlation_to_dict(row)

    def find_case_by_correlation_key(self, key: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.query(ForensicCaseORM).filter_by(correlation_key=str(key)).one_or_none()
            return _case_to_dict(row) if row is not None else None

    def find_correlation_by_finding_id(self, finding_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.query(ForensicCorrelationORM).filter_by(finding_id=str(finding_id)).one_or_none()
            return _correlation_to_dict(row) if row is not None else None

    def list_correlations(self, case_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(ForensicCorrelationORM)
                .filter_by(case_id=str(case_id))
                .order_by(ForensicCorrelationORM.created_at.asc())
                .all()
            )
            return [_correlation_to_dict(row) for row in rows]

    def list_incident_links(self, case_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(ForensicIncidentLinkORM)
                .filter_by(case_id=str(case_id))
                .order_by(ForensicIncidentLinkORM.linked_at.asc())
                .all()
            )
            return [_link_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Evidence references
    # ------------------------------------------------------------------
    def _insert_evidence_reference(
        self,
        session: Session,
        case: ForensicCaseORM,
        reference: Mapping[str, Any],
        *,
        actor_id: str,
        actor_role: str,
        timestamp: datetime,
    ) -> ForensicEvidenceReferenceORM:
        artifact_type = str(reference.get("artifact_type") or "").upper()
        try:
            EvidenceArtifactType(artifact_type)
        except ValueError:
            raise EvidenceReferenceError(f"unsupported artifact type: {artifact_type}") from None
        artifact_id = _sanitize_artifact_id(reference.get("artifact_id"))
        if not artifact_id:
            raise EvidenceReferenceError("artifact_id is required")
        relative_path = validate_relative_path(reference.get("original_relative_path"))
        expected = normalize_sha256(
            reference.get("expected_sha256"),
            required=artifact_type
            in {
                EvidenceArtifactType.EVIDENCE_FILE.value,
                EvidenceArtifactType.EVIDENCE_SIDECAR.value,
                EvidenceArtifactType.EVIDENCE_AUDIT_CHAIN.value,
                EvidenceArtifactType.SIGNED_CHECKPOINT.value,
                EvidenceArtifactType.TRUST_STATE.value,
                EvidenceArtifactType.TRUST_STORE.value,
                EvidenceArtifactType.TRANSPARENCY_LOG.value,
                EvidenceArtifactType.TREE_HEAD.value,
                EvidenceArtifactType.INCLUSION_PROOF.value,
                EvidenceArtifactType.CONSISTENCY_PROOF.value,
                EvidenceArtifactType.RECEIPT.value,
            },
        )
        existing = (
            session.query(ForensicEvidenceReferenceORM)
            .filter_by(
                case_id=case.id,
                artifact_type=artifact_type,
                artifact_id=artifact_id,
                expected_sha256=expected,
            )
            .one_or_none()
        )
        if existing is not None:
            return existing
        row = ForensicEvidenceReferenceORM(
            id=_new_id(),
            case_id=case.id,
            artifact_type=artifact_type,
            artifact_id=artifact_id,
            original_relative_path=relative_path,
            expected_sha256=expected,
            observed_sha256="",
            source_audit_run_id=str(reference.get("source_audit_run_id") or "") or None,
            source_finding_id=str(reference.get("source_finding_id") or "") or None,
            capture_timestamp=reference.get("capture_timestamp")
            if isinstance(reference.get("capture_timestamp"), datetime)
            else None,
            verification_status=str(reference.get("verification_status") or "NOT_RUN")[:16],
            verification_outcome=str(reference.get("verification_outcome") or "NOT_RUN")[:16],
            verification_detail=_safe_text(reference.get("verification_detail"), 1024),
            reference_created_at=timestamp,
            meta=dict(redact_structure(dict(reference.get("metadata") or {}))),
        )
        session.add(row)
        self._append_custody(
            session,
            case,
            CustodyEventType.EVIDENCE_REFERENCED,
            actor_id=actor_id,
            actor_role=actor_role,
            artifact_id=artifact_id,
            metadata={
                "reference_id": row.id,
                "artifact_type": artifact_type,
                "expected_sha256": expected,
                "relative_path": relative_path,
            },
            timestamp=timestamp,
        )
        return row

    def add_evidence_reference(
        self,
        case_id: str,
        reference: Mapping[str, Any],
        *,
        actor_id: str,
        actor_role: str,
    ) -> dict[str, Any]:
        with self._session_factory() as session:
            case = self.get_case_row(session, case_id)
            row = self._insert_evidence_reference(
                session,
                case,
                reference,
                actor_id=actor_id,
                actor_role=actor_role,
                timestamp=utcnow(),
            )
            session.commit()
            session.refresh(row)
            return _evidence_to_dict(row)

    def list_evidence_references(self, case_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(ForensicEvidenceReferenceORM)
                .filter_by(case_id=str(case_id))
                .order_by(ForensicEvidenceReferenceORM.reference_created_at.asc())
                .all()
            )
            return [_evidence_to_dict(row) for row in rows]

    def get_evidence_reference(self, reference_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.query(ForensicEvidenceReferenceORM).filter_by(id=str(reference_id)).one_or_none()
            return _evidence_to_dict(row) if row is not None else None

    def list_observations(self, reference_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(ForensicEvidenceObservationORM)
                .filter_by(reference_id=str(reference_id))
                .order_by(ForensicEvidenceObservationORM.observed_at.asc())
                .all()
            )
            return [_observation_to_dict(row) for row in rows]

    def record_reference_observations(
        self,
        case_id: str,
        observations: Sequence[Mapping[str, Any]],
        *,
        actor_id: str,
        actor_role: str,
        verification_report: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist read-only verification outcomes and append custody events."""
        now = utcnow()
        with self._session_factory() as session:
            case = self.get_case_row(session, case_id)
            for item in observations:
                reference = (
                    session.query(ForensicEvidenceReferenceORM)
                    .filter_by(id=str(item.get("reference_id")), case_id=case.id)
                    .one_or_none()
                )
                if reference is None:
                    continue
                outcome = str(item.get("outcome") or "NOT_RUN").upper()
                observed = normalize_sha256(item.get("observed_sha256"))
                reference.observed_sha256 = observed
                reference.verification_status = outcome
                reference.verification_outcome = outcome
                reference.verification_detail = _safe_text(item.get("detail"), 1024)
                session.add(
                    ForensicEvidenceObservationORM(
                        id=_new_id(),
                        reference_id=reference.id,
                        case_id=case.id,
                        observed_sha256=observed,
                        size_bytes=int(item.get("size_bytes") or 0),
                        outcome=outcome,
                        detail=_safe_text(item.get("detail"), 1024),
                        observed_at=now,
                        meta=dict(redact_structure(dict(item.get("metadata") or {}))),
                    )
                )
                event_type = (
                    CustodyEventType.EVIDENCE_VERIFIED
                    if outcome in {VerificationOutcome.PASS.value, VerificationOutcome.PARTIAL.value}
                    else CustodyEventType.EVIDENCE_VERIFICATION_FAILED
                    if outcome == VerificationOutcome.FAIL.value
                    else CustodyEventType.EVIDENCE_ACCESS_RECORDED
                )
                self._append_custody(
                    session,
                    case,
                    event_type,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    artifact_id=reference.artifact_id,
                    metadata={
                        "reference_id": reference.id,
                        "artifact_type": reference.artifact_type,
                        "outcome": outcome,
                        "expected_sha256": reference.expected_sha256,
                        "observed_sha256": observed,
                    },
                    timestamp=now,
                )
            if verification_report is not None:
                report = dict(redact_structure(dict(verification_report)))
                outcome = str(report.get("outcome") or "NOT_RUN").upper()
                run = ForensicVerificationRunORM(
                    id=_new_id(),
                    case_id=case.id,
                    actor_id=actor_id,
                    outcome=outcome,
                    report=report,
                    created_at=now,
                    meta={},
                )
                session.add(run)
                self._append_custody(
                    session,
                    case,
                    CustodyEventType.VERIFICATION_RECORDED,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    metadata={
                        "verification_id": run.id,
                        "outcome": outcome,
                        "reason_codes": list(report.get("reason_codes") or [])[:20],
                    },
                    timestamp=now,
                )
                if report.get("custody", {}).get("outcome") == VerificationOutcome.FAIL.value:
                    self._append_custody(
                        session,
                        case,
                        CustodyEventType.CHAIN_VERIFICATION_FAILED,
                        actor_id=actor_id,
                        actor_role=actor_role,
                        metadata={
                            "reason_codes": list(report.get("custody", {}).get("reason_codes") or [])[:20]
                        },
                        timestamp=now,
                    )
            session.commit()
        return self.get_case_detail(case_id)

    def record_verification_run(
        self,
        case_id: str,
        *,
        actor_id: str,
        outcome: str,
        report: Mapping[str, Any],
    ) -> dict[str, Any]:
        with self._session_factory() as session:
            case = self.get_case_row(session, case_id)
            row = ForensicVerificationRunORM(
                id=_new_id(),
                case_id=case.id,
                actor_id=actor_id,
                outcome=str(outcome).upper(),
                report=dict(redact_structure(dict(report))),
                created_at=utcnow(),
                meta={},
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _verification_to_dict(row)

    def latest_verification(self, case_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(ForensicVerificationRunORM)
                .filter_by(case_id=str(case_id))
                .order_by(ForensicVerificationRunORM.created_at.desc())
                .first()
            )
            return _verification_to_dict(row) if row is not None else None

    def list_verifications(self, case_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(ForensicVerificationRunORM)
                .filter_by(case_id=str(case_id))
                .order_by(ForensicVerificationRunORM.created_at.desc())
                .all()
            )
            return [_verification_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Assignment and transitions
    # ------------------------------------------------------------------
    def assign_case(
        self,
        case_id: str,
        *,
        assignee: str | None,
        actor_id: str,
        actor_role: str,
        reason: str,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        now = utcnow()
        with self._session_factory() as session:
            case = self.get_case_row(session, case_id)
            if expected_version is not None and int(case.version or 1) != int(expected_version):
                raise CaseVersionConflictError(case_id, int(expected_version), int(case.version or 1))
            previous = case.assigned_to
            assignee_value = _safe_text(assignee, 256) or None
            case.assigned_to = assignee_value
            case.version = int(case.version or 1) + 1
            case.updated_at = now
            session.add(
                ForensicAssignmentORM(
                    id=_new_id(),
                    case_id=case.id,
                    assignee=assignee_value,
                    previous_assignee=previous,
                    actor_id=actor_id,
                    reason=_safe_text(reason, 1024),
                    timestamp=now,
                    meta={},
                )
            )
            event_type = (
                CustodyEventType.INVESTIGATOR_ASSIGNED
                if previous is None and assignee_value is not None
                else CustodyEventType.INVESTIGATOR_REASSIGNED
            )
            self._append_custody(
                session,
                case,
                event_type,
                actor_id=actor_id,
                actor_role=actor_role,
                metadata={
                    "assignee": assignee_value,
                    "previous_assignee": previous,
                    "reason": _safe_text(reason, 512),
                },
                timestamp=now,
            )
            session.commit()
            session.refresh(case)
            return _case_to_dict(case)

    def list_assignments(self, case_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(ForensicAssignmentORM)
                .filter_by(case_id=str(case_id))
                .order_by(ForensicAssignmentORM.timestamp.asc())
                .all()
            )
            return [_assignment_to_dict(row) for row in rows]

    def transition_case(
        self,
        case_id: str,
        *,
        target_status: CaseStatus | str,
        actor_id: str,
        actor_role: str,
        reason: str,
        expected_version: int | None = None,
        resolution_summary: str | None = None,
        reopening: bool = False,
        acknowledge_critical_findings: bool = False,
        acknowledge_evidence_failures: bool = False,
        allow_unverified_evidence: bool = False,
    ) -> dict[str, Any]:
        now = utcnow()
        target = target_status if isinstance(target_status, CaseStatus) else CaseStatus(str(target_status))
        with self._session_factory() as session:
            case = self.get_case_row(session, case_id)
            current = CaseStatus(str(case.status))
            if expected_version is not None and int(case.version or 1) != int(expected_version):
                raise CaseVersionConflictError(case_id, int(expected_version), int(case.version or 1))
            validate_case_transition(current, target, reopening=reopening)
            if not str(reason or "").strip():
                raise ResolutionRequirementsError("a transition reason is required")

            if target in {CaseStatus.RESOLVED, CaseStatus.CLOSED}:
                summary = _safe_text(resolution_summary, 8192) or _safe_text(case.resolution_summary, 8192)
                if not summary:
                    raise ResolutionRequirementsError("a resolution summary is required")
                conclusion = (
                    session.query(ForensicNoteORM)
                    .filter_by(case_id=case.id, note_type=NoteType.CONCLUSION.value)
                    .first()
                )
                if conclusion is None:
                    raise ResolutionRequirementsError(
                        "an investigation conclusion note is required before resolution or closure"
                    )
                references = session.query(ForensicEvidenceReferenceORM).filter_by(case_id=case.id).all()
                if not references:
                    raise ResolutionRequirementsError(
                        "at least one referenced supporting evidence item is required"
                    )
                outcomes = {str(ref.verification_outcome) for ref in references}
                if VerificationOutcome.FAIL.value in outcomes and not acknowledge_evidence_failures:
                    raise ResolutionRequirementsError(
                        "evidence verification failures must be explicitly acknowledged before resolution"
                    )
                if outcomes <= {VerificationOutcome.NOT_RUN.value} and not allow_unverified_evidence:
                    raise ResolutionRequirementsError(
                        "unverified evidence requires explicit acknowledgement before resolution"
                    )
                unresolved = (
                    session.query(ForensicCorrelationORM)
                    .filter(
                        ForensicCorrelationORM.case_id == case.id,
                        ForensicCorrelationORM.severity == CaseSeverity.CRITICAL.value,
                        ForensicCorrelationORM.resolved.is_(False),
                    )
                    .count()
                )
                if unresolved and not acknowledge_critical_findings:
                    raise UnresolvedCriticalFindingError(
                        f"case has {unresolved} unresolved critical finding(s); "
                        "explicit acknowledgement is required"
                    )
                case.resolution_summary = summary
            if reopening:
                case.resolution_summary = case.resolution_summary
                case.closed_at = None
            if target is CaseStatus.CLOSED:
                case.closed_at = now
            elif target is not CaseStatus.RESOLVED:
                case.closed_at = None

            previous_status = case.status
            case.status = target.value
            case.version = int(case.version or 1) + 1
            case.updated_at = now
            event_type = {
                CaseStatus.RESOLVED: CustodyEventType.CASE_RESOLVED,
                CaseStatus.CLOSED: CustodyEventType.CASE_CLOSED,
            }.get(target, CustodyEventType.CASE_STATUS_CHANGED)
            self._append_custody(
                session,
                case,
                event_type,
                actor_id=actor_id,
                actor_role=actor_role,
                metadata={
                    "previous_status": previous_status,
                    "new_status": target.value,
                    "reason": _safe_text(reason, 1024),
                    "reopening": bool(reopening),
                    "critical_findings_acknowledged": bool(acknowledge_critical_findings),
                    "evidence_failures_acknowledged": bool(acknowledge_evidence_failures),
                    "unverified_evidence_allowed": bool(allow_unverified_evidence),
                },
                timestamp=now,
            )
            session.commit()
            session.refresh(case)
            return _case_to_dict(case)

    # ------------------------------------------------------------------
    # Notes and actions
    # ------------------------------------------------------------------
    def _sanitize_note_content(self, content: str) -> str:
        raw = str(content or "")
        # Inspect the original text first: redaction would otherwise hide the
        # credential-shaped block and let it be stored as "[REDACTED]".
        if contains_sensitive_material(raw):
            raise ResolutionRequirementsError(
                "note content contains credential-shaped material; remove it before saving"
            )
        text = redact_text(raw).strip()
        if not text:
            raise ResolutionRequirementsError("note content is required")
        return text[:16384]

    def add_note(
        self,
        case_id: str,
        *,
        author_id: str,
        actor_role: str,
        note_type: NoteType | str,
        content: str,
        visibility: NoteVisibility | str = NoteVisibility.INTERNAL,
        related_evidence_ids: Sequence[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utcnow()
        with self._session_factory() as session:
            case = self.get_case_row(session, case_id)
            note_type_value = note_type.value if isinstance(note_type, NoteType) else str(note_type).upper()
            try:
                NoteType(note_type_value)
            except ValueError:
                raise ResolutionRequirementsError(f"unsupported note type: {note_type_value}") from None
            visibility_value = (
                visibility.value if isinstance(visibility, NoteVisibility) else str(visibility).upper()
            )
            try:
                NoteVisibility(visibility_value)
            except ValueError:
                raise ResolutionRequirementsError(
                    f"unsupported note visibility: {visibility_value}"
                ) from None
            row = ForensicNoteORM(
                id=_new_id(),
                case_id=case.id,
                author_id=_safe_text(author_id, 256) or "SYSTEM",
                note_type=note_type_value,
                content=self._sanitize_note_content(content),
                visibility=visibility_value,
                related_evidence_ids=[_sanitize_artifact_id(v) for v in related_evidence_ids][:64],
                version=1,
                edited_by=None,
                meta=dict(redact_structure(dict(metadata or {}))),
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.flush()
            session.add(
                ForensicNoteRevisionORM(
                    id=_new_id(),
                    note_id=row.id,
                    case_id=case.id,
                    revision=1,
                    content=row.content,
                    editor_id=row.author_id,
                    edited_at=now,
                    meta={},
                )
            )
            self._append_custody(
                session,
                case,
                CustodyEventType.INVESTIGATION_NOTE_ADDED,
                actor_id=row.author_id,
                actor_role=actor_role,
                metadata={
                    "note_id": row.id,
                    "note_type": row.note_type,
                    "visibility": row.visibility,
                    "revision": 1,
                },
                timestamp=now,
            )
            session.commit()
            session.refresh(row)
            return _note_to_dict(row)

    def update_note(
        self,
        case_id: str,
        note_id: str,
        *,
        editor_id: str,
        actor_role: str,
        content: str,
        expected_version: int | None = None,
        related_evidence_ids: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        now = utcnow()
        with self._session_factory() as session:
            case = self.get_case_row(session, case_id)
            row = session.query(ForensicNoteORM).filter_by(id=str(note_id), case_id=case.id).one_or_none()
            if row is None:
                raise ForensicNoteNotFoundError(note_id)
            if expected_version is not None and int(row.version or 1) != int(expected_version):
                raise NoteVersionConflictError(note_id, int(expected_version), int(row.version or 1))
            row.content = self._sanitize_note_content(content)
            row.version = int(row.version or 1) + 1
            row.edited_by = _safe_text(editor_id, 256) or "SYSTEM"
            row.updated_at = now
            if related_evidence_ids is not None:
                row.related_evidence_ids = [_sanitize_artifact_id(v) for v in related_evidence_ids][:64]
            session.add(
                ForensicNoteRevisionORM(
                    id=_new_id(),
                    note_id=row.id,
                    case_id=case.id,
                    revision=row.version,
                    content=row.content,
                    editor_id=row.edited_by,
                    edited_at=now,
                    meta={},
                )
            )
            self._append_custody(
                session,
                case,
                CustodyEventType.INVESTIGATION_NOTE_ADDED,
                actor_id=row.edited_by,
                actor_role=actor_role,
                metadata={
                    "note_id": row.id,
                    "note_type": row.note_type,
                    "revision": row.version,
                    "edited": True,
                },
                timestamp=now,
            )
            session.commit()
            session.refresh(row)
            return _note_to_dict(row)

    def list_notes(self, case_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(ForensicNoteORM)
                .filter_by(case_id=str(case_id))
                .order_by(ForensicNoteORM.created_at.asc())
                .all()
            )
            return [_note_to_dict(row) for row in rows]

    def list_note_revisions(self, note_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(ForensicNoteRevisionORM)
                .filter_by(note_id=str(note_id))
                .order_by(ForensicNoteRevisionORM.revision.asc())
                .all()
            )
            return [_revision_to_dict(row) for row in rows]

    def add_action(
        self,
        case_id: str,
        *,
        actor_id: str,
        actor_role: str,
        action_type: str,
        description: str,
        related_finding_ids: Sequence[str] = (),
        result: str = "RECORDED",
        approval_reference: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utcnow()
        with self._session_factory() as session:
            case = self.get_case_row(session, case_id)
            action_value = str(action_type or "").upper()
            from backend.app.forensics.constants import ActionType

            try:
                ActionType(action_value)
            except ValueError:
                raise ResolutionRequirementsError(
                    f"unsupported operator action type: {action_value}"
                ) from None
            result_value = str(result or "RECORDED").upper()
            from backend.app.forensics.constants import ActionResult

            try:
                ActionResult(result_value)
            except ValueError:
                raise ResolutionRequirementsError(f"unsupported action result: {result_value}") from None
            text = redact_text(str(description or "")).strip()
            if not text:
                raise ResolutionRequirementsError("action description is required")
            if contains_sensitive_material(text):
                raise ResolutionRequirementsError(
                    "action description contains credential-shaped material; remove it before saving"
                )
            row = ForensicActionORM(
                id=_new_id(),
                case_id=case.id,
                actor_id=_safe_text(actor_id, 256) or "SYSTEM",
                action_type=action_value,
                description=text[:8192],
                related_finding_ids=[_sanitize_artifact_id(v) for v in related_finding_ids][:128],
                action_timestamp=now,
                result=result_value,
                approval_reference=_safe_text(approval_reference, 256) or None,
                meta=dict(redact_structure(dict(metadata or {}))),
            )
            session.add(row)
            self._append_custody(
                session,
                case,
                CustodyEventType.OPERATOR_ACTION_RECORDED,
                actor_id=row.actor_id,
                actor_role=actor_role,
                metadata={
                    "action_id": row.id,
                    "action_type": row.action_type,
                    "result": row.result,
                    "related_finding_ids": list(row.related_finding_ids),
                },
                timestamp=now,
            )
            session.commit()
            session.refresh(row)
            return _action_to_dict(row)

    def list_actions(self, case_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(ForensicActionORM)
                .filter_by(case_id=str(case_id))
                .order_by(ForensicActionORM.action_timestamp.asc())
                .all()
            )
            return [_action_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Exports
    # ------------------------------------------------------------------
    def create_export_record(
        self,
        case_id: str,
        *,
        export_id: str,
        filename: str,
        storage_relative_path: str,
        sha256: str,
        size_bytes: int,
        file_count: int,
        schema_version: str,
        policy_version: str,
        created_by: str,
        actor_role: str,
        manifest_digest: str,
        root_digest: str,
        evidence_bytes_included: bool,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utcnow()
        with self._session_factory() as session:
            case = self.get_case_row(session, case_id)
            row = ForensicExportORM(
                id=str(export_id),
                case_id=case.id,
                filename=str(filename)[:256],
                storage_relative_path=str(storage_relative_path)[:2048],
                sha256=str(sha256),
                size_bytes=int(size_bytes),
                file_count=int(file_count),
                schema_version=str(schema_version),
                policy_version=str(policy_version),
                created_by=_safe_text(created_by, 256) or "SYSTEM",
                created_at=now,
                verification_outcome=VerificationOutcome.NOT_RUN.value,
                manifest_digest=str(manifest_digest),
                root_digest=str(root_digest),
                evidence_bytes_included=bool(evidence_bytes_included),
                meta=dict(redact_structure(dict(metadata or {}))),
            )
            session.add(row)
            self._append_custody(
                session,
                case,
                CustodyEventType.EVIDENCE_EXPORT_CREATED,
                actor_id=row.created_by,
                actor_role=actor_role,
                metadata={
                    "export_id": row.id,
                    "filename": row.filename,
                    "sha256": row.sha256,
                    "size_bytes": row.size_bytes,
                    "file_count": row.file_count,
                },
                timestamp=now,
            )
            session.commit()
            session.refresh(row)
            return _export_to_dict(row)

    def get_export(self, export_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.query(ForensicExportORM).filter_by(id=str(export_id)).one_or_none()
            return _export_to_dict(row) if row is not None else None

    def list_exports(self, case_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(ForensicExportORM)
                .filter_by(case_id=str(case_id))
                .order_by(ForensicExportORM.created_at.desc())
                .all()
            )
            return [_export_to_dict(row) for row in rows]

    def record_export_verification(
        self,
        export_id: str,
        *,
        actor_id: str,
        actor_role: str,
        outcome: str,
        detail: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utcnow()
        with self._session_factory() as session:
            row = session.query(ForensicExportORM).filter_by(id=str(export_id)).one_or_none()
            if row is None:
                raise ForensicExportNotFoundError(export_id)
            case = self.get_case_row(session, row.case_id)
            row.verified_at = now
            row.verification_outcome = str(outcome).upper()
            row.verification_detail = _safe_text(detail, 2048)
            self._append_custody(
                session,
                case,
                CustodyEventType.EVIDENCE_EXPORT_VERIFIED,
                actor_id=actor_id,
                actor_role=actor_role,
                artifact_id=row.id,
                metadata={
                    "export_id": row.id,
                    "outcome": row.verification_outcome,
                    "detail": row.verification_detail,
                },
                timestamp=now,
            )
            session.commit()
            session.refresh(row)
            return _export_to_dict(row)

    # ------------------------------------------------------------------
    # Detail and timeline
    # ------------------------------------------------------------------
    def get_case_detail(self, case_id: str) -> dict[str, Any] | None:
        case = self.get_case(case_id)
        if case is None:
            return None
        custody_events = self.list_custody_events(case_id)
        custody_verification = verify_custody_chain(case=case, events=custody_events).to_dict()
        return {
            "case": case,
            "correlations": self.list_correlations(case_id),
            "incident_links": self.list_incident_links(case_id),
            "evidence_references": self.list_evidence_references(case_id),
            "custody": {
                "events": custody_events,
                "verification": custody_verification,
            },
            "notes": self.list_notes(case_id),
            "actions": self.list_actions(case_id),
            "assignments": self.list_assignments(case_id),
            "exports": self.list_exports(case_id),
            "latest_verification": self.latest_verification(case_id),
        }

    def timeline(self, case_id: str) -> list[dict[str, Any]]:
        events = self.list_custody_events(case_id)
        return sorted(events, key=lambda item: (item.get("timestamp") or "", item.get("sequence") or 0))

    # ------------------------------------------------------------------
    # Cross-check helpers
    # ------------------------------------------------------------------
    def case_incident_ids(self, case_id: str) -> list[str]:
        return [link["incident_id"] for link in self.list_incident_links(case_id)]

    def case_finding_ids(self, case_id: str) -> list[str]:
        return [item["finding_id"] for item in self.list_correlations(case_id) if item.get("finding_id")]

    def count_critical_unresolved(self, case_id: str) -> int:
        with self._session_factory() as session:
            return int(
                session.query(ForensicCorrelationORM)
                .filter(
                    ForensicCorrelationORM.case_id == str(case_id),
                    ForensicCorrelationORM.severity == CaseSeverity.CRITICAL.value,
                    ForensicCorrelationORM.resolved.is_(False),
                )
                .count()
            )

    def recent_cases(self, limit: int = 10) -> list[dict[str, Any]]:
        cases, _ = self.list_cases(page=1, page_size=max(1, min(100, int(limit))))
        return cases


__all__ = [
    "ForensicRepository",
    "next_case_number",
    "normalize_sha256",
    "validate_relative_path",
]
