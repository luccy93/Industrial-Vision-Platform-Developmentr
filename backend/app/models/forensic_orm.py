"""Forensic investigation ORM (V34).

Durable case-management records live in the application PostgreSQL database,
not in the isolated V33 monitoring store. Every row references original V29-V33
artifacts by identifier/hash; no evidence bytes, private keys, or credentials
are stored here.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.domain.common import utcnow
from backend.app.models.camera_orm import Base


class ForensicCaseORM(Base):
    __tablename__ = "forensic_cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_number: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(String(8192), nullable=False, default="")
    case_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN", index=True)
    priority: Mapped[str] = mapped_column(String(8), nullable=False, default="P4", index=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="MANUAL")
    originating_incident_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, default=None, index=True
    )
    originating_audit_run_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True, default=None, index=True
    )
    created_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    assigned_to: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    resolution_summary: Mapped[str | None] = mapped_column(String(8192), nullable=True, default=None)
    correlation_key: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None, index=True)
    idempotency_key: Mapped[str | None] = mapped_column(
        String(128), nullable=True, default=None, unique=True, index=True
    )
    custody_event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    custody_head_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)

    __table_args__ = (
        Index("ix_forensic_cases_status_updated", "status", "updated_at"),
        Index("ix_forensic_cases_severity_status", "severity", "status"),
        Index("ix_forensic_cases_assigned_status", "assigned_to", "status"),
    )


class ForensicCaseCounterORM(Base):
    __tablename__ = "forensic_case_counters"

    year: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ForensicCorrelationORM(Base):
    __tablename__ = "forensic_correlations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    correlation_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None, unique=True)
    audit_run_id: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None, index=True)
    artifact_id: Mapped[str | None] = mapped_column(String(512), nullable=True, default=None, index=True)
    evidence_identifier: Mapped[str | None] = mapped_column(String(512), nullable=True, default=None)
    checkpoint_id: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None)
    transparency_log_id: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None)
    manifest_id: Mapped[str | None] = mapped_column(String(128), nullable=True, default=None)
    reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None)
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="SUSPICIOUS")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="MEDIUM")
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (UniqueConstraint("case_id", "finding_id", name="uq_forensic_correlation_case_finding"),)


class ForensicIncidentLinkORM(Base):
    __tablename__ = "forensic_incident_links"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    linked_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (UniqueConstraint("case_id", "incident_id", name="uq_forensic_incident_link"),)


class ForensicEvidenceReferenceORM(Base):
    __tablename__ = "forensic_evidence_references"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    artifact_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    artifact_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    original_relative_path: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    expected_sha256: Mapped[str] = mapped_column(String(71), nullable=False, default="")
    observed_sha256: Mapped[str] = mapped_column(String(71), nullable=False, default="")
    source_audit_run_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True, default=None, index=True
    )
    source_finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True, default=None, index=True)
    capture_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    verification_status: Mapped[str] = mapped_column(String(16), nullable=False, default="NOT_RUN")
    verification_outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="NOT_RUN")
    verification_detail: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    reference_created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint(
            "case_id",
            "artifact_type",
            "artifact_id",
            "expected_sha256",
            name="uq_forensic_evidence_reference",
        ),
        Index("ix_forensic_evidence_case_type", "case_id", "artifact_type"),
    )


class ForensicEvidenceObservationORM(Base):
    __tablename__ = "forensic_evidence_observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    reference_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_evidence_references.id"), nullable=False, index=True
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    observed_sha256: Mapped[str] = mapped_column(String(71), nullable=False, default="")
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="NOT_RUN")
    detail: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (Index("ix_forensic_observation_ref_time", "reference_id", "observed_at"),)


class ForensicCustodyEventORM(Base):
    __tablename__ = "forensic_custody_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    actor_role: Mapped[str] = mapped_column(String(16), nullable=False, default="SYSTEM")
    artifact_id: Mapped[str | None] = mapped_column(String(512), nullable=True, default=None)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint("case_id", "sequence", name="uq_forensic_custody_sequence"),
        Index("ix_forensic_custody_case_sequence", "case_id", "sequence"),
    )


class ForensicNoteORM(Base):
    __tablename__ = "forensic_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    author_id: Mapped[str] = mapped_column(String(256), nullable=False)
    note_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    content: Mapped[str] = mapped_column(String(16384), nullable=False)
    visibility: Mapped[str] = mapped_column(String(16), nullable=False, default="INTERNAL")
    related_evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    edited_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (Index("ix_forensic_notes_case_created", "case_id", "created_at"),)


class ForensicNoteRevisionORM(Base):
    __tablename__ = "forensic_note_revisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    note_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_notes.id"), nullable=False, index=True
    )
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(String(16384), nullable=False)
    editor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    edited_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (UniqueConstraint("note_id", "revision", name="uq_forensic_note_revision"),)


class ForensicActionORM(Base):
    __tablename__ = "forensic_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    description: Mapped[str] = mapped_column(String(8192), nullable=False)
    related_finding_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    action_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    result: Mapped[str] = mapped_column(String(32), nullable=False, default="RECORDED")
    approval_reference: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (Index("ix_forensic_actions_case_time", "case_id", "action_timestamp"),)


class ForensicAssignmentORM(Base):
    __tablename__ = "forensic_assignments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    assignee: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    previous_assignee: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    reason: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (Index("ix_forensic_assignments_case_time", "case_id", "timestamp"),)


class ForensicExportORM(Base):
    __tablename__ = "forensic_exports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    filename: Mapped[str] = mapped_column(String(256), nullable=False)
    storage_relative_path: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    file_count: Mapped[int] = mapped_column(Integer, nullable=False)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(16), nullable=False)
    created_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    verification_outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="NOT_RUN")
    verification_detail: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    manifest_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    root_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_bytes_included: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (Index("ix_forensic_exports_case_created", "case_id", "created_at"),)


class ForensicVerificationRunORM(Base):
    __tablename__ = "forensic_verification_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_cases.id"), nullable=False, index=True
    )
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    report: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (Index("ix_forensic_verifications_case_created", "case_id", "created_at"),)


class ForensicNotificationStateORM(Base):
    __tablename__ = "forensic_notification_state"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    dedup_key: Mapped[str] = mapped_column(String(256), nullable=False, unique=True, index=True)
    cooldown_key: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    last_sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )
    notification_id: Mapped[str | None] = mapped_column(String(36), nullable=True, default=None)
    meta: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_forensic_notification_rule_cooldown", "rule_id", "cooldown_key", "last_sent_at"),
    )
