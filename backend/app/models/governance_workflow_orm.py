"""Enterprise governance workflow ORM (V39).

Seven additive tables hold versioned workflow templates, workflow instances,
tasks, immutable task dependencies, read-only cross-domain references,
escalations, and append-only workflow events. No table uses
``ON DELETE CASCADE``: workflow records must never remove evidence, cases,
custody records, governance records, automation records, intelligence records,
executive actions, snapshots, or audit history.

Templates, workflows, tasks, and escalations are mutable only for validated
lifecycle or assignment updates. Task dependencies, references, and events are
append-only and are protected by migration triggers. No table is deletable.
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


class GovernanceWorkflowTemplateORM(Base):
    __tablename__ = "governance_workflow_templates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    template_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(String(4000), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE", index=True)
    definition: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    definition_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    task_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dependency_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[str] = mapped_column(String(256), nullable=False, default="SYSTEM")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)

    __table_args__ = (
        UniqueConstraint("template_key", "version", name="uq_governance_workflow_template_key_version"),
        Index("ix_governance_workflow_template_key_status", "template_key", "status"),
    )


class GovernanceWorkflowORM(Base):
    __tablename__ = "governance_workflows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    template_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("governance_workflow_templates.id"),
        nullable=False,
        index=True,
    )
    template_key: Mapped[str] = mapped_column(String(64), nullable=False)
    template_version: Mapped[int] = mapped_column(Integer, nullable=False)
    template_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    template_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    case_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("forensic_cases.id"),
        nullable=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(String(4000), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="DRAFT", index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    owner_type: Mapped[str | None] = mapped_column(String(8), nullable=True, default=None)
    owner_id: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None, index=True)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="MEDIUM")
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    created_by: Mapped[str] = mapped_column(String(256), nullable=False, default="SYSTEM")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    ready_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    blocked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    review_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    outcome_summary: Mapped[str | None] = mapped_column(String(4000), nullable=True, default=None)
    block_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    cancel_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)

    __table_args__ = (
        Index("ix_governance_workflow_status_due", "status", "due_at"),
        Index("ix_governance_workflow_owner_status", "owner_id", "status"),
        Index("ix_governance_workflow_case_status", "case_id", "status"),
    )


class GovernanceWorkflowTaskORM(Base):
    __tablename__ = "governance_workflow_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workflow_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("governance_workflows.id"),
        nullable=False,
        index=True,
    )
    task_key: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(String(4000), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING", index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    owner_type: Mapped[str | None] = mapped_column(String(8), nullable=True, default=None)
    owner_id: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None, index=True)
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    order_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    blocked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    outcome_summary: Mapped[str | None] = mapped_column(String(4000), nullable=True, default=None)
    block_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    cancel_reason: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)

    __table_args__ = (
        UniqueConstraint("workflow_id", "task_key", name="uq_governance_workflow_task_key"),
        Index("ix_governance_workflow_task_workflow_status", "workflow_id", "status"),
        Index("ix_governance_workflow_task_owner_status", "owner_id", "status"),
        Index("ix_governance_workflow_task_workflow_order", "workflow_id", "order_index"),
    )


class GovernanceWorkflowTaskDependencyORM(Base):
    __tablename__ = "governance_workflow_task_dependencies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workflow_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("governance_workflows.id"),
        nullable=False,
        index=True,
    )
    task_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("governance_workflow_tasks.id"),
        nullable=False,
        index=True,
    )
    depends_on_task_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("governance_workflow_tasks.id"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (
        UniqueConstraint(
            "workflow_id",
            "task_id",
            "depends_on_task_id",
            name="uq_governance_workflow_dependency",
        ),
        Index("ix_governance_workflow_dependency_workflow_task", "workflow_id", "task_id"),
        Index("ix_governance_workflow_dependency_depends_on", "depends_on_task_id"),
    )


class GovernanceWorkflowReferenceORM(Base):
    __tablename__ = "governance_workflow_references"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workflow_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("governance_workflows.id"),
        nullable=False,
        index=True,
    )
    task_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("governance_workflow_tasks.id"),
        nullable=True,
        default=None,
        index=True,
    )
    domain: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(String(128), nullable=False)
    reference_key: Mapped[str] = mapped_column(String(160), nullable=False)
    source_label: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    source_case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, default=None)
    availability: Mapped[str] = mapped_column(String(16), nullable=False, default="AVAILABLE")
    source_status: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    source_version: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    added_by: Mapped[str] = mapped_column(String(256), nullable=False, default="SYSTEM")
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    reason: Mapped[str] = mapped_column(String(2048), nullable=False, default="")

    __table_args__ = (
        UniqueConstraint("workflow_id", "reference_key", name="uq_governance_workflow_reference_key"),
        Index("ix_governance_workflow_reference_workflow_domain", "workflow_id", "domain"),
        Index("ix_governance_workflow_reference_domain_source", "domain", "source_id"),
    )


class GovernanceWorkflowEscalationORM(Base):
    __tablename__ = "governance_workflow_escalations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workflow_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("governance_workflows.id"),
        nullable=False,
        index=True,
    )
    task_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("governance_workflow_tasks.id"),
        nullable=True,
        default=None,
        index=True,
    )
    escalation_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="MEDIUM")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN", index=True)
    reason: Mapped[str] = mapped_column(String(2048), nullable=False)
    resolution: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    requested_by: Mapped[str] = mapped_column(String(256), nullable=False, default="SYSTEM")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    acknowledged_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    resolved_by: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)

    __table_args__ = (
        Index("ix_governance_workflow_escalation_workflow_status", "workflow_id", "status"),
        Index("ix_governance_workflow_escalation_status_severity", "status", "severity"),
    )


class GovernanceWorkflowEventORM(Base):
    __tablename__ = "governance_workflow_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workflow_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("governance_workflows.id"),
        nullable=True,
        default=None,
        index=True,
    )
    task_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("governance_workflow_tasks.id"),
        nullable=True,
        default=None,
        index=True,
    )
    template_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("governance_workflow_templates.id"),
        nullable=True,
        default=None,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    from_status: Mapped[str | None] = mapped_column(String(16), nullable=True, default=None)
    to_status: Mapped[str | None] = mapped_column(String(16), nullable=True, default=None)
    actor_id: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    actor_role: Mapped[str | None] = mapped_column(String(16), nullable=True, default=None)
    reason: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )

    __table_args__ = (
        Index("ix_governance_workflow_event_workflow_time", "workflow_id", "created_at"),
        Index("ix_governance_workflow_event_workflow_sequence", "workflow_id", "sequence"),
        Index("ix_governance_workflow_event_task_time", "task_id", "created_at"),
        Index("ix_governance_workflow_event_template_time", "template_id", "created_at"),
        Index("ix_governance_workflow_event_type_time", "event_type", "created_at"),
    )


__all__ = [
    "GovernanceWorkflowEscalationORM",
    "GovernanceWorkflowEventORM",
    "GovernanceWorkflowORM",
    "GovernanceWorkflowReferenceORM",
    "GovernanceWorkflowTaskDependencyORM",
    "GovernanceWorkflowTaskORM",
    "GovernanceWorkflowTemplateORM",
]
