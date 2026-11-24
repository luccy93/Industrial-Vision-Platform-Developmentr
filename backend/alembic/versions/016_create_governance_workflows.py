"""Create enterprise governance workflow tables (V39).

Additive schema only. Existing V01-V38 tables, rows, triggers, and artifacts are
untouched. No foreign key uses ``ON DELETE CASCADE`` or ``ON DELETE SET NULL``.
Task dependencies, cross-domain references, and workflow events are append-only
and protected by database triggers. Templates, workflows, tasks, and escalations
remain mutable for validated lifecycle updates but cannot be deleted.

Revision ID: 016_create_governance_workflows
Revises: 015_create_governance_executive
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "016_create_governance_workflows"
down_revision = "015_create_governance_executive"
branch_labels = None
depends_on = None

_APPEND_ONLY_TABLES = (
    "governance_workflow_task_dependencies",
    "governance_workflow_references",
    "governance_workflow_events",
)

_ALL_TABLES = (
    "governance_workflow_templates",
    "governance_workflows",
    "governance_workflow_tasks",
    "governance_workflow_task_dependencies",
    "governance_workflow_references",
    "governance_workflow_escalations",
    "governance_workflow_events",
)


def _create_triggers() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute(
            sa.text(
                """
                CREATE OR REPLACE FUNCTION governance_workflow_block_mutation()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'governance workflow records are protected from mutation or deletion';
                END;
                $$ LANGUAGE plpgsql
                """
            )
        )
        for table in _APPEND_ONLY_TABLES:
            op.execute(
                sa.text(
                    f"CREATE TRIGGER trg_{table}_append_only "
                    f"BEFORE UPDATE OR DELETE ON {table} "
                    f"FOR EACH ROW EXECUTE FUNCTION governance_workflow_block_mutation()"
                )
            )
        for table in _ALL_TABLES:
            op.execute(
                sa.text(
                    f"CREATE TRIGGER trg_{table}_no_delete "
                    f"BEFORE DELETE ON {table} "
                    f"FOR EACH ROW EXECUTE FUNCTION governance_workflow_block_mutation()"
                )
            )
        return

    # SQLite (and any dialect that supports SQLite-style triggers).
    for table in _APPEND_ONLY_TABLES:
        op.execute(
            sa.text(
                f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_update "
                f"BEFORE UPDATE ON {table} BEGIN "
                f"SELECT RAISE(ABORT, 'governance workflow append-only table: {table}'); END"
            )
        )
    for table in _ALL_TABLES:
        op.execute(
            sa.text(
                f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_delete "
                f"BEFORE DELETE ON {table} BEGIN "
                f"SELECT RAISE(ABORT, 'governance workflow records cannot be deleted: {table}'); END"
            )
        )


def _drop_triggers() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    for table in _ALL_TABLES:
        op.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_{table}_no_delete"))
        op.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_{table}_append_only"))
        if dialect != "postgresql":
            op.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_{table}_no_update"))
    if dialect == "postgresql":
        op.execute(sa.text("DROP FUNCTION IF EXISTS governance_workflow_block_mutation()"))


def upgrade() -> None:
    op.create_table(
        "governance_workflow_templates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("template_key", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.String(4000), nullable=False, server_default=""),
        sa.Column("status", sa.String(16), nullable=False, server_default="ACTIVE"),
        sa.Column("definition", sa.JSON(), nullable=False),
        sa.Column("definition_digest", sa.String(64), nullable=False),
        sa.Column("task_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dependency_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(256), nullable=False, server_default="SYSTEM"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
        sa.UniqueConstraint(
            "template_key",
            "version",
            name="uq_governance_workflow_template_key_version",
        ),
    )
    op.create_index(
        "ix_governance_workflow_templates_template_key",
        "governance_workflow_templates",
        ["template_key"],
    )
    op.create_index(
        "ix_governance_workflow_templates_status",
        "governance_workflow_templates",
        ["status"],
    )
    op.create_index(
        "ix_governance_workflow_template_key_status",
        "governance_workflow_templates",
        ["template_key", "status"],
    )

    op.create_table(
        "governance_workflows",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "template_id",
            sa.String(36),
            sa.ForeignKey("governance_workflow_templates.id"),
            nullable=False,
        ),
        sa.Column("template_key", sa.String(64), nullable=False),
        sa.Column("template_version", sa.Integer(), nullable=False),
        sa.Column("template_digest", sa.String(64), nullable=False),
        sa.Column("template_snapshot", sa.JSON(), nullable=False),
        sa.Column(
            "case_id",
            sa.String(36),
            sa.ForeignKey("forensic_cases.id"),
            nullable=True,
        ),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.String(4000), nullable=False, server_default=""),
        sa.Column("status", sa.String(16), nullable=False, server_default="DRAFT"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("owner_type", sa.String(8), nullable=True),
        sa.Column("owner_id", sa.String(256), nullable=True),
        sa.Column("priority", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(256), nullable=False, server_default="SYSTEM"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ready_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("blocked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outcome_summary", sa.String(4000), nullable=True),
        sa.Column("block_reason", sa.String(2048), nullable=True),
        sa.Column("cancel_reason", sa.String(2048), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
    )
    op.create_index(
        "ix_governance_workflows_template_id",
        "governance_workflows",
        ["template_id"],
    )
    op.create_index("ix_governance_workflows_case_id", "governance_workflows", ["case_id"])
    op.create_index("ix_governance_workflows_status", "governance_workflows", ["status"])
    op.create_index("ix_governance_workflows_owner_id", "governance_workflows", ["owner_id"])
    op.create_index(
        "ix_governance_workflow_status_due",
        "governance_workflows",
        ["status", "due_at"],
    )
    op.create_index(
        "ix_governance_workflow_owner_status",
        "governance_workflows",
        ["owner_id", "status"],
    )
    op.create_index(
        "ix_governance_workflow_case_status",
        "governance_workflows",
        ["case_id", "status"],
    )

    op.create_table(
        "governance_workflow_tasks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "workflow_id",
            sa.String(36),
            sa.ForeignKey("governance_workflows.id"),
            nullable=False,
        ),
        sa.Column("task_key", sa.String(64), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.String(4000), nullable=False, server_default=""),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("owner_type", sa.String(8), nullable=True),
        sa.Column("owner_id", sa.String(256), nullable=True),
        sa.Column("required", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("order_index", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("blocked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outcome_summary", sa.String(4000), nullable=True),
        sa.Column("block_reason", sa.String(2048), nullable=True),
        sa.Column("cancel_reason", sa.String(2048), nullable=True),
        sa.UniqueConstraint("workflow_id", "task_key", name="uq_governance_workflow_task_key"),
    )
    op.create_index(
        "ix_governance_workflow_tasks_workflow_id",
        "governance_workflow_tasks",
        ["workflow_id"],
    )
    op.create_index("ix_governance_workflow_tasks_status", "governance_workflow_tasks", ["status"])
    op.create_index("ix_governance_workflow_tasks_owner_id", "governance_workflow_tasks", ["owner_id"])
    op.create_index(
        "ix_governance_workflow_task_workflow_status",
        "governance_workflow_tasks",
        ["workflow_id", "status"],
    )
    op.create_index(
        "ix_governance_workflow_task_owner_status",
        "governance_workflow_tasks",
        ["owner_id", "status"],
    )
    op.create_index(
        "ix_governance_workflow_task_workflow_order",
        "governance_workflow_tasks",
        ["workflow_id", "order_index"],
    )

    op.create_table(
        "governance_workflow_task_dependencies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "workflow_id",
            sa.String(36),
            sa.ForeignKey("governance_workflows.id"),
            nullable=False,
        ),
        sa.Column(
            "task_id",
            sa.String(36),
            sa.ForeignKey("governance_workflow_tasks.id"),
            nullable=False,
        ),
        sa.Column(
            "depends_on_task_id",
            sa.String(36),
            sa.ForeignKey("governance_workflow_tasks.id"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "workflow_id",
            "task_id",
            "depends_on_task_id",
            name="uq_governance_workflow_dependency",
        ),
    )
    op.create_index(
        "ix_governance_workflow_task_dependencies_workflow_id",
        "governance_workflow_task_dependencies",
        ["workflow_id"],
    )
    op.create_index(
        "ix_governance_workflow_task_dependencies_task_id",
        "governance_workflow_task_dependencies",
        ["task_id"],
    )
    op.create_index(
        "ix_governance_workflow_task_dependencies_depends_on_task_id",
        "governance_workflow_task_dependencies",
        ["depends_on_task_id"],
    )
    op.create_index(
        "ix_governance_workflow_dependency_workflow_task",
        "governance_workflow_task_dependencies",
        ["workflow_id", "task_id"],
    )
    op.create_index(
        "ix_governance_workflow_dependency_depends_on",
        "governance_workflow_task_dependencies",
        ["depends_on_task_id"],
    )

    op.create_table(
        "governance_workflow_references",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "workflow_id",
            sa.String(36),
            sa.ForeignKey("governance_workflows.id"),
            nullable=False,
        ),
        sa.Column(
            "task_id",
            sa.String(36),
            sa.ForeignKey("governance_workflow_tasks.id"),
            nullable=True,
        ),
        sa.Column("domain", sa.String(32), nullable=False),
        sa.Column("source_id", sa.String(128), nullable=False),
        sa.Column("reference_key", sa.String(160), nullable=False),
        sa.Column("source_label", sa.String(200), nullable=False, server_default=""),
        sa.Column("source_case_id", sa.String(36), nullable=True),
        sa.Column("availability", sa.String(16), nullable=False, server_default="AVAILABLE"),
        sa.Column("source_status", sa.String(32), nullable=False, server_default=""),
        sa.Column("source_version", sa.Integer(), nullable=True),
        sa.Column("added_by", sa.String(256), nullable=False, server_default="SYSTEM"),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.String(2048), nullable=False, server_default=""),
        sa.UniqueConstraint(
            "workflow_id",
            "reference_key",
            name="uq_governance_workflow_reference_key",
        ),
    )
    op.create_index(
        "ix_governance_workflow_references_workflow_id",
        "governance_workflow_references",
        ["workflow_id"],
    )
    op.create_index(
        "ix_governance_workflow_references_task_id",
        "governance_workflow_references",
        ["task_id"],
    )
    op.create_index("ix_governance_workflow_references_domain", "governance_workflow_references", ["domain"])
    op.create_index(
        "ix_governance_workflow_reference_workflow_domain",
        "governance_workflow_references",
        ["workflow_id", "domain"],
    )
    op.create_index(
        "ix_governance_workflow_reference_domain_source",
        "governance_workflow_references",
        ["domain", "source_id"],
    )

    op.create_table(
        "governance_workflow_escalations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "workflow_id",
            sa.String(36),
            sa.ForeignKey("governance_workflows.id"),
            nullable=False,
        ),
        sa.Column(
            "task_id",
            sa.String(36),
            sa.ForeignKey("governance_workflow_tasks.id"),
            nullable=True,
        ),
        sa.Column("escalation_type", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("reason", sa.String(2048), nullable=False),
        sa.Column("resolution", sa.String(2048), nullable=True),
        sa.Column("requested_by", sa.String(256), nullable=False, server_default="SYSTEM"),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_by", sa.String(256), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(256), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
    )
    op.create_index(
        "ix_governance_workflow_escalations_workflow_id",
        "governance_workflow_escalations",
        ["workflow_id"],
    )
    op.create_index(
        "ix_governance_workflow_escalations_task_id",
        "governance_workflow_escalations",
        ["task_id"],
    )
    op.create_index(
        "ix_governance_workflow_escalations_escalation_type",
        "governance_workflow_escalations",
        ["escalation_type"],
    )
    op.create_index(
        "ix_governance_workflow_escalations_status",
        "governance_workflow_escalations",
        ["status"],
    )
    op.create_index(
        "ix_governance_workflow_escalation_workflow_status",
        "governance_workflow_escalations",
        ["workflow_id", "status"],
    )
    op.create_index(
        "ix_governance_workflow_escalation_status_severity",
        "governance_workflow_escalations",
        ["status", "severity"],
    )

    op.create_table(
        "governance_workflow_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "workflow_id",
            sa.String(36),
            sa.ForeignKey("governance_workflows.id"),
            nullable=True,
        ),
        sa.Column(
            "task_id",
            sa.String(36),
            sa.ForeignKey("governance_workflow_tasks.id"),
            nullable=True,
        ),
        sa.Column(
            "template_id",
            sa.String(36),
            sa.ForeignKey("governance_workflow_templates.id"),
            nullable=True,
        ),
        sa.Column("event_type", sa.String(48), nullable=False),
        sa.Column("from_status", sa.String(16), nullable=True),
        sa.Column("to_status", sa.String(16), nullable=True),
        sa.Column("actor_id", sa.String(256), nullable=True),
        sa.Column("actor_role", sa.String(16), nullable=True),
        sa.Column("reason", sa.String(2048), nullable=False, server_default=""),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_governance_workflow_events_workflow_id",
        "governance_workflow_events",
        ["workflow_id"],
    )
    op.create_index("ix_governance_workflow_events_task_id", "governance_workflow_events", ["task_id"])
    op.create_index(
        "ix_governance_workflow_events_template_id",
        "governance_workflow_events",
        ["template_id"],
    )
    op.create_index("ix_governance_workflow_events_event_type", "governance_workflow_events", ["event_type"])
    op.create_index("ix_governance_workflow_events_created_at", "governance_workflow_events", ["created_at"])
    op.create_index(
        "ix_governance_workflow_event_workflow_time",
        "governance_workflow_events",
        ["workflow_id", "created_at"],
    )
    op.create_index(
        "ix_governance_workflow_event_workflow_sequence",
        "governance_workflow_events",
        ["workflow_id", "sequence"],
    )
    op.create_index(
        "ix_governance_workflow_event_task_time",
        "governance_workflow_events",
        ["task_id", "created_at"],
    )
    op.create_index(
        "ix_governance_workflow_event_template_time",
        "governance_workflow_events",
        ["template_id", "created_at"],
    )
    op.create_index(
        "ix_governance_workflow_event_type_time",
        "governance_workflow_events",
        ["event_type", "created_at"],
    )

    _create_triggers()


def downgrade() -> None:
    _drop_triggers()
    for table in reversed(_ALL_TABLES):
        op.drop_table(table)
