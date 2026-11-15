"""Create executive governance tables (V38).

Additive schema only. Existing V01-V37 tables, rows, triggers, and artifacts are
untouched. No foreign key uses ``ON DELETE CASCADE``. Action events and report
metadata are append-only and protected by database triggers; actions remain
mutable for lifecycle updates but cannot be deleted.

Revision ID: 015_create_governance_executive
Revises: 014_create_governance_intelligence
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "015_create_governance_executive"
down_revision = "014_create_governance_intelligence"
branch_labels = None
depends_on = None

_APPEND_ONLY_TABLES = (
    "governance_executive_action_events",
    "governance_executive_reports",
)

_ALL_TABLES = (
    "governance_executive_actions",
    "governance_executive_action_events",
    "governance_executive_reports",
)


def _create_triggers() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute(
            sa.text(
                """
                CREATE OR REPLACE FUNCTION governance_executive_block_mutation()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'executive governance records are protected from mutation or deletion';
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
                    f"FOR EACH ROW EXECUTE FUNCTION governance_executive_block_mutation()"
                )
            )
        op.execute(
            sa.text(
                "CREATE TRIGGER trg_governance_executive_actions_no_delete "
                "BEFORE DELETE ON governance_executive_actions "
                "FOR EACH ROW EXECUTE FUNCTION governance_executive_block_mutation()"
            )
        )
        return

    # SQLite (and any dialect that supports SQLite-style triggers).
    for table in _APPEND_ONLY_TABLES:
        op.execute(
            sa.text(
                f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_update "
                f"BEFORE UPDATE ON {table} BEGIN "
                f"SELECT RAISE(ABORT, 'executive governance append-only table: {table}'); END"
            )
        )
    for table in _ALL_TABLES:
        op.execute(
            sa.text(
                f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_delete "
                f"BEFORE DELETE ON {table} BEGIN "
                f"SELECT RAISE(ABORT, 'executive governance records cannot be deleted: {table}'); END"
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
        op.execute(sa.text("DROP FUNCTION IF EXISTS governance_executive_block_mutation()"))


def upgrade() -> None:
    op.create_table(
        "governance_executive_actions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "recommendation_id",
            sa.String(36),
            sa.ForeignKey("governance_recommendations.id"),
            nullable=False,
        ),
        sa.Column("recommendation_rule_id", sa.String(64), nullable=False),
        sa.Column("recommendation_severity", sa.String(16), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.String(4000), nullable=False, server_default=""),
        sa.Column("owner_id", sa.String(256), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("priority", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_by", sa.String(256), nullable=False, server_default="SYSTEM"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("blocked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outcome_summary", sa.String(4000), nullable=True),
        sa.Column("block_reason", sa.String(2048), nullable=True),
        sa.Column("cancel_reason", sa.String(2048), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
    )
    op.create_index(
        "ix_governance_executive_actions_recommendation_id",
        "governance_executive_actions",
        ["recommendation_id"],
    )
    op.create_index(
        "ix_governance_executive_actions_case_id",
        "governance_executive_actions",
        ["case_id"],
    )
    op.create_index(
        "ix_governance_executive_actions_status",
        "governance_executive_actions",
        ["status"],
    )
    op.create_index(
        "ix_governance_executive_action_status_due",
        "governance_executive_actions",
        ["status", "due_at"],
    )
    op.create_index(
        "ix_governance_executive_action_owner_status",
        "governance_executive_actions",
        ["owner_id", "status"],
    )
    op.create_index(
        "ix_governance_executive_action_recommendation",
        "governance_executive_actions",
        ["recommendation_id", "status"],
    )

    op.create_table(
        "governance_executive_action_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "action_id",
            sa.String(36),
            sa.ForeignKey("governance_executive_actions.id"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("from_status", sa.String(16), nullable=True),
        sa.Column("to_status", sa.String(16), nullable=True),
        sa.Column("actor_id", sa.String(256), nullable=True),
        sa.Column("actor_role", sa.String(16), nullable=True),
        sa.Column("reason", sa.String(2048), nullable=False, server_default=""),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_governance_executive_action_events_action_id",
        "governance_executive_action_events",
        ["action_id"],
    )
    op.create_index(
        "ix_governance_executive_action_events_event_type",
        "governance_executive_action_events",
        ["event_type"],
    )
    op.create_index(
        "ix_governance_executive_action_events_created_at",
        "governance_executive_action_events",
        ["created_at"],
    )
    op.create_index(
        "ix_governance_executive_action_event_time",
        "governance_executive_action_events",
        ["action_id", "created_at"],
    )

    op.create_table(
        "governance_executive_reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("report_type", sa.String(32), nullable=False),
        sa.Column("report_format", sa.String(8), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="GENERATED"),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("generated_by", sa.String(256), nullable=False, server_default="SYSTEM"),
        sa.Column(
            "snapshot_id",
            sa.String(36),
            sa.ForeignKey("governance_snapshots.id"),
            nullable=False,
        ),
        sa.Column("snapshot_type", sa.String(32), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("source_coverage", sa.JSON(), nullable=False),
        sa.Column("sections_available", sa.JSON(), nullable=False),
        sa.Column("sections_unavailable", sa.JSON(), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("report_digest", sa.String(64), nullable=False),
        sa.Column("row_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("redaction_applied", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("reason", sa.String(2048), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "idempotency_key",
            name="uq_governance_executive_report_idempotency",
        ),
    )
    op.create_index(
        "ix_governance_executive_reports_report_type",
        "governance_executive_reports",
        ["report_type"],
    )
    op.create_index(
        "ix_governance_executive_reports_report_format",
        "governance_executive_reports",
        ["report_format"],
    )
    op.create_index(
        "ix_governance_executive_reports_status",
        "governance_executive_reports",
        ["status"],
    )
    op.create_index(
        "ix_governance_executive_reports_generated_at",
        "governance_executive_reports",
        ["generated_at"],
    )
    op.create_index(
        "ix_governance_executive_reports_snapshot_id",
        "governance_executive_reports",
        ["snapshot_id"],
    )
    op.create_index(
        "ix_governance_executive_report_type_generated",
        "governance_executive_reports",
        ["report_type", "generated_at"],
    )
    op.create_index(
        "ix_governance_executive_report_window",
        "governance_executive_reports",
        ["window_start", "window_end"],
    )

    _create_triggers()


def downgrade() -> None:
    _drop_triggers()
    for table in reversed(_ALL_TABLES):
        op.drop_table(table)
