"""Create governance automation tables (V36).

Additive schema only. Existing V01-V35 tables and artifacts are untouched.
No foreign key uses ON DELETE CASCADE. Job events and compliance snapshots are
append-only and protected by database triggers; schedules and jobs are protected
against deletion while remaining mutable for lifecycle updates. All seven job
schedules are seeded disabled: V36 automation is opt-in.

Revision ID: 013_create_governance_automation
Revises: 012_create_governance
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

from backend.app.governance.automation.constants import (
    DEFAULT_SCHEDULE_CONFIGS,
    DEFAULT_SCHEDULE_INTERVALS,
    JobType,
    schedule_row_id,
)

revision = "013_create_governance_automation"
down_revision = "012_create_governance"
branch_labels = None
depends_on = None

_APPEND_ONLY_TABLES = (
    "governance_job_events",
    "governance_snapshots",
)

_ALL_TABLES = (
    "governance_job_schedules",
    "governance_jobs",
    "governance_job_events",
    "governance_snapshots",
)


def _create_triggers() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute(
            sa.text(
                """
                CREATE OR REPLACE FUNCTION governance_automation_block_mutation()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'governance automation records are protected from mutation or deletion';
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
                    f"FOR EACH ROW EXECUTE FUNCTION governance_automation_block_mutation()"
                )
            )
        for table in _ALL_TABLES:
            if table in _APPEND_ONLY_TABLES:
                continue
            op.execute(
                sa.text(
                    f"CREATE TRIGGER trg_{table}_no_delete "
                    f"BEFORE DELETE ON {table} "
                    f"FOR EACH ROW EXECUTE FUNCTION governance_automation_block_mutation()"
                )
            )
        return

    # SQLite (and any dialect that supports SQLite-style triggers).
    for table in _APPEND_ONLY_TABLES:
        op.execute(
            sa.text(
                f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_update "
                f"BEFORE UPDATE ON {table} BEGIN "
                f"SELECT RAISE(ABORT, 'governance automation append-only table: {table}'); END"
            )
        )
    for table in _ALL_TABLES:
        op.execute(
            sa.text(
                f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_delete "
                f"BEFORE DELETE ON {table} BEGIN "
                f"SELECT RAISE(ABORT, 'governance automation records cannot be deleted: {table}'); END"
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
        op.execute(sa.text("DROP FUNCTION IF EXISTS governance_automation_block_mutation()"))


def _seed_schedules() -> None:
    now = datetime.now(UTC)
    for job_type in JobType:
        op.execute(
            sa.text(
                """
                INSERT INTO governance_job_schedules (
                    id, job_type, enabled, interval_minutes, config, config_version,
                    last_slot, last_idempotency_key, updated_by, created_at, updated_at
                ) VALUES (
                    :id, :job_type, :enabled, :interval_minutes, :config, :config_version,
                    NULL, NULL, :updated_by, :created_at, :updated_at
                )
                """
            ).bindparams(
                id=schedule_row_id(job_type.value),
                job_type=job_type.value,
                enabled=False,
                interval_minutes=DEFAULT_SCHEDULE_INTERVALS[job_type.value],
                config=json.dumps(DEFAULT_SCHEDULE_CONFIGS[job_type.value], sort_keys=True),
                config_version=1,
                updated_by="SYSTEM",
                created_at=now,
                updated_at=now,
            )
        )


def upgrade() -> None:
    op.create_table(
        "governance_job_schedules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("job_type", sa.String(48), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("interval_minutes", sa.Integer(), nullable=False, server_default="1440"),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("config_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("last_slot", sa.String(128), nullable=True),
        sa.Column("last_idempotency_key", sa.String(200), nullable=True),
        sa.Column("updated_by", sa.String(256), nullable=False, server_default="SYSTEM"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_governance_job_schedules_job_type",
        "governance_job_schedules",
        ["job_type"],
        unique=True,
    )
    op.create_index(
        "ix_governance_job_schedules_enabled",
        "governance_job_schedules",
        ["enabled"],
    )
    op.create_index(
        "ix_governance_schedule_enabled_type",
        "governance_job_schedules",
        ["enabled", "job_type"],
    )

    op.create_table(
        "governance_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("job_type", sa.String(48), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("trigger", sa.String(16), nullable=False, server_default="MANUAL"),
        sa.Column("schedule_slot", sa.String(128), nullable=True),
        sa.Column("dedup_key", sa.String(200), nullable=False),
        sa.Column(
            "retry_of_job_id",
            sa.String(36),
            sa.ForeignKey("governance_jobs.id"),
            nullable=True,
        ),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("config_version", sa.Integer(), nullable=True),
        sa.Column("config_snapshot", sa.JSON(), nullable=False),
        sa.Column("requested_by", sa.String(256), nullable=False, server_default="SYSTEM"),
        sa.Column("requested_role", sa.String(16), nullable=False, server_default="SYSTEM"),
        sa.Column("request_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_owner", sa.String(128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_requested_by", sa.String(256), nullable=True),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.String(512), nullable=True),
        sa.UniqueConstraint("job_type", "schedule_slot", name="uq_governance_job_slot"),
        sa.UniqueConstraint("retry_of_job_id", "attempt", name="uq_governance_job_retry_attempt"),
    )
    op.create_index("ix_governance_jobs_job_type", "governance_jobs", ["job_type"])
    op.create_index("ix_governance_jobs_status", "governance_jobs", ["status"])
    op.create_index("ix_governance_jobs_dedup_key", "governance_jobs", ["dedup_key"], unique=True)
    op.create_index("ix_governance_jobs_retry_of_job_id", "governance_jobs", ["retry_of_job_id"])
    op.create_index("ix_governance_job_status_available", "governance_jobs", ["status", "available_at"])
    op.create_index("ix_governance_job_type_created", "governance_jobs", ["job_type", "created_at"])
    op.create_index("ix_governance_job_lease_expires", "governance_jobs", ["lease_expires_at"])
    op.create_index("ix_governance_job_cancel_requested", "governance_jobs", ["cancel_requested_at"])

    op.create_table(
        "governance_job_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "job_id",
            sa.String(36),
            sa.ForeignKey("governance_jobs.id"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("from_status", sa.String(16), nullable=True),
        sa.Column("to_status", sa.String(16), nullable=True),
        sa.Column("actor_id", sa.String(256), nullable=True),
        sa.Column("actor_role", sa.String(16), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_governance_job_events_job_id", "governance_job_events", ["job_id"])
    op.create_index("ix_governance_job_events_event_type", "governance_job_events", ["event_type"])
    op.create_index("ix_governance_job_events_created_at", "governance_job_events", ["created_at"])
    op.create_index("ix_governance_job_event_job_time", "governance_job_events", ["job_id", "created_at"])

    op.create_table(
        "governance_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("snapshot_type", sa.String(32), nullable=False),
        sa.Column("as_of", sa.DateTime(timezone=True), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("generated_by", sa.String(256), nullable=False, server_default="SYSTEM"),
        sa.Column(
            "job_id",
            sa.String(36),
            sa.ForeignKey("governance_jobs.id"),
            nullable=True,
        ),
        sa.Column("trigger", sa.String(16), nullable=False, server_default="MANUAL"),
        sa.Column("dedup_key", sa.String(200), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("row_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_governance_snapshots_snapshot_type", "governance_snapshots", ["snapshot_type"])
    op.create_index("ix_governance_snapshots_as_of", "governance_snapshots", ["as_of"])
    op.create_index("ix_governance_snapshots_job_id", "governance_snapshots", ["job_id"])
    op.create_index("ix_governance_snapshots_dedup_key", "governance_snapshots", ["dedup_key"], unique=True)
    op.create_index(
        "ix_governance_snapshot_type_generated",
        "governance_snapshots",
        ["snapshot_type", "generated_at"],
    )

    _seed_schedules()
    _create_triggers()


def downgrade() -> None:
    _drop_triggers()
    for table in reversed(_ALL_TABLES):
        op.drop_table(table)
