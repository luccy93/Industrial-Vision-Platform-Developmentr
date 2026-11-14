"""Create governance intelligence tables (V37).

Additive schema only. Existing V01-V36 tables, rows, triggers, and artifacts are
untouched. No foreign key uses ``ON DELETE CASCADE``. Risk models, SLA targets,
and recommendation events are append-only and protected by database triggers;
recommendations remain mutable for lifecycle updates but cannot be deleted.

Revision ID: 014_create_governance_intelligence
Revises: 013_create_governance_automation
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

from backend.app.governance.intelligence.constants import (
    DEFAULT_FACTOR_POINTS,
    DEFAULT_MODEL_ID,
    DEFAULT_MODEL_NAME,
    DEFAULT_MODEL_VERSION,
    DEFAULT_RISK_THRESHOLDS,
    DEFAULT_SLA_EFFECTIVE_FROM,
    DEFAULT_SLA_TARGETS,
    SLA_TARGET_KEYS,
    risk_model_row_id,
    sla_target_row_id,
)

revision = "014_create_governance_intelligence"
down_revision = "013_create_governance_automation"
branch_labels = None
depends_on = None

_APPEND_ONLY_TABLES = (
    "governance_risk_models",
    "governance_sla_targets",
    "governance_recommendation_events",
)

_ALL_TABLES = (
    "governance_risk_models",
    "governance_sla_targets",
    "governance_recommendations",
    "governance_recommendation_events",
)


def _create_triggers() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute(
            sa.text(
                """
                CREATE OR REPLACE FUNCTION governance_intelligence_block_mutation()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'governance intelligence records are protected from mutation or deletion';
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
                    f"FOR EACH ROW EXECUTE FUNCTION governance_intelligence_block_mutation()"
                )
            )
        op.execute(
            sa.text(
                "CREATE TRIGGER trg_governance_recommendations_no_delete "
                "BEFORE DELETE ON governance_recommendations "
                "FOR EACH ROW EXECUTE FUNCTION governance_intelligence_block_mutation()"
            )
        )
        return

    # SQLite (and any dialect that supports SQLite-style triggers).
    for table in _APPEND_ONLY_TABLES:
        op.execute(
            sa.text(
                f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_update "
                f"BEFORE UPDATE ON {table} BEGIN "
                f"SELECT RAISE(ABORT, 'governance intelligence append-only table: {table}'); END"
            )
        )
    for table in _ALL_TABLES:
        op.execute(
            sa.text(
                f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_delete "
                f"BEFORE DELETE ON {table} BEGIN "
                f"SELECT RAISE(ABORT, 'governance intelligence records cannot be deleted: {table}'); END"
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
        op.execute(sa.text("DROP FUNCTION IF EXISTS governance_intelligence_block_mutation()"))


def _seed_defaults() -> None:
    now = datetime.now(UTC)
    op.execute(
        sa.text(
            """
            INSERT INTO governance_risk_models (
                id, model_id, version, name, state, thresholds, factor_points,
                effective_from, actor_id, actor_role, reason, idempotency_key, created_at
            ) VALUES (
                :id, :model_id, :version, :name, :state, :thresholds, :factor_points,
                :effective_from, :actor_id, :actor_role, :reason, NULL, :created_at
            )
            """
        ).bindparams(
            id=risk_model_row_id(DEFAULT_MODEL_ID, DEFAULT_MODEL_VERSION),
            model_id=DEFAULT_MODEL_ID,
            version=DEFAULT_MODEL_VERSION,
            name=DEFAULT_MODEL_NAME,
            state="ENABLED",
            thresholds=json.dumps(DEFAULT_RISK_THRESHOLDS, sort_keys=True),
            factor_points=json.dumps(DEFAULT_FACTOR_POINTS, sort_keys=True),
            effective_from=DEFAULT_SLA_EFFECTIVE_FROM,
            actor_id="SYSTEM",
            actor_role="SYSTEM",
            reason="Seeded platform default risk model.",
            created_at=now,
        )
    )
    for target_key in SLA_TARGET_KEYS:
        defaults = DEFAULT_SLA_TARGETS[target_key]
        op.execute(
            sa.text(
                """
                INSERT INTO governance_sla_targets (
                    id, target_key, version, target_hours, warning_hours,
                    effective_from, actor_id, actor_role, reason, idempotency_key, created_at
                ) VALUES (
                    :id, :target_key, :version, :target_hours, :warning_hours,
                    :effective_from, :actor_id, :actor_role, :reason, NULL, :created_at
                )
                """
            ).bindparams(
                id=sla_target_row_id(target_key, 1),
                target_key=target_key,
                version=1,
                target_hours=int(defaults["target_hours"]),
                warning_hours=int(defaults["warning_hours"]),
                effective_from=DEFAULT_SLA_EFFECTIVE_FROM,
                actor_id="SYSTEM",
                actor_role="SYSTEM",
                reason="Seeded platform default operational SLA target.",
                created_at=now,
            )
        )


def upgrade() -> None:
    op.create_table(
        "governance_risk_models",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("model_id", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="ENABLED"),
        sa.Column("thresholds", sa.JSON(), nullable=False),
        sa.Column("factor_points", sa.JSON(), nullable=False),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(256), nullable=False, server_default="SYSTEM"),
        sa.Column("actor_role", sa.String(16), nullable=False, server_default="SYSTEM"),
        sa.Column("reason", sa.String(2048), nullable=False, server_default=""),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("model_id", "version", name="uq_governance_risk_model_version"),
    )
    op.create_index("ix_governance_risk_models_model_id", "governance_risk_models", ["model_id"])
    op.create_index(
        "ix_governance_risk_model_effective",
        "governance_risk_models",
        ["model_id", "effective_from"],
    )

    op.create_table(
        "governance_sla_targets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("target_key", sa.String(48), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("target_hours", sa.Integer(), nullable=False),
        sa.Column("warning_hours", sa.Integer(), nullable=False),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(256), nullable=False, server_default="SYSTEM"),
        sa.Column("actor_role", sa.String(16), nullable=False, server_default="SYSTEM"),
        sa.Column("reason", sa.String(2048), nullable=False, server_default=""),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("target_key", "version", name="uq_governance_sla_target_version"),
    )
    op.create_index("ix_governance_sla_targets_target_key", "governance_sla_targets", ["target_key"])
    op.create_index(
        "ix_governance_sla_target_effective",
        "governance_sla_targets",
        ["target_key", "effective_from"],
    )

    op.create_table(
        "governance_recommendations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("recommendation_key", sa.String(320), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("scope_type", sa.String(32), nullable=False),
        sa.Column("scope_id", sa.String(64), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("risk_level", sa.String(16), nullable=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("rationale", sa.String(2048), nullable=False, server_default=""),
        sa.Column("source_refs", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_by", sa.String(256), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledgement_reason", sa.String(2048), nullable=True),
        sa.Column("dismissed_by", sa.String(256), nullable=True),
        sa.Column("dismissed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dismissal_reason", sa.String(500), nullable=True),
        sa.Column("resolved_by", sa.String(256), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution_reason", sa.String(2048), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_governance_recommendations_recommendation_key",
        "governance_recommendations",
        ["recommendation_key"],
        unique=True,
    )
    op.create_index("ix_governance_recommendations_rule_id", "governance_recommendations", ["rule_id"])
    op.create_index("ix_governance_recommendations_scope_type", "governance_recommendations", ["scope_type"])
    op.create_index("ix_governance_recommendations_scope_id", "governance_recommendations", ["scope_id"])
    op.create_index("ix_governance_recommendations_case_id", "governance_recommendations", ["case_id"])
    op.create_index("ix_governance_recommendations_severity", "governance_recommendations", ["severity"])
    op.create_index("ix_governance_recommendations_risk_level", "governance_recommendations", ["risk_level"])
    op.create_index("ix_governance_recommendations_status", "governance_recommendations", ["status"])
    op.create_index(
        "ix_governance_recommendation_status_severity",
        "governance_recommendations",
        ["status", "severity", "last_evaluated_at"],
    )
    op.create_index(
        "ix_governance_recommendation_scope",
        "governance_recommendations",
        ["rule_id", "scope_type", "scope_id"],
    )

    op.create_table(
        "governance_recommendation_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "recommendation_id",
            sa.String(36),
            sa.ForeignKey("governance_recommendations.id"),
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
        "ix_governance_recommendation_events_recommendation_id",
        "governance_recommendation_events",
        ["recommendation_id"],
    )
    op.create_index(
        "ix_governance_recommendation_events_event_type",
        "governance_recommendation_events",
        ["event_type"],
    )
    op.create_index(
        "ix_governance_recommendation_events_created_at",
        "governance_recommendation_events",
        ["created_at"],
    )
    op.create_index(
        "ix_governance_recommendation_event_time",
        "governance_recommendation_events",
        ["recommendation_id", "created_at"],
    )

    _seed_defaults()
    _create_triggers()


def downgrade() -> None:
    _drop_triggers()
    for table in reversed(_ALL_TABLES):
        op.drop_table(table)
