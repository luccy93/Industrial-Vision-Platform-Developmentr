"""Create forensic governance tables (V35).

Additive schema only. Existing V01-V34 tables and artifacts are untouched.
No foreign key uses ON DELETE CASCADE. Append-only history is protected by
database triggers; mutable workflow rows are protected against deletion.

Revision ID: 012_create_governance
Revises: 011_create_forensics
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

from backend.app.governance.constants import (
    DEFAULT_POLICY_ID,
    DEFAULT_POLICY_NAME,
    DEFAULT_POLICY_REASON,
)
from backend.app.governance.policies import default_policy_row_id

revision = "012_create_governance"
down_revision = "011_create_forensics"
branch_labels = None
depends_on = None

_APPEND_ONLY_TABLES = (
    "governance_policy_versions",
    "governance_retention_evaluations",
    "governance_legal_hold_events",
    "governance_disposition_decisions",
    "governance_access_audit",
)

_ALL_TABLES = (
    "governance_policy_versions",
    "governance_retention_evaluations",
    "governance_legal_holds",
    "governance_legal_hold_events",
    "governance_disposition_requests",
    "governance_disposition_decisions",
    "governance_export_approvals",
    "governance_access_audit",
)


def _create_triggers() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute(
            sa.text(
                """
                CREATE OR REPLACE FUNCTION governance_block_mutation()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'governance records are append-only or protected from deletion';
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
                    f"FOR EACH ROW EXECUTE FUNCTION governance_block_mutation()"
                )
            )
        for table in _ALL_TABLES:
            if table in _APPEND_ONLY_TABLES:
                continue
            op.execute(
                sa.text(
                    f"CREATE TRIGGER trg_{table}_no_delete "
                    f"BEFORE DELETE ON {table} "
                    f"FOR EACH ROW EXECUTE FUNCTION governance_block_mutation()"
                )
            )
        return

    # SQLite (and any dialect that supports SQLite-style triggers).
    for table in _APPEND_ONLY_TABLES:
        op.execute(
            sa.text(
                f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_update "
                f"BEFORE UPDATE ON {table} BEGIN "
                f"SELECT RAISE(ABORT, 'governance append-only table: {table}'); END"
            )
        )
    for table in _ALL_TABLES:
        op.execute(
            sa.text(
                f"CREATE TRIGGER IF NOT EXISTS trg_{table}_no_delete "
                f"BEFORE DELETE ON {table} BEGIN "
                f"SELECT RAISE(ABORT, 'governance records cannot be deleted: {table}'); END"
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
        op.execute(sa.text("DROP FUNCTION IF EXISTS governance_block_mutation()"))


def _seed_default_policy() -> None:
    now = datetime.now(UTC)
    op.execute(
        sa.text(
            """
            INSERT INTO governance_policy_versions (
                id, policy_id, version, name, state, case_type, evidence_category,
                retention_days, review_interval_days, required_approval_level,
                export_allowed, export_requires_approval, allow_evidence_bytes,
                export_expiry_days, export_review_days, legal_hold_eligible,
                disposition_review_required, actor_id, actor_role, reason,
                idempotency_key, created_at
            ) VALUES (
                :id, :policy_id, :version, :name, :state, NULL, NULL,
                NULL, NULL, :approval_level,
                :export_allowed, :export_requires_approval, :allow_evidence_bytes,
                NULL, NULL, :legal_hold_eligible,
                :disposition_review_required, :actor_id, :actor_role, :reason,
                NULL, :created_at
            )
            """
        ).bindparams(
            id=default_policy_row_id(),
            policy_id=DEFAULT_POLICY_ID,
            version=1,
            name=DEFAULT_POLICY_NAME,
            state="ENABLED",
            approval_level="SINGLE_REVIEWER",
            export_allowed=True,
            export_requires_approval=True,
            allow_evidence_bytes=False,
            legal_hold_eligible=True,
            disposition_review_required=True,
            actor_id="SYSTEM",
            actor_role="SYSTEM",
            reason=DEFAULT_POLICY_REASON,
            created_at=now,
        )
    )


def upgrade() -> None:
    op.create_table(
        "governance_policy_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("policy_id", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="DRAFT"),
        sa.Column("case_type", sa.String(32), nullable=True),
        sa.Column("evidence_category", sa.String(32), nullable=True),
        sa.Column("retention_days", sa.Integer(), nullable=True),
        sa.Column("review_interval_days", sa.Integer(), nullable=True),
        sa.Column("required_approval_level", sa.String(24), nullable=False, server_default="SINGLE_REVIEWER"),
        sa.Column("export_allowed", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("export_requires_approval", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("allow_evidence_bytes", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("export_expiry_days", sa.Integer(), nullable=True),
        sa.Column("export_review_days", sa.Integer(), nullable=True),
        sa.Column("legal_hold_eligible", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("disposition_review_required", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("actor_id", sa.String(256), nullable=False, server_default="SYSTEM"),
        sa.Column("actor_role", sa.String(16), nullable=False, server_default="SYSTEM"),
        sa.Column("reason", sa.String(2048), nullable=False, server_default=""),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("policy_id", "version", name="uq_governance_policy_version"),
    )
    op.create_index("ix_governance_policy_versions_policy_id", "governance_policy_versions", ["policy_id"])
    op.create_index("ix_governance_policy_versions_state", "governance_policy_versions", ["state"])
    op.create_index("ix_governance_policy_versions_case_type", "governance_policy_versions", ["case_type"])
    op.create_index(
        "ix_governance_policy_versions_evidence_category",
        "governance_policy_versions",
        ["evidence_category"],
    )
    op.create_index(
        "ix_governance_policy_versions_idempotency_key",
        "governance_policy_versions",
        ["idempotency_key"],
        unique=True,
    )
    op.create_index("ix_governance_policy_versions_created_at", "governance_policy_versions", ["created_at"])
    op.create_index("ix_governance_policy_id_version", "governance_policy_versions", ["policy_id", "version"])

    op.create_table(
        "governance_retention_evaluations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column("evaluation_kind", sa.String(16), nullable=False, server_default="EVALUATION"),
        sa.Column("evaluation_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("policy_id", sa.String(64), nullable=True),
        sa.Column("policy_version", sa.Integer(), nullable=True),
        sa.Column("policy_snapshot", sa.JSON(), nullable=False),
        sa.Column("as_of", sa.Date(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retention_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retention_deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_review_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("governance_state", sa.String(32), nullable=False),
        sa.Column("data_status", sa.String(16), nullable=False, server_default="OK"),
        sa.Column("disposition_eligible", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("integrity_status", sa.String(16), nullable=False, server_default="NOT_RUN"),
        sa.Column("verification_id", sa.String(36), nullable=True),
        sa.Column("legal_hold_ids", sa.JSON(), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("reviewed_by", sa.String(256), nullable=True),
        sa.Column("review_reason", sa.String(2048), nullable=True),
        sa.Column("created_by", sa.String(256), nullable=True),
        sa.Column("request_id", sa.String(128), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_governance_retention_evaluations_case_id", "governance_retention_evaluations", ["case_id"]
    )
    op.create_index(
        "ix_governance_retention_evaluations_as_of", "governance_retention_evaluations", ["as_of"]
    )
    op.create_index(
        "ix_governance_retention_evaluations_evaluated_at",
        "governance_retention_evaluations",
        ["evaluated_at"],
    )
    op.create_index(
        "ix_governance_retention_evaluations_governance_state",
        "governance_retention_evaluations",
        ["governance_state"],
    )
    op.create_index(
        "ix_governance_retention_evaluations_idempotency_key",
        "governance_retention_evaluations",
        ["idempotency_key"],
        unique=True,
    )
    op.create_index(
        "ix_governance_eval_case_time", "governance_retention_evaluations", ["case_id", "evaluated_at"]
    )
    op.create_index(
        "ix_governance_eval_state_review",
        "governance_retention_evaluations",
        ["governance_state", "next_review_at"],
    )
    op.create_index(
        "ix_governance_eval_policy",
        "governance_retention_evaluations",
        ["policy_id", "policy_version"],
    )

    op.create_table(
        "governance_legal_holds",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("hold_number", sa.String(32), nullable=False),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column(
            "evidence_reference_id",
            sa.String(36),
            sa.ForeignKey("forensic_evidence_references.id"),
            nullable=True,
        ),
        sa.Column("status", sa.String(24), nullable=False, server_default="PENDING_APPROVAL"),
        sa.Column("scope", sa.String(2048), nullable=False, server_default=""),
        sa.Column("reason", sa.String(2048), nullable=False),
        sa.Column("requested_by", sa.String(256), nullable=False),
        sa.Column("requested_role", sa.String(16), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_by", sa.String(256), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approval_reason", sa.String(2048), nullable=True),
        sa.Column("rejected_by", sa.String(256), nullable=True),
        sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.String(2048), nullable=True),
        sa.Column("released_by", sa.String(256), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("release_reason", sa.String(2048), nullable=True),
        sa.Column("withdrawn_by", sa.String(256), nullable=True),
        sa.Column("withdrawn_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("withdrawal_reason", sa.String(2048), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_governance_legal_holds_hold_number",
        "governance_legal_holds",
        ["hold_number"],
        unique=True,
    )
    op.create_index("ix_governance_legal_holds_case_id", "governance_legal_holds", ["case_id"])
    op.create_index(
        "ix_governance_legal_holds_evidence_reference_id",
        "governance_legal_holds",
        ["evidence_reference_id"],
    )
    op.create_index("ix_governance_legal_holds_status", "governance_legal_holds", ["status"])
    op.create_index("ix_governance_legal_holds_requested_at", "governance_legal_holds", ["requested_at"])
    op.create_index("ix_governance_legal_holds_created_at", "governance_legal_holds", ["created_at"])
    op.create_index(
        "ix_governance_legal_holds_idempotency_key",
        "governance_legal_holds",
        ["idempotency_key"],
        unique=True,
    )
    op.create_index("ix_governance_holds_case_status", "governance_legal_holds", ["case_id", "status"])
    op.create_index(
        "ix_governance_holds_status_requested", "governance_legal_holds", ["status", "requested_at"]
    )

    op.create_table(
        "governance_legal_hold_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("hold_id", sa.String(36), sa.ForeignKey("governance_legal_holds.id"), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("actor_id", sa.String(256), nullable=False),
        sa.Column("actor_role", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(2048), nullable=False, server_default=""),
        sa.Column("from_status", sa.String(24), nullable=True),
        sa.Column("to_status", sa.String(24), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_governance_legal_hold_events_hold_id", "governance_legal_hold_events", ["hold_id"])
    op.create_index(
        "ix_governance_legal_hold_events_event_type",
        "governance_legal_hold_events",
        ["event_type"],
    )
    op.create_index(
        "ix_governance_legal_hold_events_occurred_at",
        "governance_legal_hold_events",
        ["occurred_at"],
    )
    op.create_index(
        "ix_governance_legal_hold_events_idempotency_key",
        "governance_legal_hold_events",
        ["idempotency_key"],
        unique=True,
    )
    op.create_index(
        "ix_governance_hold_events_hold_time",
        "governance_legal_hold_events",
        ["hold_id", "created_at"],
    )

    op.create_table(
        "governance_disposition_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("request_number", sa.String(32), nullable=False),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column(
            "evaluation_id",
            sa.String(36),
            sa.ForeignKey("governance_retention_evaluations.id"),
            nullable=True,
        ),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("justification", sa.String(4096), nullable=False),
        sa.Column("requested_by", sa.String(256), nullable=False),
        sa.Column("requested_role", sa.String(16), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_id", sa.String(64), nullable=True),
        sa.Column("policy_version", sa.Integer(), nullable=True),
        sa.Column("required_approval_level", sa.String(24), nullable=False, server_default="SINGLE_REVIEWER"),
        sa.Column("approval_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reviewer_id", sa.String(256), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.String(2048), nullable=True),
        sa.Column("blocked_reason_codes", sa.JSON(), nullable=False),
        sa.Column("open_key", sa.String(64), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_governance_disposition_requests_request_number",
        "governance_disposition_requests",
        ["request_number"],
        unique=True,
    )
    op.create_index(
        "ix_governance_disposition_requests_case_id",
        "governance_disposition_requests",
        ["case_id"],
    )
    op.create_index(
        "ix_governance_disposition_requests_status",
        "governance_disposition_requests",
        ["status"],
    )
    op.create_index(
        "ix_governance_disposition_requests_requested_at",
        "governance_disposition_requests",
        ["requested_at"],
    )
    op.create_index(
        "ix_governance_disposition_requests_idempotency_key",
        "governance_disposition_requests",
        ["idempotency_key"],
        unique=True,
    )
    op.create_index(
        "ix_governance_disposition_requests_open_key",
        "governance_disposition_requests",
        ["open_key"],
        unique=True,
    )
    op.create_index(
        "ix_governance_disposition_case_status",
        "governance_disposition_requests",
        ["case_id", "status"],
    )
    op.create_index(
        "ix_governance_disposition_status_requested",
        "governance_disposition_requests",
        ["status", "requested_at"],
    )

    op.create_table(
        "governance_disposition_decisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "disposition_id",
            sa.String(36),
            sa.ForeignKey("governance_disposition_requests.id"),
            nullable=False,
        ),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("actor_id", sa.String(256), nullable=False),
        sa.Column("actor_role", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(2048), nullable=False, server_default=""),
        sa.Column("from_status", sa.String(24), nullable=False),
        sa.Column("to_status", sa.String(24), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "disposition_id", "actor_id", "decision", name="uq_governance_disposition_actor_decision"
        ),
    )
    op.create_index(
        "ix_governance_disposition_decisions_disposition_id",
        "governance_disposition_decisions",
        ["disposition_id"],
    )
    op.create_index(
        "ix_governance_disposition_decisions_decision",
        "governance_disposition_decisions",
        ["decision"],
    )
    op.create_index(
        "ix_governance_disposition_decisions_occurred_at",
        "governance_disposition_decisions",
        ["occurred_at"],
    )
    op.create_index(
        "ix_governance_disposition_decisions_idempotency_key",
        "governance_disposition_decisions",
        ["idempotency_key"],
        unique=True,
    )
    op.create_index(
        "ix_governance_disposition_decisions_time",
        "governance_disposition_decisions",
        ["disposition_id", "created_at"],
    )

    op.create_table(
        "governance_export_approvals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("request_number", sa.String(32), nullable=False),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("reason", sa.String(2048), nullable=False),
        sa.Column("requested_by", sa.String(256), nullable=False),
        sa.Column("requested_role", sa.String(16), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_id", sa.String(64), nullable=True),
        sa.Column("policy_version", sa.Integer(), nullable=True),
        sa.Column("include_evidence_bytes", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("required_approval_level", sa.String(24), nullable=False, server_default="SINGLE_REVIEWER"),
        sa.Column("approved_by", sa.String(256), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approval_reason", sa.String(2048), nullable=True),
        sa.Column("rejected_by", sa.String(256), nullable=True),
        sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.String(2048), nullable=True),
        sa.Column("withdrawn_by", sa.String(256), nullable=True),
        sa.Column("withdrawn_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("withdrawal_reason", sa.String(2048), nullable=True),
        sa.Column("export_id", sa.String(36), sa.ForeignKey("forensic_exports.id"), nullable=True),
        sa.Column("export_sha256", sa.String(64), nullable=True),
        sa.Column("manifest_digest", sa.String(64), nullable=True),
        sa.Column("root_digest", sa.String(64), nullable=True),
        sa.Column("filename", sa.String(256), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("file_count", sa.Integer(), nullable=True),
        sa.Column("generated_by", sa.String(256), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("generation_error", sa.String(1024), nullable=True),
        sa.Column("verified_by", sa.String(256), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_outcome", sa.String(16), nullable=False, server_default="NOT_RUN"),
        sa.Column("verification_detail", sa.String(2048), nullable=False, server_default=""),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_governance_export_approvals_request_number",
        "governance_export_approvals",
        ["request_number"],
        unique=True,
    )
    op.create_index("ix_governance_export_approvals_case_id", "governance_export_approvals", ["case_id"])
    op.create_index("ix_governance_export_approvals_status", "governance_export_approvals", ["status"])
    op.create_index(
        "ix_governance_export_approvals_requested_at",
        "governance_export_approvals",
        ["requested_at"],
    )
    op.create_index(
        "ix_governance_export_approvals_idempotency_key",
        "governance_export_approvals",
        ["idempotency_key"],
        unique=True,
    )
    op.create_index(
        "ix_governance_export_approvals_export_id",
        "governance_export_approvals",
        ["export_id"],
        unique=True,
    )
    op.create_index(
        "ix_governance_export_approvals_expires_at",
        "governance_export_approvals",
        ["expires_at"],
    )
    op.create_index(
        "ix_governance_export_case_status",
        "governance_export_approvals",
        ["case_id", "status"],
    )
    op.create_index(
        "ix_governance_export_status_requested",
        "governance_export_approvals",
        ["status", "requested_at"],
    )

    op.create_table(
        "governance_access_audit",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("event_type", sa.String(48), nullable=False),
        sa.Column("actor_id", sa.String(256), nullable=False),
        sa.Column("actor_role", sa.String(16), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.String(128), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=True),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(2048), nullable=False, server_default=""),
        sa.Column("request_id", sa.String(128), nullable=True),
        sa.Column("occurred_at", sa.String(40), nullable=False),
        sa.Column("event_key", sa.String(128), nullable=True),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_governance_access_audit_event_type", "governance_access_audit", ["event_type"])
    op.create_index("ix_governance_access_audit_actor_id", "governance_access_audit", ["actor_id"])
    op.create_index("ix_governance_access_audit_target_type", "governance_access_audit", ["target_type"])
    op.create_index("ix_governance_access_audit_target_id", "governance_access_audit", ["target_id"])
    op.create_index("ix_governance_access_audit_case_id", "governance_access_audit", ["case_id"])
    op.create_index("ix_governance_access_audit_outcome", "governance_access_audit", ["outcome"])
    op.create_index("ix_governance_access_audit_request_id", "governance_access_audit", ["request_id"])
    op.create_index("ix_governance_access_audit_occurred_at", "governance_access_audit", ["occurred_at"])
    op.create_index("ix_governance_access_audit_event_hash", "governance_access_audit", ["event_hash"])
    op.create_index(
        "ix_governance_access_audit_event_key",
        "governance_access_audit",
        ["event_key"],
        unique=True,
    )
    op.create_index("ix_governance_access_audit_created_at", "governance_access_audit", ["created_at"])
    op.create_index("ix_governance_audit_target", "governance_access_audit", ["target_type", "target_id"])
    op.create_index("ix_governance_audit_occurred", "governance_access_audit", ["occurred_at"])

    _seed_default_policy()
    _create_triggers()


def downgrade() -> None:
    _drop_triggers()
    for table in reversed(_ALL_TABLES):
        op.drop_table(table)
