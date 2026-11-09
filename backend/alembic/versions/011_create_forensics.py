"""Create forensic investigation tables (V34).

Additive schema only. Existing V10-V33 tables and artifacts are untouched.

Revision ID: 011_create_forensics
Revises: 010_add_notification_mute
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "011_create_forensics"
down_revision = "010_add_notification_mute"
branch_labels = None
depends_on = None


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "forensic_cases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_number", sa.String(32), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("description", sa.String(8192), nullable=False, server_default=""),
        sa.Column("case_type", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="OPEN"),
        sa.Column("priority", sa.String(8), nullable=False, server_default="P4"),
        sa.Column("source", sa.String(32), nullable=False, server_default="MANUAL"),
        sa.Column("originating_incident_id", sa.String(36), nullable=True),
        sa.Column("originating_audit_run_id", sa.String(128), nullable=True),
        sa.Column("created_by", sa.String(256), nullable=True),
        sa.Column("assigned_to", sa.String(256), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("resolution_summary", sa.String(8192), nullable=True),
        sa.Column("correlation_key", sa.String(64), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("custody_event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("custody_head_hash", sa.String(64), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_forensic_cases_case_number", "forensic_cases", ["case_number"], unique=True)
    op.create_index("ix_forensic_cases_case_type", "forensic_cases", ["case_type"])
    op.create_index("ix_forensic_cases_severity", "forensic_cases", ["severity"])
    op.create_index("ix_forensic_cases_status", "forensic_cases", ["status"])
    op.create_index("ix_forensic_cases_priority", "forensic_cases", ["priority"])
    op.create_index(
        "ix_forensic_cases_originating_incident_id", "forensic_cases", ["originating_incident_id"]
    )
    op.create_index(
        "ix_forensic_cases_originating_audit_run_id", "forensic_cases", ["originating_audit_run_id"]
    )
    op.create_index("ix_forensic_cases_assigned_to", "forensic_cases", ["assigned_to"])
    op.create_index("ix_forensic_cases_correlation_key", "forensic_cases", ["correlation_key"])
    op.create_index("ix_forensic_cases_idempotency_key", "forensic_cases", ["idempotency_key"], unique=True)
    op.create_index("ix_forensic_cases_created_at", "forensic_cases", ["created_at"])
    op.create_index("ix_forensic_cases_updated_at", "forensic_cases", ["updated_at"])
    op.create_index("ix_forensic_cases_status_updated", "forensic_cases", ["status", "updated_at"])
    op.create_index("ix_forensic_cases_severity_status", "forensic_cases", ["severity", "status"])
    op.create_index("ix_forensic_cases_assigned_status", "forensic_cases", ["assigned_to", "status"])

    op.create_table(
        "forensic_case_counters",
        sa.Column("year", sa.Integer(), primary_key=True),
        sa.Column("last_number", sa.Integer(), nullable=False, server_default="0"),
    )

    op.create_table(
        "forensic_correlations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column("correlation_key", sa.String(64), nullable=False),
        sa.Column("finding_id", sa.String(64), nullable=True),
        sa.Column("audit_run_id", sa.String(128), nullable=True),
        sa.Column("artifact_id", sa.String(512), nullable=True),
        sa.Column("evidence_identifier", sa.String(512), nullable=True),
        sa.Column("checkpoint_id", sa.String(128), nullable=True),
        sa.Column("transparency_log_id", sa.String(128), nullable=True),
        sa.Column("manifest_id", sa.String(128), nullable=True),
        sa.Column("reason_code", sa.String(64), nullable=True),
        sa.Column("classification", sa.String(32), nullable=False, server_default="SUSPICIOUS"),
        sa.Column("severity", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("resolved", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("case_id", "finding_id", name="uq_forensic_correlation_case_finding"),
    )
    op.create_index("ix_forensic_correlations_case_id", "forensic_correlations", ["case_id"])
    op.create_index("ix_forensic_correlations_correlation_key", "forensic_correlations", ["correlation_key"])
    op.create_index(
        "ix_forensic_correlations_finding_id", "forensic_correlations", ["finding_id"], unique=True
    )
    op.create_index("ix_forensic_correlations_audit_run_id", "forensic_correlations", ["audit_run_id"])
    op.create_index("ix_forensic_correlations_artifact_id", "forensic_correlations", ["artifact_id"])

    op.create_table(
        "forensic_incident_links",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column("incident_id", sa.String(36), nullable=False),
        sa.Column("linked_by", sa.String(256), nullable=True),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.UniqueConstraint("case_id", "incident_id", name="uq_forensic_incident_link"),
    )
    op.create_index("ix_forensic_incident_links_case_id", "forensic_incident_links", ["case_id"])
    op.create_index("ix_forensic_incident_links_incident_id", "forensic_incident_links", ["incident_id"])

    op.create_table(
        "forensic_evidence_references",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column("artifact_type", sa.String(32), nullable=False),
        sa.Column("artifact_id", sa.String(512), nullable=False),
        sa.Column("original_relative_path", sa.String(2048), nullable=False, server_default=""),
        sa.Column("expected_sha256", sa.String(71), nullable=False, server_default=""),
        sa.Column("observed_sha256", sa.String(71), nullable=False, server_default=""),
        sa.Column("source_audit_run_id", sa.String(128), nullable=True),
        sa.Column("source_finding_id", sa.String(64), nullable=True),
        sa.Column("capture_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_status", sa.String(16), nullable=False, server_default="NOT_RUN"),
        sa.Column("verification_outcome", sa.String(16), nullable=False, server_default="NOT_RUN"),
        sa.Column("verification_detail", sa.String(1024), nullable=False, server_default=""),
        sa.Column("reference_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.UniqueConstraint(
            "case_id",
            "artifact_type",
            "artifact_id",
            "expected_sha256",
            name="uq_forensic_evidence_reference",
        ),
    )
    op.create_index("ix_forensic_evidence_references_case_id", "forensic_evidence_references", ["case_id"])
    op.create_index(
        "ix_forensic_evidence_references_artifact_type", "forensic_evidence_references", ["artifact_type"]
    )
    op.create_index(
        "ix_forensic_evidence_references_artifact_id", "forensic_evidence_references", ["artifact_id"]
    )
    op.create_index(
        "ix_forensic_evidence_references_source_audit_run_id",
        "forensic_evidence_references",
        ["source_audit_run_id"],
    )
    op.create_index(
        "ix_forensic_evidence_references_source_finding_id",
        "forensic_evidence_references",
        ["source_finding_id"],
    )
    op.create_index(
        "ix_forensic_evidence_case_type", "forensic_evidence_references", ["case_id", "artifact_type"]
    )

    op.create_table(
        "forensic_evidence_observations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "reference_id", sa.String(36), sa.ForeignKey("forensic_evidence_references.id"), nullable=False
        ),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column("observed_sha256", sa.String(71), nullable=False, server_default=""),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("outcome", sa.String(16), nullable=False, server_default="NOT_RUN"),
        sa.Column("detail", sa.String(1024), nullable=False, server_default=""),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_forensic_evidence_observations_reference_id", "forensic_evidence_observations", ["reference_id"]
    )
    op.create_index(
        "ix_forensic_evidence_observations_case_id", "forensic_evidence_observations", ["case_id"]
    )
    op.create_index(
        "ix_forensic_evidence_observations_observed_at", "forensic_evidence_observations", ["observed_at"]
    )
    op.create_index(
        "ix_forensic_observation_ref_time", "forensic_evidence_observations", ["reference_id", "observed_at"]
    )

    op.create_table(
        "forensic_custody_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(256), nullable=False),
        sa.Column("actor_role", sa.String(16), nullable=False),
        sa.Column("artifact_id", sa.String(512), nullable=True),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.UniqueConstraint("case_id", "sequence", name="uq_forensic_custody_sequence"),
    )
    op.create_index("ix_forensic_custody_events_case_id", "forensic_custody_events", ["case_id"])
    op.create_index("ix_forensic_custody_events_event_type", "forensic_custody_events", ["event_type"])
    op.create_index("ix_forensic_custody_events_timestamp", "forensic_custody_events", ["timestamp"])
    op.create_index(
        "ix_forensic_custody_events_event_hash", "forensic_custody_events", ["event_hash"], unique=True
    )
    op.create_index("ix_forensic_custody_case_sequence", "forensic_custody_events", ["case_id", "sequence"])

    op.create_table(
        "forensic_notes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column("author_id", sa.String(256), nullable=False),
        sa.Column("note_type", sa.String(32), nullable=False),
        sa.Column("content", sa.String(16384), nullable=False),
        sa.Column("visibility", sa.String(16), nullable=False, server_default="INTERNAL"),
        sa.Column("related_evidence_ids", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("edited_by", sa.String(256), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_forensic_notes_case_id", "forensic_notes", ["case_id"])
    op.create_index("ix_forensic_notes_note_type", "forensic_notes", ["note_type"])
    op.create_index("ix_forensic_notes_created_at", "forensic_notes", ["created_at"])
    op.create_index("ix_forensic_notes_case_created", "forensic_notes", ["case_id", "created_at"])

    op.create_table(
        "forensic_note_revisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("note_id", sa.String(36), sa.ForeignKey("forensic_notes.id"), nullable=False),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("content", sa.String(16384), nullable=False),
        sa.Column("editor_id", sa.String(256), nullable=False),
        sa.Column("edited_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.UniqueConstraint("note_id", "revision", name="uq_forensic_note_revision"),
    )
    op.create_index("ix_forensic_note_revisions_note_id", "forensic_note_revisions", ["note_id"])
    op.create_index("ix_forensic_note_revisions_case_id", "forensic_note_revisions", ["case_id"])

    op.create_table(
        "forensic_actions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column("actor_id", sa.String(256), nullable=False),
        sa.Column("action_type", sa.String(64), nullable=False),
        sa.Column("description", sa.String(8192), nullable=False),
        sa.Column("related_finding_ids", sa.JSON(), nullable=False),
        sa.Column("action_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", sa.String(32), nullable=False, server_default="RECORDED"),
        sa.Column("approval_reference", sa.String(256), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False),
    )
    op.create_index("ix_forensic_actions_case_id", "forensic_actions", ["case_id"])
    op.create_index("ix_forensic_actions_action_type", "forensic_actions", ["action_type"])
    op.create_index("ix_forensic_actions_action_timestamp", "forensic_actions", ["action_timestamp"])
    op.create_index("ix_forensic_actions_case_time", "forensic_actions", ["case_id", "action_timestamp"])

    op.create_table(
        "forensic_assignments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column("assignee", sa.String(256), nullable=True),
        sa.Column("previous_assignee", sa.String(256), nullable=True),
        sa.Column("actor_id", sa.String(256), nullable=False),
        sa.Column("reason", sa.String(1024), nullable=False, server_default=""),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
    )
    op.create_index("ix_forensic_assignments_case_id", "forensic_assignments", ["case_id"])
    op.create_index("ix_forensic_assignments_timestamp", "forensic_assignments", ["timestamp"])
    op.create_index("ix_forensic_assignments_case_time", "forensic_assignments", ["case_id", "timestamp"])

    op.create_table(
        "forensic_exports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column("filename", sa.String(256), nullable=False),
        sa.Column("storage_relative_path", sa.String(2048), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("file_count", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column("policy_version", sa.String(16), nullable=False),
        sa.Column("created_by", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_outcome", sa.String(16), nullable=False, server_default="NOT_RUN"),
        sa.Column("verification_detail", sa.String(2048), nullable=False, server_default=""),
        sa.Column("manifest_digest", sa.String(64), nullable=False),
        sa.Column("root_digest", sa.String(64), nullable=False),
        sa.Column("evidence_bytes_included", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("metadata", sa.JSON(), nullable=False),
    )
    op.create_index("ix_forensic_exports_case_id", "forensic_exports", ["case_id"])
    op.create_index("ix_forensic_exports_created_at", "forensic_exports", ["created_at"])
    op.create_index("ix_forensic_exports_case_created", "forensic_exports", ["case_id", "created_at"])
    op.create_index(
        "ix_forensic_exports_storage_relative_path",
        "forensic_exports",
        ["storage_relative_path"],
        unique=True,
    )

    op.create_table(
        "forensic_verification_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("forensic_cases.id"), nullable=False),
        sa.Column("actor_id", sa.String(256), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("report", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
    )
    op.create_index("ix_forensic_verification_runs_case_id", "forensic_verification_runs", ["case_id"])
    op.create_index("ix_forensic_verification_runs_outcome", "forensic_verification_runs", ["outcome"])
    op.create_index("ix_forensic_verification_runs_created_at", "forensic_verification_runs", ["created_at"])
    op.create_index(
        "ix_forensic_verifications_case_created", "forensic_verification_runs", ["case_id", "created_at"]
    )

    op.create_table(
        "forensic_notification_state",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("rule_id", sa.String(36), nullable=False),
        sa.Column("dedup_key", sa.String(256), nullable=False),
        sa.Column("cooldown_key", sa.String(128), nullable=False),
        sa.Column("last_sent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notification_id", sa.String(36), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False),
    )
    op.create_index("ix_forensic_notification_state_rule_id", "forensic_notification_state", ["rule_id"])
    op.create_index(
        "ix_forensic_notification_state_dedup_key", "forensic_notification_state", ["dedup_key"], unique=True
    )
    op.create_index(
        "ix_forensic_notification_state_cooldown_key", "forensic_notification_state", ["cooldown_key"]
    )
    op.create_index(
        "ix_forensic_notification_state_last_sent_at", "forensic_notification_state", ["last_sent_at"]
    )
    op.create_index(
        "ix_forensic_notification_rule_cooldown",
        "forensic_notification_state",
        ["rule_id", "cooldown_key", "last_sent_at"],
    )


def downgrade() -> None:
    for table in (
        "forensic_notification_state",
        "forensic_verification_runs",
        "forensic_exports",
        "forensic_assignments",
        "forensic_actions",
        "forensic_note_revisions",
        "forensic_notes",
        "forensic_custody_events",
        "forensic_evidence_observations",
        "forensic_evidence_references",
        "forensic_incident_links",
        "forensic_correlations",
        "forensic_case_counters",
        "forensic_cases",
    ):
        op.drop_table(table)
