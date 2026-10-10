"""Create alerting and notification tables (V15).

Durable alert rules, notification instances, per-channel delivery
attempts, incident transition records, evaluation outcomes (including
cooldown suppressions), and consumer watermarks. Additive only; no
existing tables touched. No credentials stored anywhere here.

Revision ID: 008_create_alerting
Revises: 007_add_analytics_time_indexes
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "008_create_alerting"
down_revision = "007_add_analytics_time_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alert_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.String(1024), nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("domains", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("event_types", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("min_severity", sa.String(16), nullable=True),
        sa.Column("min_priority", sa.String(8), nullable=True),
        sa.Column("camera_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("incident_statuses", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("channels", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("cooldown_seconds", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("suppression_scope", sa.String(16), nullable=False, server_default="RULE"),
        sa.Column("trigger_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("suppressed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_alert_rules_enabled", "alert_rules", ["enabled"])

    op.create_table(
        "notifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("rule_id", sa.String(36), sa.ForeignKey("alert_rules.id"), nullable=False),
        sa.Column("source_event_id", sa.String(256), nullable=False),
        sa.Column("source_domain", sa.String(32), nullable=False, server_default=""),
        sa.Column("event_type", sa.String(64), nullable=False, server_default=""),
        sa.Column("camera_id", sa.String(128), nullable=True),
        sa.Column("incident_id", sa.String(36), nullable=True),
        sa.Column("title", sa.String(256), nullable=False, server_default=""),
        sa.Column("message", sa.String(4096), nullable=False, server_default=""),
        sa.Column("severity", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("priority", sa.String(8), nullable=False, default="P4"),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("rule_id", "source_event_id", name="uq_notification_rule_source"),
    )
    op.create_index("ix_notifications_rule_id", "notifications", ["rule_id"])
    op.create_index("ix_notifications_camera_id", "notifications", ["camera_id"])
    op.create_index("ix_notifications_incident_id", "notifications", ["incident_id"])
    op.create_index("ix_notifications_created_at", "notifications", ["created_at"])

    op.create_table(
        "delivery_attempts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("notification_id", sa.String(36), sa.ForeignKey("notifications.id"), nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("destination", sa.String(512), nullable=False, server_default=""),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "notification_id", "channel", "destination", name="uq_delivery_notification_channel"
        ),
    )
    op.create_index("ix_delivery_notification_id", "delivery_attempts", ["notification_id"])
    op.create_index("ix_delivery_channel", "delivery_attempts", ["channel"])
    op.create_index("ix_delivery_status", "delivery_attempts", ["status"])
    op.create_index("ix_delivery_next_retry_at", "delivery_attempts", ["next_retry_at"])
    op.create_index("ix_delivery_pending_retry", "delivery_attempts", ["status", "next_retry_at"])

    op.create_table(
        "incident_transitions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), nullable=False),
        sa.Column("transition_type", sa.String(32), nullable=False),
        sa.Column("previous_state", sa.String(16), nullable=True),
        sa.Column("new_state", sa.String(16), nullable=True),
        sa.Column("actor_id", sa.String(256), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.create_index("ix_transition_incident_id", "incident_transitions", ["incident_id"])
    op.create_index("ix_transition_type", "incident_transitions", ["transition_type"])
    op.create_index("ix_transition_timestamp", "incident_transitions", ["timestamp"])

    op.create_table(
        "alert_evaluations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("rule_id", sa.String(36), sa.ForeignKey("alert_rules.id"), nullable=False),
        sa.Column("source_event_id", sa.String(256), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("suppression_reason", sa.String(32), nullable=True),
        sa.Column("suppression_scope", sa.String(16), nullable=True),
        sa.Column("next_eligible_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.UniqueConstraint("rule_id", "source_event_id", name="uq_evaluation_rule_source"),
    )
    op.create_index("ix_evaluation_rule_id", "alert_evaluations", ["rule_id"])
    op.create_index("ix_evaluation_outcome", "alert_evaluations", ["outcome"])
    op.create_index("ix_evaluation_evaluated_at", "alert_evaluations", ["evaluated_at"])

    op.create_table(
        "alerting_cursor",
        sa.Column("consumer", sa.String(64), primary_key=True),
        sa.Column("last_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_id", sa.String(256), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("alerting_cursor")
    op.drop_index("ix_evaluation_evaluated_at", table_name="alert_evaluations")
    op.drop_index("ix_evaluation_outcome", table_name="alert_evaluations")
    op.drop_index("ix_evaluation_rule_id", table_name="alert_evaluations")
    op.drop_table("alert_evaluations")
    op.drop_index("ix_transition_timestamp", table_name="incident_transitions")
    op.drop_index("ix_transition_type", table_name="incident_transitions")
    op.drop_index("ix_transition_incident_id", table_name="incident_transitions")
    op.drop_table("incident_transitions")
    op.drop_index("ix_delivery_pending_retry", table_name="delivery_attempts")
    op.drop_index("ix_delivery_next_retry_at", table_name="delivery_attempts")
    op.drop_index("ix_delivery_status", table_name="delivery_attempts")
    op.drop_index("ix_delivery_channel", table_name="delivery_attempts")
    op.drop_index("ix_delivery_notification_id", table_name="delivery_attempts")
    op.drop_table("delivery_attempts")
    op.drop_index("ix_notifications_created_at", table_name="notifications")
    op.drop_index("ix_notifications_incident_id", table_name="notifications")
    op.drop_index("ix_notifications_camera_id", table_name="notifications")
    op.drop_index("ix_notifications_rule_id", table_name="notifications")
    op.drop_table("notifications")
    op.drop_index("ix_alert_rules_enabled", table_name="alert_rules")
    op.drop_table("alert_rules")
