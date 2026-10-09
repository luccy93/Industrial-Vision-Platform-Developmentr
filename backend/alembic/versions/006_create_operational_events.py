"""Create operational event history + delivery outbox (V12).

``operational_events`` durably records canonical V09 unified events that
gain operational significance (one row per stable event identity,
idempotent upsert). ``event_outbox`` holds delivery intents written in
the same transaction as the event row; a managed publisher drains them.

Deliberately NOT stored: frames, detections, tracks, telemetry samples.

Revision ID: 006_create_operational_events
Revises: 005_create_incident_management
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "006_create_operational_events"
down_revision = "005_create_incident_management"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "operational_events",
        sa.Column("event_id", sa.String(128), primary_key=True),
        sa.Column("camera_id", sa.String(128), nullable=False),
        sa.Column("source_domain", sa.String(32), nullable=False),
        sa.Column("source_event_id", sa.String(128), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("risk_level", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("status", sa.String(16), nullable=False, server_default="ACTIVE"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.create_index("ix_operational_events_camera_id", "operational_events", ["camera_id"])
    op.create_index("ix_operational_events_source_domain", "operational_events", ["source_domain"])
    op.create_index("ix_operational_events_event_type", "operational_events", ["event_type"])
    op.create_index("ix_operational_events_last_seen", "operational_events", ["last_seen"])
    op.create_index(
        "ix_operational_events_domain_type",
        "operational_events",
        ["source_domain", "event_type"],
    )
    # Unique index (not constraint): SQLite cannot ALTER constraints, and
    # the 005 precedent uses unique indexes for the same reason.
    op.create_index(
        "uq_operational_event_source",
        "operational_events",
        ["camera_id", "source_domain", "source_event_id"],
        unique=True,
    )

    op.create_table(
        "event_outbox",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("event_id", sa.String(256), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("envelope", sa.JSON(), nullable=False),
        sa.Column("last_error", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("uq_event_outbox_event_id", "event_outbox", ["event_id"], unique=True)
    op.create_index("ix_event_outbox_kind", "event_outbox", ["kind"])
    op.create_index("ix_event_outbox_status", "event_outbox", ["status"])
    op.create_index("ix_event_outbox_next_retry_at", "event_outbox", ["next_retry_at"])


def downgrade() -> None:
    op.drop_index("ix_event_outbox_next_retry_at", table_name="event_outbox")
    op.drop_index("ix_event_outbox_status", table_name="event_outbox")
    op.drop_index("ix_event_outbox_kind", table_name="event_outbox")
    op.drop_index("uq_event_outbox_event_id", table_name="event_outbox")
    op.drop_table("event_outbox")
    op.drop_index("uq_operational_event_source", table_name="operational_events")
    op.drop_index("ix_operational_events_domain_type", table_name="operational_events")
    op.drop_index("ix_operational_events_last_seen", table_name="operational_events")
    op.drop_index("ix_operational_events_event_type", table_name="operational_events")
    op.drop_index("ix_operational_events_source_domain", table_name="operational_events")
    op.drop_index("ix_operational_events_camera_id", table_name="operational_events")
    op.drop_table("operational_events")
