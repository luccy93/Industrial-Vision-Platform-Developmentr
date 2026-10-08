"""Create incident management tables (V10).

Operational incident records: incidents, linked intelligence events, the
append-only timeline, evidence metadata, assignment audit rows, and yearly
numbering counters. Runtime perception state stays in memory; only
operational records persist here.

Revision ID: 005_create_incident_management
Revises: 004_create_autonomous_perception_profiles
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "005_create_incident_management"
down_revision = "004_create_autonomous_perception_profiles"
branch_labels = None
depends_on = None

# Incident states that block automatic creation of a duplicate incident for
# the same source cluster. RESOLVED incidents update in place; CLOSED ones
# allow a brand-new incident.
_OPEN_STATES = ["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "MITIGATED"]


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_number", sa.String(32), nullable=False, unique=True),
        sa.Column("camera_id", sa.String(128), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("description", sa.String(4096), nullable=False, server_default=""),
        sa.Column("source_cluster_id", sa.String(128), nullable=True),
        sa.Column("primary_event_id", sa.String(128), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("risk_level", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("priority", sa.String(8), nullable=False, server_default="P4"),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("category", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("source", sa.String(16), nullable=False, server_default="AUTOMATIC"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assigned_to", sa.String(256), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_priority", "incidents", ["priority"])
    op.create_index("ix_incidents_camera_id", "incidents", ["camera_id"])
    op.create_index("ix_incidents_created_at", "incidents", ["created_at"])
    op.create_index("ix_incidents_source_cluster_id", "incidents", ["source_cluster_id"])
    op.create_index("ix_incidents_assigned_to", "incidents", ["assigned_to"])
    # One open incident per source cluster: enforced at the database level in
    # addition to the application-level dedupe check in IncidentManager.
    op.create_index(
        "uq_incidents_open_cluster",
        "incidents",
        ["camera_id", "source_cluster_id"],
        unique=True,
        sqlite_where=sa.text(f"status IN ({', '.join(repr(s) for s in _OPEN_STATES)})"),
        postgresql_where=sa.text(f"status IN ({', '.join(repr(s) for s in _OPEN_STATES)})"),
    )

    op.create_table(
        "incident_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), nullable=False),
        sa.Column("event_id", sa.String(128), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False, server_default="UNKNOWN"),
        sa.Column("source_domain", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.create_index("ix_incident_events_incident_id", "incident_events", ["incident_id"])

    op.create_table(
        "incident_timeline",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("actor_id", sa.String(256), nullable=True),
        sa.Column("actor_type", sa.String(16), nullable=False, server_default="SYSTEM"),
        sa.Column("message", sa.String(4096), nullable=False, server_default=""),
        sa.Column("previous_state", sa.String(64), nullable=True),
        sa.Column("new_state", sa.String(64), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.create_index("ix_incident_timeline_incident_id", "incident_timeline", ["incident_id"])
    op.create_index(
        "ix_incident_timeline_incident_timestamp", "incident_timeline", ["incident_id", "timestamp"]
    )

    op.create_table(
        "incident_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), nullable=False),
        sa.Column("camera_id", sa.String(128), nullable=False),
        sa.Column("evidence_type", sa.String(16), nullable=False, server_default="OTHER"),
        sa.Column("uri", sa.String(2048), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("frame_id", sa.String(128), nullable=True),
        sa.Column("description", sa.String(4096), nullable=False, server_default=""),
        sa.Column("checksum", sa.String(256), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incident_evidence_incident_id", "incident_evidence", ["incident_id"])

    op.create_table(
        "incident_assignments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), nullable=False),
        sa.Column("assignee", sa.String(256), nullable=True),
        sa.Column("previous_assignee", sa.String(256), nullable=True),
        sa.Column("actor_id", sa.String(256), nullable=True),
        sa.Column("actor_type", sa.String(16), nullable=False, server_default="SYSTEM"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.create_index("ix_incident_assignments_incident_id", "incident_assignments", ["incident_id"])

    op.create_table(
        "incident_counters",
        sa.Column("year", sa.Integer(), primary_key=True),
        sa.Column("last_number", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_table("incident_counters")
    op.drop_index("ix_incident_assignments_incident_id", table_name="incident_assignments")
    op.drop_table("incident_assignments")
    op.drop_index("ix_incident_evidence_incident_id", table_name="incident_evidence")
    op.drop_table("incident_evidence")
    op.drop_index("ix_incident_timeline_incident_timestamp", table_name="incident_timeline")
    op.drop_index("ix_incident_timeline_incident_id", table_name="incident_timeline")
    op.drop_table("incident_timeline")
    op.drop_index("ix_incident_events_incident_id", table_name="incident_events")
    op.drop_table("incident_events")
    op.drop_index("uq_incidents_open_cluster", table_name="incidents")
    op.drop_index("ix_incidents_assigned_to", table_name="incidents")
    op.drop_index("ix_incidents_source_cluster_id", table_name="incidents")
    op.drop_index("ix_incidents_created_at", table_name="incidents")
    op.drop_index("ix_incidents_camera_id", table_name="incidents")
    op.drop_index("ix_incidents_priority", table_name="incidents")
    op.drop_index("ix_incidents_status", table_name="incidents")
    op.drop_table("incidents")
