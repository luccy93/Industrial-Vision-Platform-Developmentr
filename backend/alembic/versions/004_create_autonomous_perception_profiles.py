"""Create autonomous perception profiles table (V08).

Configuration only: per-camera perception profiles. Frame-level scenes,
objects, trajectories, risk estimates, and events are never persisted.

Revision ID: 004_create_autonomous_perception_profiles
Revises: 003_create_quality_inspection
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "004_create_autonomous_perception_profiles"
down_revision = "003_create_quality_inspection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "autonomous_perception_profiles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("profile_id", sa.String(128), nullable=False),
        sa.Column("camera_id", sa.String(128), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("scene_type", sa.String(32), nullable=False, server_default="UNKNOWN"),
        sa.Column("lane_detection_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("depth_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("trajectory_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("collision_risk_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("bev_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("trajectory_horizon_seconds", sa.Float(), nullable=False, server_default="2.0"),
        sa.Column("collision_risk_threshold", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("collision_grace_seconds", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("configuration", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("camera_id", "profile_id", name="uq_autonomous_profiles_camera_profile"),
    )
    op.create_index("ix_autonomous_profiles_camera_id", "autonomous_perception_profiles", ["camera_id"])
    op.create_index("ix_autonomous_profiles_profile_id", "autonomous_perception_profiles", ["profile_id"])


def downgrade() -> None:
    op.drop_index("ix_autonomous_profiles_profile_id", table_name="autonomous_perception_profiles")
    op.drop_index("ix_autonomous_profiles_camera_id", table_name="autonomous_perception_profiles")
    op.drop_table("autonomous_perception_profiles")
