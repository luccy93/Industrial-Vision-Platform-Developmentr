"""Create cameras table (V02 video ingestion).

Revision ID: 001_create_cameras
Revises:
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "001_create_cameras"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cameras",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("camera_id", sa.String(128), nullable=False, unique=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("source_type", sa.String(16), nullable=False, server_default="file"),
        sa.Column("source", sa.String(1024), nullable=False, server_default=""),
        sa.Column("source_secret", sa.String(1024), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("width", sa.Integer(), nullable=True),
        sa.Column("height", sa.Integer(), nullable=True),
        sa.Column("target_fps", sa.Float(), nullable=True),
        sa.Column("reconnect_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_cameras_camera_id", "cameras", ["camera_id"])


def downgrade() -> None:
    op.drop_index("ix_cameras_camera_id", table_name="cameras")
    op.drop_table("cameras")
