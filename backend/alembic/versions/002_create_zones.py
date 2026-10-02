"""Create zones table (V06 spatial safety).

Revision ID: 002_create_zones
Revises: 001_create_cameras
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "002_create_zones"
down_revision = "001_create_cameras"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "zones",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("zone_id", sa.String(128), nullable=False),
        sa.Column("camera_id", sa.String(128), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("zone_type", sa.String(16), nullable=False, server_default="RESTRICTED"),
        sa.Column("polygon", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("severity", sa.String(16), nullable=False, server_default="HIGH"),
        sa.Column("dwell_threshold_seconds", sa.Float(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_zones_camera_id", "zones", ["camera_id"])
    op.create_index("ix_zones_zone_id", "zones", ["zone_id"])


def downgrade() -> None:
    op.drop_index("ix_zones_zone_id", table_name="zones")
    op.drop_index("ix_zones_camera_id", table_name="zones")
    op.drop_table("zones")
