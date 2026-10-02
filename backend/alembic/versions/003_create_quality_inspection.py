"""Create quality inspection tables (V07).

Configuration only: profiles, regions, defect categories, and
profile<->category associations. Frame-level results/observations/events are
never persisted.

Revision ID: 003_create_quality_inspection
Revises: 002_create_zones
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "003_create_quality_inspection"
down_revision = "002_create_zones"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "inspection_profiles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("profile_id", sa.String(128), nullable=False),
        sa.Column("camera_id", sa.String(128), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("inspection_type", sa.String(16), nullable=False, server_default="GENERAL"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("confidence_threshold", sa.Float(), nullable=False, server_default="0.6"),
        sa.Column("review_threshold", sa.Float(), nullable=False, server_default="0.35"),
        sa.Column("decision_policy", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("product_correlation", sa.JSON(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("camera_id", "profile_id", name="uq_inspection_profiles_camera_profile"),
    )
    op.create_index("ix_inspection_profiles_camera_id", "inspection_profiles", ["camera_id"])
    op.create_index("ix_inspection_profiles_profile_id", "inspection_profiles", ["profile_id"])

    op.create_table(
        "inspection_regions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("region_id", sa.String(128), nullable=False),
        sa.Column("camera_id", sa.String(128), nullable=False),
        sa.Column("profile_id", sa.String(128), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("region_type", sa.String(16), nullable=False, server_default="RECTANGLE"),
        sa.Column("geometry", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("required", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "camera_id", "profile_id", "region_id", name="uq_inspection_regions_profile_region"
        ),
    )
    op.create_index("ix_inspection_regions_camera_id", "inspection_regions", ["camera_id"])
    op.create_index("ix_inspection_regions_profile_id", "inspection_regions", ["profile_id"])

    op.create_table(
        "defect_categories",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("code", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.String(1024), nullable=False, server_default=""),
        sa.Column("severity", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("confidence_threshold", sa.Float(), nullable=False, server_default="0.6"),
        sa.Column("review_threshold", sa.Float(), nullable=False, server_default="0.35"),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("code", name="uq_defect_categories_code"),
    )
    op.create_index("ix_defect_categories_code", "defect_categories", ["code"])

    op.create_table(
        "inspection_profile_defect_categories",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("camera_id", sa.String(128), nullable=False),
        sa.Column("profile_id", sa.String(128), nullable=False),
        sa.Column("defect_category_id", sa.String(36), nullable=False),
        sa.Column("defect_code", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("override_confidence_threshold", sa.Float(), nullable=True),
        sa.Column("override_review_threshold", sa.Float(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "profile_id",
            "defect_category_id",
            name="uq_inspection_profile_defect_category",
        ),
    )
    op.create_index(
        "ix_inspection_profile_defect_categories_profile_id",
        "inspection_profile_defect_categories",
        ["profile_id"],
    )
    op.create_index(
        "ix_inspection_profile_defect_categories_category_id",
        "inspection_profile_defect_categories",
        ["defect_category_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_inspection_profile_defect_categories_category_id",
        table_name="inspection_profile_defect_categories",
    )
    op.drop_index(
        "ix_inspection_profile_defect_categories_profile_id",
        table_name="inspection_profile_defect_categories",
    )
    op.drop_table("inspection_profile_defect_categories")
    op.drop_index("ix_defect_categories_code", table_name="defect_categories")
    op.drop_table("defect_categories")
    op.drop_index("ix_inspection_regions_profile_id", table_name="inspection_regions")
    op.drop_index("ix_inspection_regions_camera_id", table_name="inspection_regions")
    op.drop_table("inspection_regions")
    op.drop_index("ix_inspection_profiles_profile_id", table_name="inspection_profiles")
    op.drop_index("ix_inspection_profiles_camera_id", table_name="inspection_profiles")
    op.drop_table("inspection_profiles")
