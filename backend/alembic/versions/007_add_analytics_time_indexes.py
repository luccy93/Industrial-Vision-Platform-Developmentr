"""Add analytics time-range indexes (V14).

EXPLAIN on the V14 query patterns proves sequential scans without these:

- incidents resolved/closed range filters (terminal counts, durations).
  (created_at has been indexed since 005; verified, not duplicated here.)
- operational_events first_seen range filter (trend/window reads) —
  only last_seen was indexed in 006.

Three plain btree indexes, additive only. No data changes, no constraint
changes, fully reversible.

Revision ID: 007_add_analytics_time_indexes
Revises: 006_create_operational_events
"""

from __future__ import annotations

from alembic import op

revision = "007_add_analytics_time_indexes"
down_revision = "006_create_operational_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_incidents_resolved_at", "incidents", ["resolved_at"])
    op.create_index("ix_incidents_closed_at", "incidents", ["closed_at"])
    op.create_index("ix_operational_events_first_seen", "operational_events", ["first_seen"])


def downgrade() -> None:
    op.drop_index("ix_operational_events_first_seen", table_name="operational_events")
    op.drop_index("ix_incidents_closed_at", table_name="incidents")
    op.drop_index("ix_incidents_resolved_at", table_name="incidents")
