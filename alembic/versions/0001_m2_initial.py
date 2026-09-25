"""M2 initial schema

Revision ID: 0001_m2_initial
Revises:
Create Date: 2026-08-15 10:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001_m2_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "log_sources",
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("format", sa.String(), nullable=False),
        sa.Column("file_inode", sa.BigInteger(), nullable=True),
        sa.Column("offset", sa.BigInteger(), nullable=True),
        sa.Column("journal_cursor", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("last_read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("source"),
    )
    op.create_table(
        "events",
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hostname", sa.String(), nullable=True),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=True),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("source_ip", sa.String(), nullable=True),
        sa.Column("destination_ip", sa.String(), nullable=True),
        sa.Column("process", sa.String(), nullable=True),
        sa.Column("command", sa.String(), nullable=True),
        sa.Column("file_path", sa.String(), nullable=True),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("raw_log", sa.Text(), nullable=False),
        sa.Column("indicators", sa.JSON(), nullable=True),
        sa.Column("log_source", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("event_id"),
    )
    op.create_index(
        "idx_events_time_ip_user",
        "events",
        ["event_time", "source_ip", "username"],
        unique=False,
    )
    op.create_index("idx_events_source", "events", ["source"], unique=False)
    op.create_index("idx_events_hostname", "events", ["hostname"], unique=False)
    op.create_index("idx_events_event_type", "events", ["event_type"], unique=False)
    op.create_index("idx_events_severity", "events", ["severity"], unique=False)


def downgrade() -> None:
    op.drop_index("idx_events_severity", table_name="events")
    op.drop_index("idx_events_event_type", table_name="events")
    op.drop_index("idx_events_hostname", table_name="events")
    op.drop_index("idx_events_source", table_name="events")
    op.drop_index("idx_events_time_ip_user", table_name="events")
    op.drop_table("events")
    op.drop_table("log_sources")
