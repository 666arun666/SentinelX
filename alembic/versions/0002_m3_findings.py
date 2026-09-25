"""m3_findings

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-15 18:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001_m2_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("finding_id"),
    )
    op.create_index("idx_findings_rule_id", "findings", ["rule_id"], unique=False)
    op.create_index("idx_findings_severity", "findings", ["severity"], unique=False)
    op.create_index("idx_findings_status", "findings", ["status"], unique=False)
    op.create_index("idx_findings_created_at", "findings", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("idx_findings_created_at", table_name="findings")
    op.drop_index("idx_findings_status", table_name="findings")
    op.drop_index("idx_findings_severity", table_name="findings")
    op.drop_index("idx_findings_rule_id", table_name="findings")
    op.drop_table("findings")
