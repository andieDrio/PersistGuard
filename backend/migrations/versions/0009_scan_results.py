"""Persist completed device inventory reports."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0009_scan_results"
down_revision = "0008_scan_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_jobs", sa.Column("result", postgresql.JSONB()))
    op.add_column("scan_jobs", sa.Column("finished_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("scan_jobs", "finished_at")
    op.drop_column("scan_jobs", "result")
