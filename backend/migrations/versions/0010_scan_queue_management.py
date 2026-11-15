"""Add cancellation and organization-scoped job listing."""

from alembic import op
import sqlalchemy as sa


revision = "0010_scan_queue_management"
down_revision = "0009_scan_results"
branch_labels = None
depends_on = None


def replace_status_rules(cancellation: bool) -> None:
    statuses = "'queued', 'dispatched', 'acknowledged', 'running', 'uploading', 'analyzing'"
    terminal = "'completed', 'partial', 'failed'" + (", 'canceled'" if cancellation else "")
    op.drop_index("uq_scan_jobs_open_endpoint", table_name="scan_jobs")
    op.drop_constraint("ck_scan_jobs_status", "scan_jobs", type_="check")
    op.create_check_constraint("ck_scan_jobs_status", "scan_jobs", f"status IN ({statuses}, {terminal})")
    op.create_index(
        "uq_scan_jobs_open_endpoint", "scan_jobs", ["endpoint_id"], unique=True,
        postgresql_where=sa.text(f"status NOT IN ({terminal})"),
    )


def upgrade() -> None:
    replace_status_rules(cancellation=True)
    op.create_index("ix_scan_jobs_org_created", "scan_jobs", ["organization_id", "created_at", "id"])


def downgrade() -> None:
    op.execute("UPDATE scan_jobs SET status = 'failed' WHERE status = 'canceled'")
    op.drop_index("ix_scan_jobs_org_created", table_name="scan_jobs")
    replace_status_rules(cancellation=False)
