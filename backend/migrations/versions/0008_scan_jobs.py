"""Queue tenant-scoped Windows inventory jobs."""

from alembic import op
import sqlalchemy as sa


revision = "0008_scan_jobs"
down_revision = "0007_credential_rotation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        sa.Column("scan_type", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="queued"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["endpoint_id", "organization_id"], ["endpoints.id", "endpoints.organization_id"]),
        sa.CheckConstraint("scan_type = 'persistence_full_scan'", name="ck_scan_jobs_type"),
        sa.CheckConstraint(
            "status IN ('queued', 'dispatched', 'acknowledged', 'running', 'uploading', 'analyzing', "
            "'completed', 'partial', 'failed')", name="ck_scan_jobs_status",
        ),
    )
    op.create_index(
        "uq_scan_jobs_open_endpoint", "scan_jobs", ["endpoint_id"], unique=True,
        postgresql_where=sa.text("status NOT IN ('completed', 'partial', 'failed')"),
    )


def downgrade() -> None:
    op.drop_table("scan_jobs")
