"""Add tenant-scoped links to preserved scan finding evidence."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0014_case_findings"
down_revision = "0013_rule_version_history"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint("uq_cases_id_org", "cases", ["id", "organization_id"])
    op.create_unique_constraint("uq_scan_jobs_id_org", "scan_jobs", ["id", "organization_id"])
    op.create_table(
        "case_findings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("scan_job_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("artifact_index", sa.Integer(), nullable=False),
        sa.Column("evidence", JSONB(), nullable=False),
        sa.Column("attached_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["case_id", "organization_id"], ["cases.id", "cases.organization_id"]),
        sa.ForeignKeyConstraint(["scan_job_id", "organization_id"], ["scan_jobs.id", "scan_jobs.organization_id"]),
        sa.UniqueConstraint("case_id", "scan_job_id", "source", "artifact_index", name="uq_case_findings_artifact"),
        sa.CheckConstraint("source IN ('registry', 'scheduled_tasks', 'services') AND artifact_index >= 0",
                           name="ck_case_findings_artifact"),
    )
    op.create_index("ix_case_findings_case_attached", "case_findings", ["case_id", "attached_at", "id"])
    op.create_index("ix_case_findings_scan_job", "case_findings", ["scan_job_id"])


def downgrade() -> None:
    op.drop_table("case_findings")
    op.drop_constraint("uq_scan_jobs_id_org", "scan_jobs", type_="unique")
    op.drop_constraint("uq_cases_id_org", "cases", type_="unique")
