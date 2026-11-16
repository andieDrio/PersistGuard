"""Allow Windows scan jobs for individual collectors."""

from alembic import op
import sqlalchemy as sa


revision = "0016_targeted_scans"
down_revision = "0015_coverage_validations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("ck_scan_jobs_type", "scan_jobs", type_="check")
    op.create_check_constraint(
        "ck_scan_jobs_type", "scan_jobs",
        "scan_type IN ('persistence_full_scan', 'persistence_registry_scan', "
        "'persistence_scheduled_tasks_scan', 'persistence_services_scan')",
    )


def downgrade() -> None:
    if op.get_bind().scalar(sa.text("SELECT EXISTS (SELECT 1 FROM scan_jobs WHERE scan_type <> 'persistence_full_scan')")):
        raise RuntimeError("Downgrade requires archiving and removing targeted scan jobs first")
    op.drop_constraint("ck_scan_jobs_type", "scan_jobs", type_="check")
    op.create_check_constraint("ck_scan_jobs_type", "scan_jobs", "scan_type = 'persistence_full_scan'")
