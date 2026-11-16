"""Persist per-schedule run history and recover recorded legacy outcomes."""

from alembic import op
import sqlalchemy as sa


revision = "0018_scan_schedule_runs"
down_revision = "0017_scan_schedules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_schedule_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("schedule_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid()),
        sa.Column("scheduled_for", sa.DateTime(timezone=True)),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["schedule_id", "organization_id"], ["scan_schedules.id", "scan_schedules.organization_id"]),
        sa.ForeignKeyConstraint(["job_id", "organization_id"], ["scan_jobs.id", "scan_jobs.organization_id"]),
        sa.UniqueConstraint("job_id", name="uq_scan_schedule_runs_job"),
        sa.CheckConstraint("outcome IN ('queued', 'skipped_busy', 'paused_endpoint', 'paused_owner') "
                           "AND (outcome = 'queued') = (job_id IS NOT NULL)", name="ck_scan_schedule_runs_outcome"),
    )
    # Earlier versions retained the job creation time and only the last scheduler outcome.
    op.execute("""
        INSERT INTO scan_schedule_runs (id, organization_id, schedule_id, job_id, attempted_at, outcome)
        SELECT id, organization_id, schedule_id, id, created_at, 'queued'
        FROM scan_jobs WHERE schedule_id IS NOT NULL
    """)
    op.execute("""
        INSERT INTO scan_schedule_runs (id, organization_id, schedule_id, attempted_at, outcome)
        SELECT gen_random_uuid(), organization_id, id, last_run_at, last_outcome
        FROM scan_schedules
        WHERE last_run_at IS NOT NULL AND last_outcome IN ('skipped_busy', 'paused_endpoint', 'paused_owner')
    """)
    op.create_index("ix_scan_schedule_runs_history", "scan_schedule_runs", ["schedule_id", "attempted_at", "id"])


def downgrade() -> None:
    op.drop_table("scan_schedule_runs")
