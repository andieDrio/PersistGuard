"""Persist recurring Windows inventory schedules and job provenance."""

from alembic import op
import sqlalchemy as sa


revision = "0017_scan_schedules"
down_revision = "0016_targeted_scans"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        sa.Column("scan_type", sa.Text(), nullable=False),
        sa.Column("frequency", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_outcome", sa.Text()),
        sa.ForeignKeyConstraint(["endpoint_id", "organization_id"], ["endpoints.id", "endpoints.organization_id"]),
        sa.UniqueConstraint("id", "organization_id", name="uq_scan_schedules_id_org"),
        sa.UniqueConstraint("organization_id", "endpoint_id", "scan_type", name="uq_scan_schedules_endpoint_scope"),
        sa.CheckConstraint("scan_type IN ('persistence_full_scan', 'persistence_registry_scan', "
                           "'persistence_scheduled_tasks_scan', 'persistence_services_scan')", name="ck_scan_schedules_type"),
        sa.CheckConstraint("frequency IN ('daily', 'weekly')", name="ck_scan_schedules_frequency"),
        sa.CheckConstraint("last_outcome IN ('queued', 'skipped_busy', 'paused_endpoint', 'paused_owner')",
                           name="ck_scan_schedules_outcome"),
    )
    op.create_index("ix_scan_schedules_due", "scan_schedules", ["next_run_at", "id"],
                    postgresql_where=sa.text("enabled IS TRUE"))
    op.add_column("scan_jobs", sa.Column("schedule_id", sa.Uuid(), nullable=True))
    op.create_foreign_key("fk_scan_jobs_schedule_org", "scan_jobs", "scan_schedules",
                          ["schedule_id", "organization_id"], ["id", "organization_id"])


def downgrade() -> None:
    op.drop_constraint("fk_scan_jobs_schedule_org", "scan_jobs", type_="foreignkey")
    op.drop_column("scan_jobs", "schedule_id")
    op.drop_table("scan_schedules")
