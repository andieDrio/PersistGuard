"""Add tenant-scoped cases and indicators."""

from alembic import op
import sqlalchemy as sa


revision = "0011_workspace_registers"
down_revision = "0010_scan_queue_management"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default="new", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('new', 'in_progress', 'resolved')", name="ck_cases_status"),
    )
    op.create_index("ix_cases_org_created", "cases", ["organization_id", "created_at", "id"])
    op.create_table(
        "indicators",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("kind IN ('ip', 'domain', 'sha256', 'url')", name="ck_indicators_kind"),
        sa.UniqueConstraint("organization_id", "kind", "value", name="uq_indicators_org_kind_value"),
    )
    op.create_index("ix_indicators_org_created", "indicators", ["organization_id", "created_at", "id"])


def downgrade() -> None:
    op.drop_table("indicators")
    op.drop_table("cases")
