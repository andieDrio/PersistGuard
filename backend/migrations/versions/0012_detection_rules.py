"""Add tenant-scoped custom detection rules."""

from alembic import op
import sqlalchemy as sa


revision = "0012_detection_rules"
down_revision = "0011_workspace_registers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("field", sa.Text(), nullable=False),
        sa.Column("pattern", sa.Text(), nullable=False),
        sa.Column("score", sa.SmallInteger(), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("tested", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.CheckConstraint("source IN ('registry', 'scheduled_tasks', 'services')", name="ck_detection_rules_source"),
        sa.CheckConstraint("field IN ('path', 'command')", name="ck_detection_rules_field"),
        sa.CheckConstraint("score BETWEEN 1 AND 100", name="ck_detection_rules_score"),
        sa.CheckConstraint("NOT enabled OR tested", name="ck_detection_rules_tested"),
    )
    op.create_index("ix_detection_rules_org", "detection_rules", ["organization_id"])


def downgrade() -> None:
    op.drop_table("detection_rules")
