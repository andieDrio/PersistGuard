"""Store tenant deployment test evidence for coverage use cases."""

from alembic import op
import sqlalchemy as sa


revision = "0015_coverage_validations"
down_revision = "0014_case_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "coverage_validations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("use_case_id", sa.Text(), nullable=False),
        sa.Column("result", sa.Text(), nullable=False),
        sa.Column("tested_on", sa.Date(), nullable=False),
        sa.Column("reference", sa.Text(), nullable=False),
        sa.Column("recorded_by", sa.Uuid(), nullable=False),
        sa.Column("recorded_role", sa.Text(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("result IN ('passed', 'failed', 'inconclusive')", name="ck_coverage_validations_result"),
        sa.CheckConstraint("recorded_role IN ('admin', 'analyst')", name="ck_coverage_validations_role"),
        sa.UniqueConstraint("organization_id", "use_case_id", "tested_on", "result", "reference", name="uq_coverage_validation_test"),
    )
    op.create_index("ix_coverage_validations_scope_date", "coverage_validations",
                    ["organization_id", "use_case_id", "tested_on", "recorded_at", "id"])


def downgrade() -> None:
    op.drop_table("coverage_validations")
