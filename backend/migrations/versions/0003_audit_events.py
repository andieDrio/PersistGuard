"""Create the API audit event table."""

from alembic import op
import sqlalchemy as sa


revision = "0003_audit_events"
down_revision = "0002_user_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("status_code", sa.SmallInteger(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status_code BETWEEN 100 AND 599", name="ck_audit_events_status_code"),
    )
    op.create_index("ix_audit_events_org_time", "audit_events", ["organization_id", "occurred_at"])


def downgrade() -> None:
    op.drop_table("audit_events")
