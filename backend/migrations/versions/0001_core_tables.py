"""Create organizations, users, and endpoints."""

from alembic import op
import sqlalchemy as sa


revision = "0001_core_tables"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("role IN ('admin', 'analyst', 'viewer')", name="ck_users_role"),
    )
    op.create_index(
        "uq_users_org_email",
        "users",
        ["organization_id", sa.text("lower(email)")],
        unique=True,
    )

    op.create_table(
        "endpoints",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("hostname", sa.Text(), nullable=False),
        sa.Column("os_family", sa.Text(), nullable=False),
        sa.Column("os_version", sa.Text()),
        sa.Column("agent_version", sa.Text()),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("id", "organization_id", name="uq_endpoints_id_org"),
    )
    op.create_index("ix_endpoints_organization_id", "endpoints", ["organization_id"])


def downgrade() -> None:
    op.drop_table("endpoints")
    op.drop_table("users")
    op.drop_table("organizations")
