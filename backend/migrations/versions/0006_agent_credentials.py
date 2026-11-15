"""Store issued client certificates and audit targets."""

from alembic import op
import sqlalchemy as sa


revision = "0006_agent_credentials"
down_revision = "0005_endpoint_public_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("target_id", sa.Uuid()))
    op.create_table(
        "agent_credentials",
        sa.Column("certificate_serial", sa.Text(), primary_key=True),
        sa.Column("endpoint_id", sa.Uuid(), sa.ForeignKey("endpoints.id"), nullable=False),
        sa.Column("certificate_pem", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_agent_credentials_endpoint_id", "agent_credentials", ["endpoint_id"])
    op.create_index(
        "uq_agent_credentials_unrevoked_endpoint",
        "agent_credentials",
        ["endpoint_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_table("agent_credentials")
    op.drop_column("audit_events", "target_id")
