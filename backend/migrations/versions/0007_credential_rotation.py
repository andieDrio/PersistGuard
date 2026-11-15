"""Allow a replacement certificate to overlap with its predecessor."""

from alembic import op
import sqlalchemy as sa


revision = "0007_credential_rotation"
down_revision = "0006_agent_credentials"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_credentials", sa.Column("superseded_at", sa.DateTime(timezone=True)))
    op.add_column("agent_credentials", sa.Column("replaces_serial", sa.Text()))
    op.create_foreign_key(
        "fk_agent_credentials_predecessor", "agent_credentials", "agent_credentials",
        ["replaces_serial"], ["certificate_serial"],
    )
    op.create_unique_constraint("uq_agent_credentials_replaces_serial", "agent_credentials", ["replaces_serial"])
    op.drop_index("uq_agent_credentials_unrevoked_endpoint", table_name="agent_credentials")
    op.create_index(
        "uq_agent_credentials_current_endpoint", "agent_credentials", ["endpoint_id"], unique=True,
        postgresql_where=sa.text("revoked_at IS NULL AND superseded_at IS NULL"),
    )


def downgrade() -> None:
    op.execute("UPDATE agent_credentials SET revoked_at = superseded_at WHERE revoked_at IS NULL AND superseded_at IS NOT NULL")
    op.drop_index("uq_agent_credentials_current_endpoint", table_name="agent_credentials")
    op.create_index(
        "uq_agent_credentials_unrevoked_endpoint", "agent_credentials", ["endpoint_id"], unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.drop_constraint("uq_agent_credentials_replaces_serial", "agent_credentials", type_="unique")
    op.drop_constraint("fk_agent_credentials_predecessor", "agent_credentials", type_="foreignkey")
    op.drop_column("agent_credentials", "replaces_serial")
    op.drop_column("agent_credentials", "superseded_at")
