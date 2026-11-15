"""Store expiring, single-use enrollment token digests."""

from alembic import op
import sqlalchemy as sa


revision = "0004_enrollment_tokens"
down_revision = "0003_audit_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "enrollment_tokens",
        sa.Column("token_hash", sa.LargeBinary(), primary_key=True),
        sa.Column("organization_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.statement_timestamp()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("octet_length(token_hash) = 32", name="ck_enrollment_tokens_hash_length"),
        sa.CheckConstraint("expires_at > created_at", name="ck_enrollment_tokens_expiry"),
    )
    op.create_index("ix_enrollment_tokens_organization_id", "enrollment_tokens", ["organization_id"])


def downgrade() -> None:
    op.drop_table("enrollment_tokens")
