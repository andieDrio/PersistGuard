"""Store verified device public keys on endpoints."""

from alembic import op
import sqlalchemy as sa


revision = "0005_endpoint_public_keys"
down_revision = "0004_enrollment_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("endpoints", sa.Column("device_public_key", sa.LargeBinary()))
    op.create_unique_constraint(
        "uq_endpoints_org_device_key", "endpoints", ["organization_id", "device_public_key"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_endpoints_org_device_key", "endpoints", type_="unique")
    op.drop_column("endpoints", "device_public_key")
