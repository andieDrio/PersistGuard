"""Link local users to verified token identities."""

from alembic import op
import sqlalchemy as sa


revision = "0002_user_identity"
down_revision = "0001_core_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("identity_issuer", sa.Text(collation="C")))
    op.add_column("users", sa.Column("identity_subject", sa.Text(collation="C")))
    op.create_check_constraint(
        "ck_users_identity_pair",
        "users",
        "(identity_issuer IS NULL) = (identity_subject IS NULL)",
    )
    op.create_unique_constraint(
        "uq_users_identity", "users", ["identity_issuer", "identity_subject"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_users_identity", "users", type_="unique")
    op.drop_constraint("ck_users_identity_pair", "users", type_="check")
    op.drop_column("users", "identity_subject")
    op.drop_column("users", "identity_issuer")
