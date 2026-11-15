"""Keep live detection definitions and their publication history."""

from alembic import op
import sqlalchemy as sa


revision = "0013_rule_version_history"
down_revision = "0012_detection_rules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("detection_rules", sa.Column("draft_version", sa.Integer(), server_default="1", nullable=False))
    op.add_column("detection_rules", sa.Column("published_version", sa.Integer()))
    op.create_table(
        "published_detection_rules",
        sa.Column("rule_id", sa.Uuid(), sa.ForeignKey("detection_rules.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("field", sa.Text(), nullable=False),
        sa.Column("pattern", sa.Text(), nullable=False),
        sa.Column("score", sa.SmallInteger(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True)),
    )
    op.execute("""INSERT INTO published_detection_rules (rule_id, version, name, source, field, pattern, score)
                  SELECT id, 1, name, source, field, pattern, score FROM detection_rules WHERE enabled""")
    op.execute("UPDATE detection_rules SET published_version = 1 WHERE enabled")
    op.drop_constraint("ck_detection_rules_tested", "detection_rules", type_="check")
    op.create_check_constraint("ck_detection_rules_published", "detection_rules", "NOT enabled OR published_version IS NOT NULL")


def downgrade() -> None:
    op.execute("""UPDATE detection_rules AS draft
                  SET name = live.name, source = live.source, field = live.field, pattern = live.pattern, score = live.score,
                      tested = true, revision = draft.revision + 1
                  FROM published_detection_rules AS live
                  WHERE draft.enabled AND draft.id = live.rule_id AND draft.published_version = live.version""")
    op.drop_constraint("ck_detection_rules_published", "detection_rules", type_="check")
    op.create_check_constraint("ck_detection_rules_tested", "detection_rules", "NOT enabled OR tested")
    op.drop_table("published_detection_rules")
    op.drop_column("detection_rules", "published_version")
    op.drop_column("detection_rules", "draft_version")
