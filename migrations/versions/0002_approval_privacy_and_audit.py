"""Encrypt review details and make PostgreSQL audit events append-only."""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("approval_requests", sa.Column("encrypted_arguments", sa.Text(), nullable=True))
    if op.get_bind().dialect.name == "postgresql":
        op.execute("""
            CREATE FUNCTION securemcp_reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'audit events are append only';
            END;
            $$
        """)
        op.execute("""
            CREATE TRIGGER securemcp_audit_append_only BEFORE UPDATE OR DELETE OR TRUNCATE
            ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION securemcp_reject_audit_mutation()
        """)


def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER securemcp_audit_append_only ON audit_events")
        op.execute("DROP FUNCTION securemcp_reject_audit_mutation()")
    op.drop_column("approval_requests", "encrypted_arguments")
