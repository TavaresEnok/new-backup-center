"""add composite index for activity log tenant/user/time queries

Revision ID: 0003_add_activity_tenant_user_created_index
Revises: 0002_add_api_tokens
Create Date: 2026-05-04
"""

from alembic import op

revision = "0003_add_activity_tenant_user_created_index"
down_revision = "0002_add_api_tokens"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        "idx_activity_tenant_user_created",
        "activity_logs",
        ["tenant_id", "user_id", "created_at"],
    )


def downgrade():
    op.drop_index("idx_activity_tenant_user_created", table_name="activity_logs")

