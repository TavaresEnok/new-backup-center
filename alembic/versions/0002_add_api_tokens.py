"""add api_tokens table

Revision ID: 0002_add_api_tokens
Revises: 0001_add_indexes
Create Date: 2026-02-18

"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID
from alembic import op

revision = "0002_add_api_tokens"
down_revision = "0001_add_indexes"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'api_tokens',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', UUID(as_uuid=True), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('token_prefix', sa.String(12), nullable=False),
        sa.Column('token_hash', sa.String(200), nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False, server_default='true'),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('idx_api_token_tenant', 'api_tokens', ['tenant_id'])
    op.create_index('idx_api_token_prefix', 'api_tokens', ['token_prefix'])


def downgrade():
    op.drop_index('idx_api_token_prefix', table_name='api_tokens')
    op.drop_index('idx_api_token_tenant', table_name='api_tokens')
    op.drop_table('api_tokens')
