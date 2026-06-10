"""add indexes for core tables

Revision ID: 0001_add_indexes
Revises: 
Create Date: 2026-01-14

"""

from alembic import op

revision = "0001_add_indexes"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_index("idx_backup_device", "backups", ["device_id"])
    op.create_index("idx_backup_created_at", "backups", ["created_at"])
    op.create_index("idx_backup_status", "backups", ["status"])
    op.create_index("idx_backup_device_created", "backups", ["device_id", "created_at"])

    op.create_index("idx_schedule_device", "schedules", ["device_id"])
    op.create_index("idx_schedule_next_run", "schedules", ["next_run_at"])
    op.create_index("idx_schedule_active", "schedules", ["is_active"])

    op.create_index("idx_activity_tenant", "activity_logs", ["tenant_id"])
    op.create_index("idx_activity_created_at", "activity_logs", ["created_at"])
    op.create_index("idx_activity_action", "activity_logs", ["action"])

    op.create_index("idx_report_tenant", "reports", ["tenant_id"])
    op.create_index("idx_report_schedule", "reports", ["schedule"])

    op.create_index("idx_user_tenant", "users", ["tenant_id"])
    op.create_index("idx_user_role", "users", ["role"])


def downgrade():
    op.drop_index("idx_user_role", table_name="users")
    op.drop_index("idx_user_tenant", table_name="users")

    op.drop_index("idx_report_schedule", table_name="reports")
    op.drop_index("idx_report_tenant", table_name="reports")

    op.drop_index("idx_activity_action", table_name="activity_logs")
    op.drop_index("idx_activity_created_at", table_name="activity_logs")
    op.drop_index("idx_activity_tenant", table_name="activity_logs")

    op.drop_index("idx_schedule_active", table_name="schedules")
    op.drop_index("idx_schedule_next_run", table_name="schedules")
    op.drop_index("idx_schedule_device", table_name="schedules")

    op.drop_index("idx_backup_device_created", table_name="backups")
    op.drop_index("idx_backup_status", table_name="backups")
    op.drop_index("idx_backup_created_at", table_name="backups")
    op.drop_index("idx_backup_device", table_name="backups")
