from __future__ import annotations

from datetime import datetime, timedelta
from threading import Lock

from sqlalchemy import func, inspect, text

from app.core.database import engine, is_sqlite_engine
from app.models.backup import Backup
from app.models.device import Device
from app.models.plan import Plan
from app.models.tenant import Tenant
from app.models.user import User


class TenantAccessService:
    UNLIMITED_DEFAULT_SLUGS = {"ajust-consulting"}
    PROTECTED_DEFAULT_SLUGS = {"ajust-consulting"}
    _schema_lock = Lock()
    _schema_ready = False

    @classmethod
    def ensure_schema(cls) -> None:
        if cls._schema_ready:
            return
        with cls._schema_lock:
            if cls._schema_ready:
                return
            if is_sqlite_engine():
                cls._schema_ready = True
                return

            inspector = inspect(engine)
            tenant_columns = {col["name"] for col in inspector.get_columns("tenants")}
            required = {
                "access_unlimited",
                "protected_system_tenant",
                "deleted_at",
                "deleted_by",
                "delete_reason",
                "deleted_was_active",
            }
            if required.issubset(tenant_columns):
                cls._schema_ready = True
                return

            with engine.begin() as conn:
                conn.execute(text("SET LOCAL lock_timeout = '3s'"))
                conn.execute(
                    text(
                        "ALTER TABLE tenants "
                        "ADD COLUMN IF NOT EXISTS access_unlimited BOOLEAN NOT NULL DEFAULT FALSE"
                    )
                )
                conn.execute(
                    text(
                        "ALTER TABLE tenants "
                        "ADD COLUMN IF NOT EXISTS protected_system_tenant BOOLEAN NOT NULL DEFAULT FALSE"
                    )
                )
                conn.execute(
                    text(
                        "ALTER TABLE tenants "
                        "ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP NULL"
                    )
                )
                conn.execute(
                    text(
                        "ALTER TABLE tenants "
                        "ADD COLUMN IF NOT EXISTS deleted_by UUID NULL"
                    )
                )
                conn.execute(
                    text(
                        "ALTER TABLE tenants "
                        "ADD COLUMN IF NOT EXISTS delete_reason TEXT NULL"
                    )
                )
                conn.execute(
                    text(
                        "ALTER TABLE tenants "
                        "ADD COLUMN IF NOT EXISTS deleted_was_active BOOLEAN NOT NULL DEFAULT FALSE"
                    )
                )
            cls._schema_ready = True

    @classmethod
    def apply_builtin_overrides(cls) -> None:
        cls.ensure_schema()
        with engine.begin() as conn:
            for slug in cls.UNLIMITED_DEFAULT_SLUGS:
                conn.execute(
                    text(
                        "UPDATE tenants "
                        "SET access_unlimited = TRUE "
                        "WHERE slug = :slug"
                    ),
                    {"slug": slug},
                )
            for slug in cls.PROTECTED_DEFAULT_SLUGS:
                conn.execute(
                    text(
                        "UPDATE tenants "
                        "SET protected_system_tenant = TRUE "
                        "WHERE slug = :slug"
                    ),
                    {"slug": slug},
                )

    @staticmethod
    def get_device_count(db, tenant_id) -> int:
        return int(
            db.query(Device.id)
            .filter(Device.tenant_id == tenant_id, Device.is_active.isnot(False))
            .count()
            or 0
        )

    @staticmethod
    def get_active_user_count(db, tenant_id) -> int:
        return int(
            db.query(User.id)
            .filter(User.tenant_id == tenant_id, User.is_active.is_(True))
            .count()
            or 0
        )

    @staticmethod
    def get_storage_used_bytes(db, tenant_id) -> int:
        return int(
            db.query(func.coalesce(func.sum(Backup.file_size_bytes), 0))
            .join(Device, Backup.device_id == Device.id)
            .filter(Device.tenant_id == tenant_id)
            .scalar()
            or 0
        )

    @staticmethod
    def get_plan_display_name(tenant: Tenant) -> str:
        if tenant.plan:
            return tenant.plan.name
        if bool(getattr(tenant, "access_unlimited", False)):
            return "Acesso ilimitado"
        return "Sem plano"

    @staticmethod
    def is_deleted(tenant: Tenant) -> bool:
        return bool(getattr(tenant, "deleted_at", None))

    @staticmethod
    def can_operate_without_plan(tenant: Tenant) -> bool:
        return bool(tenant.plan_id or getattr(tenant, "access_unlimited", False))

    @staticmethod
    def validate_plan_selection(
        plan: Plan | None,
        device_count: int,
        user_count: int | None = None,
        storage_used_bytes: int | None = None,
    ) -> None:
        if not plan:
            raise ValueError("Selecione um plano valido.")
        if device_count > int(plan.max_devices or 0):
            raise ValueError(
                f"Esse plano suporta ate {int(plan.max_devices or 0)} dispositivos, mas este cliente possui {device_count}."
            )
        if user_count is not None and user_count > int(plan.max_users or 0):
            raise ValueError(
                f"Esse plano suporta ate {int(plan.max_users or 0)} usuarios ativos, mas este cliente possui {user_count}."
            )
        if storage_used_bytes is not None:
            storage_limit_gb = int(getattr(plan, "storage_quota_gb", 0) or 0)
            if storage_limit_gb > 0:
                storage_limit_bytes = storage_limit_gb * 1024 * 1024 * 1024
                if storage_used_bytes > storage_limit_bytes:
                    used_gb = storage_used_bytes / float(1024 * 1024 * 1024)
                    raise ValueError(
                        f"Storage atual ({used_gb:.2f} GB) acima do limite do plano ({storage_limit_gb} GB)."
                    )

    @staticmethod
    def seed_trial_plan_fields(tenant: Tenant, plan: Plan | None) -> None:
        if not plan:
            return
        tenant.plan_id = plan.id
        tenant.subscription_status = "trial"
        trial_days = int(plan.trial_days or 0)
        tenant.trial_ends_at = datetime.utcnow() + timedelta(days=trial_days) if trial_days > 0 else None

    @staticmethod
    def seed_pending_payment_plan_fields(tenant: Tenant, plan: Plan | None) -> None:
        if not plan:
            return
        tenant.plan_id = plan.id
        tenant.subscription_status = "pending_payment"
        tenant.trial_ends_at = None
        tenant.current_period_end = None
        tenant.billing_blocked_at = None
        tenant.is_active = False
