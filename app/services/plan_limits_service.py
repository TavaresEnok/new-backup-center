from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from threading import Lock

from sqlalchemy import func, inspect, text
from sqlalchemy.orm import Session

from app.core.database import engine, is_sqlite_engine
from app.models.backup import Backup
from app.models.device import Device
from app.models.plan import Plan
from app.models.tenant import Tenant
from app.models.tenant_usage_metric import TenantUsageMetric
from app.models.user import User


@dataclass
class LimitCheckResult:
    allowed: bool
    reason: str
    used_bytes: int = 0
    limit_bytes: int = 0
    used_count: int = 0
    limit_count: int = 0


class PlanLimitsService:
    DEFAULT_STORAGE_GB = 10
    DEFAULT_DOWNLOAD_GB_MONTH = 20
    BYTES_PER_GB = 1024 * 1024 * 1024
    METRIC_DOWNLOAD_BYTES = "download_bytes"

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
            plan_columns = {col["name"] for col in inspector.get_columns("plans")}
            usage_table_ok = inspector.has_table("tenant_usage_metrics")
            required_plan_columns = {
                "storage_quota_gb",
                "download_quota_gb_month",
                "max_download_rate_mbps",
            }
            if usage_table_ok and required_plan_columns.issubset(plan_columns):
                cls._schema_ready = True
                return

            with engine.begin() as conn:
                conn.execute(text("SET LOCAL lock_timeout = '3s'"))
                conn.execute(
                    text(
                        "ALTER TABLE plans "
                        "ADD COLUMN IF NOT EXISTS storage_quota_gb INTEGER NOT NULL DEFAULT 10"
                    )
                )
                conn.execute(
                    text(
                        "ALTER TABLE plans "
                        "ADD COLUMN IF NOT EXISTS download_quota_gb_month INTEGER NOT NULL DEFAULT 20"
                    )
                )
                conn.execute(
                    text(
                        "ALTER TABLE plans "
                        "ADD COLUMN IF NOT EXISTS max_download_rate_mbps INTEGER NOT NULL DEFAULT 0"
                    )
                )
                conn.execute(
                    text(
                        "UPDATE plans SET storage_quota_gb = :default_value "
                        "WHERE storage_quota_gb IS NULL OR storage_quota_gb < 0"
                    ),
                    {"default_value": cls.DEFAULT_STORAGE_GB},
                )
                conn.execute(
                    text(
                        "UPDATE plans SET download_quota_gb_month = :default_value "
                        "WHERE download_quota_gb_month IS NULL OR download_quota_gb_month < 0"
                    ),
                    {"default_value": cls.DEFAULT_DOWNLOAD_GB_MONTH},
                )
                conn.execute(
                    text(
                        "UPDATE plans SET max_download_rate_mbps = 0 "
                        "WHERE max_download_rate_mbps IS NULL OR max_download_rate_mbps < 0"
                    )
                )
                conn.execute(
                    text(
                        "CREATE TABLE IF NOT EXISTS tenant_usage_metrics ("
                        "id UUID PRIMARY KEY, "
                        "tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, "
                        "metric_key VARCHAR(64) NOT NULL, "
                        "period_key VARCHAR(16) NOT NULL, "
                        "value_bytes BIGINT NOT NULL DEFAULT 0, "
                        "events_count INTEGER NOT NULL DEFAULT 0, "
                        "created_at TIMESTAMP NOT NULL DEFAULT NOW(), "
                        "updated_at TIMESTAMP NOT NULL DEFAULT NOW()"
                        ")"
                    )
                )
                conn.execute(
                    text(
                        "CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_usage_metric_period "
                        "ON tenant_usage_metrics (tenant_id, metric_key, period_key)"
                    )
                )
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS idx_tenant_usage_metric_tenant "
                        "ON tenant_usage_metrics (tenant_id)"
                    )
                )
            cls._schema_ready = True

    @staticmethod
    def is_unlimited_tenant(tenant: Tenant | None) -> bool:
        return bool(getattr(tenant, "access_unlimited", False))

    @staticmethod
    def has_plan_access(tenant: Tenant | None) -> bool:
        if not tenant:
            return False
        if PlanLimitsService.is_unlimited_tenant(tenant):
            return True
        return bool(getattr(tenant, "plan_id", None))

    @staticmethod
    def _as_int(value, default: int = 0, minimum: int = 0) -> int:
        try:
            parsed = int(value)
        except Exception:
            parsed = default
        return parsed if parsed >= minimum else minimum

    @classmethod
    def storage_limit_bytes(cls, plan: Plan | None) -> int:
        if not plan:
            return 0
        gb = cls._as_int(getattr(plan, "storage_quota_gb", cls.DEFAULT_STORAGE_GB), cls.DEFAULT_STORAGE_GB, 0)
        return gb * cls.BYTES_PER_GB

    @classmethod
    def monthly_download_limit_bytes(cls, plan: Plan | None) -> int:
        if not plan:
            return 0
        gb = cls._as_int(
            getattr(plan, "download_quota_gb_month", cls.DEFAULT_DOWNLOAD_GB_MONTH),
            cls.DEFAULT_DOWNLOAD_GB_MONTH,
            0,
        )
        return gb * cls.BYTES_PER_GB

    @staticmethod
    def period_key_month(now: datetime | None = None) -> str:
        current = now or datetime.utcnow()
        return current.strftime("%Y-%m")

    @staticmethod
    def format_bytes(value: int | float | None) -> str:
        size = float(value or 0)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

    @staticmethod
    def get_storage_used_bytes(db: Session, tenant_id) -> int:
        return int(
            db.query(func.coalesce(func.sum(Backup.file_size_bytes), 0))
            .join(Device, Backup.device_id == Device.id)
            .filter(Device.tenant_id == tenant_id)
            .scalar()
            or 0
        )

    @classmethod
    def get_download_used_bytes_current_month(cls, db: Session, tenant_id, now: datetime | None = None) -> int:
        period_key = cls.period_key_month(now=now)
        row = (
            db.query(TenantUsageMetric)
            .filter(
                TenantUsageMetric.tenant_id == tenant_id,
                TenantUsageMetric.metric_key == cls.METRIC_DOWNLOAD_BYTES,
                TenantUsageMetric.period_key == period_key,
            )
            .first()
        )
        return int(getattr(row, "value_bytes", 0) or 0)

    @classmethod
    def check_can_add_device(cls, db: Session, tenant: Tenant) -> LimitCheckResult:
        if cls.is_unlimited_tenant(tenant):
            return LimitCheckResult(allowed=True, reason="ok")
        if not tenant.plan:
            return LimitCheckResult(allowed=False, reason="Cliente sem plano ativo.")
        limit = cls._as_int(getattr(tenant.plan, "max_devices", 0), 0, 0)
        used = int(
            db.query(func.count(Device.id))
            .filter(Device.tenant_id == tenant.id, Device.is_active.isnot(False))
            .scalar()
            or 0
        )
        if limit > 0 and used >= limit:
            return LimitCheckResult(
                allowed=False,
                reason=f"Limite de dispositivos do plano atingido ({used}/{limit}).",
                used_count=used,
                limit_count=limit,
            )
        return LimitCheckResult(allowed=True, reason="ok", used_count=used, limit_count=limit)

    @classmethod
    def check_can_add_user(cls, db: Session, tenant: Tenant) -> LimitCheckResult:
        if cls.is_unlimited_tenant(tenant):
            return LimitCheckResult(allowed=True, reason="ok")
        if not tenant.plan:
            return LimitCheckResult(allowed=False, reason="Cliente sem plano ativo.")
        limit = cls._as_int(getattr(tenant.plan, "max_users", 0), 0, 0)
        used = int(
            db.query(func.count(User.id))
            .filter(User.tenant_id == tenant.id, User.is_active.is_(True))
            .scalar()
            or 0
        )
        if limit > 0 and used >= limit:
            return LimitCheckResult(
                allowed=False,
                reason=f"Limite de usuários do plano atingido ({used}/{limit}).",
                used_count=used,
                limit_count=limit,
            )
        return LimitCheckResult(allowed=True, reason="ok", used_count=used, limit_count=limit)

    @classmethod
    def check_storage_before_backup(cls, db: Session, tenant: Tenant, backup_size_bytes: int) -> LimitCheckResult:
        incoming = max(int(backup_size_bytes or 0), 0)
        if incoming <= 0:
            return LimitCheckResult(allowed=True, reason="ok")
        if cls.is_unlimited_tenant(tenant):
            return LimitCheckResult(allowed=True, reason="ok")
        if not tenant.plan:
            return LimitCheckResult(allowed=False, reason="Cliente sem plano ativo para armazenar backups.")

        limit = cls.storage_limit_bytes(tenant.plan)
        used = cls.get_storage_used_bytes(db, tenant.id)
        if limit > 0 and (used + incoming) > limit:
            reason = (
                "Limite de armazenamento do plano excedido. "
                f"Uso atual {cls.format_bytes(used)} de {cls.format_bytes(limit)}."
            )
            return LimitCheckResult(
                allowed=False,
                reason=reason,
                used_bytes=used,
                limit_bytes=limit,
            )
        return LimitCheckResult(allowed=True, reason="ok", used_bytes=used, limit_bytes=limit)

    @classmethod
    def consume_download_bytes(
        cls,
        db: Session,
        tenant: Tenant,
        download_size_bytes: int,
        now: datetime | None = None,
    ) -> LimitCheckResult:
        size = max(int(download_size_bytes or 0), 0)
        if size <= 0:
            return LimitCheckResult(allowed=True, reason="ok")
        if cls.is_unlimited_tenant(tenant):
            return LimitCheckResult(allowed=True, reason="ok")
        if not tenant.plan:
            return LimitCheckResult(allowed=False, reason="Cliente sem plano ativo para download de backups.")

        period_key = cls.period_key_month(now=now)
        metric = (
            db.query(TenantUsageMetric)
            .filter(
                TenantUsageMetric.tenant_id == tenant.id,
                TenantUsageMetric.metric_key == cls.METRIC_DOWNLOAD_BYTES,
                TenantUsageMetric.period_key == period_key,
            )
            .first()
        )
        if not metric:
            metric = TenantUsageMetric(
                tenant_id=tenant.id,
                metric_key=cls.METRIC_DOWNLOAD_BYTES,
                period_key=period_key,
                value_bytes=0,
                events_count=0,
            )
            db.add(metric)
            db.flush()

        limit = cls.monthly_download_limit_bytes(tenant.plan)
        used = int(metric.value_bytes or 0)
        if limit > 0 and (used + size) > limit:
            return LimitCheckResult(
                allowed=False,
                reason=(
                    "Limite mensal de download do plano excedido. "
                    f"Uso atual {cls.format_bytes(used)} de {cls.format_bytes(limit)}."
                ),
                used_bytes=used,
                limit_bytes=limit,
            )

        metric.value_bytes = used + size
        metric.events_count = int(metric.events_count or 0) + 1
        metric.updated_at = datetime.utcnow()

        return LimitCheckResult(
            allowed=True,
            reason="ok",
            used_bytes=int(metric.value_bytes or 0),
            limit_bytes=limit,
        )

    @classmethod
    def build_usage_snapshot(cls, db: Session, tenant: Tenant, now: datetime | None = None) -> dict:
        has_plan_access = cls.has_plan_access(tenant)
        storage_used = cls.get_storage_used_bytes(db, tenant.id)
        download_used = cls.get_download_used_bytes_current_month(db, tenant.id, now=now)
        storage_limit = 0 if cls.is_unlimited_tenant(tenant) else cls.storage_limit_bytes(tenant.plan)
        download_limit = 0 if cls.is_unlimited_tenant(tenant) else cls.monthly_download_limit_bytes(tenant.plan)
        storage_pct = int(round((storage_used / storage_limit) * 100)) if storage_limit > 0 else 0
        download_pct = int(round((download_used / download_limit) * 100)) if download_limit > 0 else 0
        return {
            "has_plan_access": has_plan_access,
            "storage_used_bytes": storage_used,
            "storage_limit_bytes": storage_limit,
            "storage_used_label": cls.format_bytes(storage_used),
            "storage_limit_label": "Ilimitado" if storage_limit <= 0 else cls.format_bytes(storage_limit),
            "storage_usage_pct": max(0, min(storage_pct, 100)) if storage_limit > 0 else 0,
            "download_used_bytes": download_used,
            "download_limit_bytes": download_limit,
            "download_used_label": cls.format_bytes(download_used),
            "download_limit_label": "Ilimitado" if download_limit <= 0 else cls.format_bytes(download_limit),
            "download_usage_pct": max(0, min(download_pct, 100)) if download_limit > 0 else 0,
            "download_period_key": cls.period_key_month(now=now),
        }
