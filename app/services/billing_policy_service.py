from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from threading import Lock

from sqlalchemy import inspect, text
from sqlalchemy.orm import joinedload

from app.core.database import SessionLocal, engine, is_sqlite_engine
from app.models.plan import Plan
from app.models.tenant import Tenant


@dataclass
class BillingPolicyEvaluation:
    overdue: bool
    should_block: bool
    overdue_days: int
    grace_days: int
    days_until_block: int
    due_at: datetime | None


class BillingPolicyService:
    DEFAULT_BILLING_PERIOD_DAYS = 30
    DEFAULT_PAYMENT_GRACE_DAYS = 3

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
            tenant_columns = {col["name"] for col in inspector.get_columns("tenants")}
            if {
                "billing_period_days",
                "payment_grace_days",
            }.issubset(plan_columns) and "billing_blocked_at" in tenant_columns:
                cls._schema_ready = True
                return

            with engine.begin() as conn:
                conn.execute(text("SET LOCAL lock_timeout = '3s'"))
                conn.execute(
                    text(
                        "ALTER TABLE plans "
                        "ADD COLUMN IF NOT EXISTS billing_period_days INTEGER NOT NULL DEFAULT 30"
                    )
                )
                conn.execute(
                    text(
                        "ALTER TABLE plans "
                        "ADD COLUMN IF NOT EXISTS payment_grace_days INTEGER NOT NULL DEFAULT 3"
                    )
                )
                conn.execute(
                    text(
                        "ALTER TABLE tenants "
                        "ADD COLUMN IF NOT EXISTS billing_blocked_at TIMESTAMP NULL"
                    )
                )
                conn.execute(
                    text(
                        "UPDATE plans "
                        "SET billing_period_days = 30 "
                        "WHERE billing_period_days IS NULL OR billing_period_days <= 0"
                    )
                )
                conn.execute(
                    text(
                        "UPDATE plans "
                        "SET payment_grace_days = 3 "
                        "WHERE payment_grace_days IS NULL OR payment_grace_days < 0"
                    )
                )
            cls._schema_ready = True

    @classmethod
    def plan_period_days(cls, plan: Plan | None) -> int:
        days = int(getattr(plan, "billing_period_days", 0) or 0)
        return days if days > 0 else cls.DEFAULT_BILLING_PERIOD_DAYS

    @classmethod
    def plan_grace_days(cls, plan: Plan | None) -> int:
        days = int(getattr(plan, "payment_grace_days", 0) or 0)
        return days if days >= 0 else cls.DEFAULT_PAYMENT_GRACE_DAYS

    @staticmethod
    def _coerce_naive_utc(dt: datetime | None) -> datetime | None:
        if not dt:
            return None
        if dt.tzinfo:
            return dt.astimezone().replace(tzinfo=None)
        return dt

    @classmethod
    def resolve_due_at(cls, tenant: Tenant) -> datetime | None:
        current_period_end = cls._coerce_naive_utc(getattr(tenant, "current_period_end", None))
        trial_ends_at = cls._coerce_naive_utc(getattr(tenant, "trial_ends_at", None))
        if current_period_end:
            return current_period_end
        if trial_ends_at:
            return trial_ends_at
        return None

    @classmethod
    def evaluate_tenant(cls, tenant: Tenant, now: datetime | None = None) -> BillingPolicyEvaluation:
        now = cls._coerce_naive_utc(now) or datetime.utcnow()
        due_at = cls.resolve_due_at(tenant)
        grace_days = cls.plan_grace_days(getattr(tenant, "plan", None))
        if not due_at or now <= due_at:
            return BillingPolicyEvaluation(
                overdue=False,
                should_block=False,
                overdue_days=0,
                grace_days=grace_days,
                days_until_block=grace_days,
                due_at=due_at,
            )

        delta_days = int((now - due_at).total_seconds() // 86400) + 1
        overdue_days = max(delta_days, 1)
        should_block = overdue_days > grace_days
        days_until_block = max(grace_days - overdue_days, 0)
        return BillingPolicyEvaluation(
            overdue=True,
            should_block=should_block,
            overdue_days=overdue_days,
            grace_days=grace_days,
            days_until_block=days_until_block,
            due_at=due_at,
        )

    @classmethod
    def build_runtime_alert(cls, tenant: Tenant, now: datetime | None = None) -> dict | None:
        if bool(getattr(tenant, "access_unlimited", False)):
            return None
        evaluation = cls.evaluate_tenant(tenant, now=now)
        if not evaluation.overdue or evaluation.should_block:
            return None

        due_str = evaluation.due_at.strftime("%d/%m/%Y") if evaluation.due_at else "-"
        if evaluation.days_until_block <= 0:
            urgency_text = "Ultimo dia antes do bloqueio automatico."
        else:
            urgency_text = f"Bloqueio em {evaluation.days_until_block} dia(s)."

        message = (
            f"Pagamento em aberto desde {due_str}. "
            f"{urgency_text} Regularize para evitar indisponibilidade de acesso."
        )
        return {
            "type": "warning",
            "message": message,
            "overdue_days": evaluation.overdue_days,
            "days_until_block": evaluation.days_until_block,
            "due_at": evaluation.due_at,
        }

    @classmethod
    def enforce_access_policy(cls, now: datetime | None = None) -> dict[str, int]:
        cls.ensure_schema()
        now = cls._coerce_naive_utc(now) or datetime.utcnow()

        db = SessionLocal()
        processed = 0
        marked_past_due = 0
        blocked = 0
        reactivated = 0
        try:
            tenants = (
                db.query(Tenant)
                .options(joinedload(Tenant.plan))
                .filter(Tenant.access_unlimited.is_(False), Tenant.deleted_at.is_(None))
                .all()
            )
            for tenant in tenants:
                processed += 1
                evaluation = cls.evaluate_tenant(tenant, now=now)
                status = (tenant.subscription_status or "").strip().lower()

                if evaluation.should_block:
                    if tenant.is_active:
                        tenant.is_active = False
                        blocked += 1
                    tenant.subscription_status = "canceled"
                    if not tenant.billing_blocked_at:
                        tenant.billing_blocked_at = now
                    continue

                if evaluation.overdue:
                    if status in {"active", "trial", "past_due"} and tenant.subscription_status != "past_due":
                        tenant.subscription_status = "past_due"
                        marked_past_due += 1
                    continue

                if tenant.billing_blocked_at and tenant.is_active:
                    tenant.billing_blocked_at = None
                    reactivated += 1

            db.commit()
            return {
                "processed": processed,
                "marked_past_due": marked_past_due,
                "blocked": blocked,
                "reactivated": reactivated,
            }
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
