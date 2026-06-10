from datetime import datetime, timedelta

from flask import Blueprint, redirect, render_template, request, session, url_for
from sqlalchemy import case, func
from sqlalchemy import or_
from sqlalchemy.orm import joinedload

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.activity_log import ActivityLog
from app.models.backup import Backup, BackupStatus
from app.models.device import Device
from app.models.device_type import DeviceType
from app.models.invoice import Invoice, InvoiceStatus
from app.models.payment import Subscription, SubscriptionStatus
from app.models.plan import Plan
from app.models.tenant import Tenant
from app.models.user import User, UserRole
from app.services.platform_settings_service import PlatformSettingsService
from app.services.tenant_access_service import TenantAccessService

bp = Blueprint("superadmin_dashboard", __name__, url_prefix="/admin")


RANGE_OPTIONS = {
    "24h": {
        "label": "Ultimas 24h",
        "duration": timedelta(hours=24),
        "bucket": "hour",
        "points": 24,
    },
    "7d": {
        "label": "Ultimos 7 dias",
        "duration": timedelta(days=7),
        "bucket": "day",
        "points": 7,
    },
    "30d": {
        "label": "Ultimos 30 dias",
        "duration": timedelta(days=30),
        "bucket": "day",
        "points": 30,
    },
}


def _to_reais(cents):
    value = float(cents or 0) / 100.0
    return f"R$ {value:,.2f}".replace(",", "_").replace(".", ",").replace("_", ".")


def _rate(success, total):
    if not total:
        return 0.0
    return round((float(success) / float(total)) * 100.0, 1)


@bp.route("/dashboard")
def dashboard():
    if session.get("user_role") != UserRole.SUPER_ADMIN.value:
        return redirect(url_for("auth.login"))

    selected_range = (request.args.get("range") or "7d").strip().lower()
    if selected_range not in RANGE_OPTIONS:
        selected_range = "7d"
    range_cfg = RANGE_OPTIONS[selected_range]

    db = SessionLocal()
    try:
        now = datetime.utcnow()
        window_duration = range_cfg["duration"]
        window_start = now - window_duration
        prev_window_start = window_start - window_duration

        tenants_total = db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.is_(None)).scalar() or 0
        tenants_active = db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.is_(None), Tenant.is_active.is_(True)).scalar() or 0
        tenants_inactive = max(0, tenants_total - tenants_active)

        users_total = db.query(func.count(User.id)).scalar() or 0
        admin_users_total = db.query(func.count(User.id)).filter(User.role == UserRole.SUPER_ADMIN).scalar() or 0
        tenant_users_total = db.query(func.count(User.id)).filter(User.tenant_id.isnot(None)).scalar() or 0

        devices_total = db.query(func.count(Device.id)).scalar() or 0
        devices_active = db.query(func.count(Device.id)).filter(Device.is_active.is_(True)).scalar() or 0
        avg_devices_per_tenant = round((devices_total / tenants_total), 1) if tenants_total else 0

        backups_total = db.query(func.count(Backup.id)).filter(Backup.created_at >= window_start).scalar() or 0
        backups_success = (
            db.query(func.count(Backup.id))
            .filter(Backup.created_at >= window_start, Backup.status == BackupStatus.SUCCESS)
            .scalar()
            or 0
        )
        backups_failed = (
            db.query(func.count(Backup.id))
            .filter(Backup.created_at >= window_start, Backup.status == BackupStatus.FAILED)
            .scalar()
            or 0
        )

        backups_prev_total = db.query(func.count(Backup.id)).filter(
            Backup.created_at >= prev_window_start,
            Backup.created_at < window_start,
        ).scalar() or 0
        backups_prev_success = (
            db.query(func.count(Backup.id))
            .filter(
                Backup.created_at >= prev_window_start,
                Backup.created_at < window_start,
                Backup.status == BackupStatus.SUCCESS,
            )
            .scalar()
            or 0
        )
        backups_success_rate = _rate(backups_success, backups_total)
        backups_prev_success_rate = _rate(backups_prev_success, backups_prev_total)
        backups_rate_delta = round(backups_success_rate - backups_prev_success_rate, 1)

        invoices_pending = db.query(func.count(Invoice.id)).filter(Invoice.status == InvoiceStatus.PENDING).scalar() or 0
        invoices_failed = db.query(func.count(Invoice.id)).filter(Invoice.status == InvoiceStatus.FAILED).scalar() or 0
        invoices_paid = db.query(func.count(Invoice.id)).filter(Invoice.status == InvoiceStatus.PAID).scalar() or 0

        invoices_period_total = db.query(func.count(Invoice.id)).filter(Invoice.created_at >= window_start).scalar() or 0
        invoices_period_paid = (
            db.query(func.count(Invoice.id))
            .filter(Invoice.created_at >= window_start, Invoice.status == InvoiceStatus.PAID)
            .scalar()
            or 0
        )
        invoices_period_pending = (
            db.query(func.count(Invoice.id))
            .filter(Invoice.created_at >= window_start, Invoice.status == InvoiceStatus.PENDING)
            .scalar()
            or 0
        )
        invoices_period_failed = (
            db.query(func.count(Invoice.id))
            .filter(Invoice.created_at >= window_start, Invoice.status == InvoiceStatus.FAILED)
            .scalar()
            or 0
        )

        invoices_collection_rate = _rate(invoices_period_paid, invoices_period_total)

        pending_amount_cents = (
            db.query(func.coalesce(func.sum(Invoice.amount), 0))
            .filter(Invoice.status == InvoiceStatus.PENDING)
            .scalar()
            or 0
        )
        failed_amount_cents = (
            db.query(func.coalesce(func.sum(Invoice.amount), 0))
            .filter(Invoice.status == InvoiceStatus.FAILED)
            .scalar()
            or 0
        )

        subscriptions_active = (
            db.query(func.count(Subscription.id)).filter(Subscription.status == SubscriptionStatus.ACTIVE).scalar() or 0
        )
        subscriptions_past_due = (
            db.query(func.count(Subscription.id)).filter(Subscription.status == SubscriptionStatus.PAST_DUE).scalar() or 0
        )
        subscriptions_trial = (
            db.query(func.count(Subscription.id)).filter(Subscription.status == SubscriptionStatus.TRIAL).scalar() or 0
        )

        tenants_payment_active = (
            db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.is_(None), Tenant.subscription_status == SubscriptionStatus.ACTIVE.value).scalar() or 0
        )
        tenants_payment_pending = (
            db.query(func.count(Tenant.id))
            .filter(
                Tenant.deleted_at.is_(None),
                Tenant.subscription_status.in_(
                    [SubscriptionStatus.TRIAL.value, SubscriptionStatus.PAST_DUE.value, "pending_payment"]
                )
            )
            .scalar()
            or 0
        )
        tenants_payment_canceled = (
            db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.is_(None), Tenant.subscription_status == SubscriptionStatus.CANCELED.value).scalar() or 0
        )

        trial_expiring_7d = (
            db.query(func.count(Tenant.id))
            .filter(
                Tenant.subscription_status == SubscriptionStatus.TRIAL.value,
                Tenant.deleted_at.is_(None),
                Tenant.trial_ends_at.isnot(None),
                Tenant.trial_ends_at >= now,
                Tenant.trial_ends_at <= (now + timedelta(days=7)),
            )
            .scalar()
            or 0
        )

        plans_total = db.query(func.count(Plan.id)).scalar() or 0
        plans_active = db.query(func.count(Plan.id)).filter(Plan.is_active.is_(True)).scalar() or 0

        plan_usage_rows = (
            db.query(Plan.name, func.count(Tenant.id))
            .outerjoin(Tenant, (Tenant.plan_id == Plan.id) & Tenant.deleted_at.is_(None))
            .group_by(Plan.id, Plan.name)
            .order_by(func.count(Tenant.id).desc(), Plan.name.asc())
            .all()
        )
        plan_usage = [{"name": name, "tenants": int(count or 0)} for name, count in plan_usage_rows]
        tenants_without_plan = (
            db.query(func.count(Tenant.id))
            .filter(Tenant.deleted_at.is_(None), Tenant.plan_id.is_(None), Tenant.access_unlimited.is_(False))
            .scalar()
            or 0
        )

        mrr_cents = (
            db.query(func.coalesce(func.sum(Plan.price_monthly), 0))
            .select_from(Tenant)
            .join(Plan, Tenant.plan_id == Plan.id)
            .filter(Tenant.deleted_at.is_(None), Tenant.subscription_status == SubscriptionStatus.ACTIVE.value)
            .scalar()
            or 0
        )

        current_30d_start = now - timedelta(days=30)
        previous_30d_start = now - timedelta(days=60)
        new_tenants_30d = db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.is_(None), Tenant.created_at >= current_30d_start).scalar() or 0
        prev_tenants_30d = (
            db.query(func.count(Tenant.id))
            .filter(Tenant.deleted_at.is_(None), Tenant.created_at >= previous_30d_start, Tenant.created_at < current_30d_start)
            .scalar()
            or 0
        )
        tenants_growth_delta = int(new_tenants_30d - prev_tenants_30d)
        tenants_growth_pct = None
        if prev_tenants_30d > 0:
            tenants_growth_pct = round(((new_tenants_30d - prev_tenants_30d) / prev_tenants_30d) * 100.0, 1)

        bucket = range_cfg["bucket"]
        if bucket == "hour":
            backup_bucket_expr = func.date_trunc("hour", func.coalesce(Backup.started_at, Backup.created_at))
            invoice_bucket_expr = func.date_trunc("hour", Invoice.created_at)
        else:
            backup_bucket_expr = func.date_trunc("day", func.coalesce(Backup.started_at, Backup.created_at))
            invoice_bucket_expr = func.date_trunc("day", Invoice.created_at)

        backup_grouped = (
            db.query(backup_bucket_expr.label("bucket"), Backup.status, func.count(Backup.id))
            .filter(func.coalesce(Backup.started_at, Backup.created_at) >= window_start)
            .group_by(backup_bucket_expr, Backup.status)
            .all()
        )
        backup_map = {}
        for bucket_dt, status, count in backup_grouped:
            key = bucket_dt.strftime("%Y-%m-%d %H:00") if bucket == "hour" else bucket_dt.strftime("%Y-%m-%d")
            backup_map.setdefault(key, {"success": 0, "failed": 0})
            value = str(status)
            if value == BackupStatus.SUCCESS.value:
                backup_map[key]["success"] = int(count or 0)
            elif value == BackupStatus.FAILED.value:
                backup_map[key]["failed"] = int(count or 0)

        invoice_grouped = (
            db.query(invoice_bucket_expr.label("bucket"), Invoice.status, func.count(Invoice.id))
            .filter(Invoice.created_at >= window_start)
            .group_by(invoice_bucket_expr, Invoice.status)
            .all()
        )
        invoice_map = {}
        for bucket_dt, status, count in invoice_grouped:
            key = bucket_dt.strftime("%Y-%m-%d %H:00") if bucket == "hour" else bucket_dt.strftime("%Y-%m-%d")
            invoice_map.setdefault(key, {"paid": 0, "pending": 0, "failed": 0})
            value = str(status)
            if value == InvoiceStatus.PAID.value:
                invoice_map[key]["paid"] = int(count or 0)
            elif value == InvoiceStatus.PENDING.value:
                invoice_map[key]["pending"] = int(count or 0)
            elif value == InvoiceStatus.FAILED.value:
                invoice_map[key]["failed"] = int(count or 0)

        chart_labels = []
        backup_success_series = []
        backup_failed_series = []
        invoice_paid_series = []
        invoice_pending_series = []
        invoice_failed_series = []

        points = range_cfg["points"]
        for i in range(points - 1, -1, -1):
            if bucket == "hour":
                slot = (now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0)
                key = slot.strftime("%Y-%m-%d %H:00")
                label = slot.strftime("%Hh")
            else:
                slot = (now - timedelta(days=i)).date()
                key = slot.strftime("%Y-%m-%d")
                label = slot.strftime("%d/%m")

            chart_labels.append(label)
            b_item = backup_map.get(key, {"success": 0, "failed": 0})
            backup_success_series.append(b_item["success"])
            backup_failed_series.append(b_item["failed"])

            inv_item = invoice_map.get(key, {"paid": 0, "pending": 0, "failed": 0})
            invoice_paid_series.append(inv_item["paid"])
            invoice_pending_series.append(inv_item["pending"])
            invoice_failed_series.append(inv_item["failed"])

        payment_distribution = {
            "active": int(tenants_payment_active),
            "pending": int(tenants_payment_pending),
            "canceled": int(tenants_payment_canceled),
        }

        payment_config = PlatformSettingsService.get_payment_config()
        payment_setup = {
            "public_url": bool(payment_config.get("app_public_url")),
            "mp_access_token": bool(payment_config.get("mercado_pago_access_token")),
            "mp_webhook_token": bool(payment_config.get("mercado_pago_webhook_token")),
            "mp_webhook_url": bool(payment_config.get("mercado_pago_webhook_url")),
        }
        payment_setup["ready"] = (
            payment_setup["public_url"] and payment_setup["mp_access_token"] and payment_setup["mp_webhook_token"]
        )

        device_count_by_tenant = {
            str(tid): int(count or 0)
            for tid, count in db.query(Device.tenant_id, func.count(Device.id)).group_by(Device.tenant_id).all()
        }
        user_count_by_tenant = {
            str(tid): int(count or 0)
            for tid, count in db.query(User.tenant_id, func.count(User.id))
            .filter(User.tenant_id.isnot(None))
            .group_by(User.tenant_id)
            .all()
        }
        admin_user_count_by_tenant = {
            str(tid): int(count or 0)
            for tid, count in db.query(User.tenant_id, func.count(User.id))
            .filter(
                User.tenant_id.isnot(None),
                User.role.in_([UserRole.TENANT_OWNER, UserRole.TENANT_ADMIN]),
            )
            .group_by(User.tenant_id)
            .all()
        }

        backup_by_tenant_rows = (
            db.query(
                Device.tenant_id,
                func.sum(case((Backup.status == BackupStatus.SUCCESS, 1), else_=0)).label("success_period"),
                func.sum(case((Backup.status == BackupStatus.FAILED, 1), else_=0)).label("failed_period"),
            )
            .join(Backup, Backup.device_id == Device.id)
            .filter(Backup.created_at >= window_start)
            .group_by(Device.tenant_id)
            .all()
        )
        backup_by_tenant = {
            str(tid): {"success_period": int(success_period or 0), "failed_period": int(failed_period or 0)}
            for tid, success_period, failed_period in backup_by_tenant_rows
        }

        invoice_by_tenant_rows = (
            db.query(
                Invoice.tenant_id,
                func.sum(case((Invoice.status == InvoiceStatus.PAID, 1), else_=0)).label("paid"),
                func.sum(case((Invoice.status == InvoiceStatus.PENDING, 1), else_=0)).label("pending"),
                func.sum(case((Invoice.status == InvoiceStatus.FAILED, 1), else_=0)).label("failed"),
            )
            .group_by(Invoice.tenant_id)
            .all()
        )
        invoice_by_tenant = {
            str(tid): {"paid": int(paid or 0), "pending": int(pending or 0), "failed": int(failed or 0)}
            for tid, paid, pending, failed in invoice_by_tenant_rows
        }

        all_tenants = db.query(Tenant).filter(Tenant.deleted_at.is_(None)).order_by(Tenant.created_at.desc()).all()

        tenant_rows = []
        risk_rows = []
        for tenant in all_tenants:
            tid = str(tenant.id)
            usage = backup_by_tenant.get(tid, {"success_period": 0, "failed_period": 0})
            inv = invoice_by_tenant.get(tid, {"paid": 0, "pending": 0, "failed": 0})

            row = {
                "id": tid,
                "name": tenant.name,
                "slug": tenant.slug,
                "email": tenant.email,
                "is_active": bool(tenant.is_active),
                "subscription_status": (tenant.subscription_status or "unknown").lower(),
                "plan_name": TenantAccessService.get_plan_display_name(tenant),
                "devices_count": device_count_by_tenant.get(tid, 0),
                "users_count": user_count_by_tenant.get(tid, 0),
                "admin_users_count": admin_user_count_by_tenant.get(tid, 0),
                "backup_success_period": usage["success_period"],
                "backup_failed_period": usage["failed_period"],
                "invoice_paid": inv["paid"],
                "invoice_pending": inv["pending"],
                "invoice_failed": inv["failed"],
                "created_at": tenant.created_at,
            }

            risk_score = 0
            if row["subscription_status"] == "past_due":
                risk_score += 70
            elif row["subscription_status"] == "canceled":
                risk_score += 100
            elif row["subscription_status"] == "trial":
                risk_score += 20
            if row["invoice_failed"] > 0:
                risk_score += 35
            if row["invoice_pending"] > 0:
                risk_score += 20
            if row["backup_failed_period"] > row["backup_success_period"] and row["backup_failed_period"] > 0:
                risk_score += 20
            if row["devices_count"] > 0 and row["backup_success_period"] == 0 and row["backup_failed_period"] == 0:
                risk_score += 10
            row["risk_score"] = risk_score
            tenant_rows.append(row)

            if risk_score > 0:
                risk_copy = dict(row)
                risk_rows.append(risk_copy)

        recent_tenants = tenant_rows[:12]
        risk_tenants = sorted(risk_rows, key=lambda x: x["risk_score"], reverse=True)[:12]
        top_activity_tenants = sorted(
            tenant_rows,
            key=lambda x: (x["devices_count"], x["backup_success_period"] + x["backup_failed_period"]),
            reverse=True,
        )[:12]

        activities = (
            db.query(ActivityLog)
            .options(joinedload(ActivityLog.tenant), joinedload(ActivityLog.user))
            .order_by(ActivityLog.created_at.desc())
            .limit(20)
            .all()
        )
        recent_activities = [
            {
                "action": item.action,
                "details": item.details,
                "tenant_name": item.tenant.name if item.tenant else "Plataforma",
                "user_name": item.user.full_name if item.user else "Sistema",
                "created_at": item.created_at,
            }
            for item in activities
        ]

        tenants_without_devices_subq = (
            db.query(Tenant.id)
            .outerjoin(Device, Device.tenant_id == Tenant.id)
            .filter(Tenant.deleted_at.is_(None))
            .group_by(Tenant.id)
            .having(func.count(Device.id) == 0)
            .subquery()
        )
        tenants_without_devices = db.query(func.count()).select_from(tenants_without_devices_subq).scalar() or 0

        tenants_without_admin_subq = (
            db.query(Tenant.id)
            .outerjoin(
                User,
                (User.tenant_id == Tenant.id)
                & (User.role.in_([UserRole.TENANT_OWNER, UserRole.TENANT_ADMIN])),
            )
            .filter(Tenant.deleted_at.is_(None))
            .group_by(Tenant.id)
            .having(func.count(User.id) == 0)
            .subquery()
        )
        tenants_without_admin = db.query(func.count()).select_from(tenants_without_admin_subq).scalar() or 0

        alerts = []
        if not payment_setup["ready"]:
            alerts.append(
                {
                    "severity": "critical",
                    "title": "Integracao de pagamento incompleta",
                    "description": "Mercado Pago ainda nao esta 100% configurado no ambiente atual.",
                    "action_label": "Abrir configuracao",
                    "action_url": url_for("superadmin_billing.payment_settings"),
                }
            )
        if tenants_payment_pending > 0:
            alerts.append(
                {
                    "severity": "critical",
                    "title": f"{tenants_payment_pending} cliente(s) com pagamento pendente",
                    "description": "Clientes em trial vencendo ou past_due exigem acao comercial imediata.",
                    "action_label": "Abrir cobranca",
                    "action_url": url_for("superadmin_billing.list_billing", focus="pending"),
                }
            )
        if invoices_failed > 0:
            alerts.append(
                {
                    "severity": "critical",
                    "title": f"{invoices_failed} fatura(s) com falha",
                    "description": "Falhas de cobranca impactam diretamente o MRR e inadimplencia.",
                    "action_label": "Investigar",
                    "action_url": url_for("superadmin_billing.list_billing", focus="failed"),
                }
            )
        if trial_expiring_7d > 0:
            alerts.append(
                {
                    "severity": "attention",
                    "title": f"{trial_expiring_7d} trial(s) vencendo em 7 dias",
                    "description": "Momento ideal para contato comercial e conversao de plano.",
                    "action_label": "Abrir clientes",
                    "action_url": url_for("superadmin_tenants.list_tenants", subscription="trial"),
                }
            )
        if tenants_without_plan > 0:
            alerts.append(
                {
                    "severity": "attention",
                    "title": f"{tenants_without_plan} cliente(s) sem plano",
                    "description": "Clientes ativos sem plano podem burlar limites e faturamento.",
                    "action_label": "Corrigir planos",
                    "action_url": url_for("superadmin_tenants.list_tenants", ops="no_plan"),
                }
            )
        if backups_failed > backups_success and backups_total > 0:
            alerts.append(
                {
                    "severity": "attention",
                    "title": "Falhas de backup acima de sucessos no periodo",
                    "description": "Indicador de degradacao operacional nos tenants.",
                    "action_label": "Ver top atividade",
                    "action_url": url_for("superadmin_tenants.list_tenants", ops="payment_risk"),
                }
            )

        stats = {
            "tenants_total": int(tenants_total),
            "tenants_active": int(tenants_active),
            "tenants_inactive": int(tenants_inactive),
            "users_total": int(users_total),
            "admin_users_total": int(admin_users_total),
            "tenant_users_total": int(tenant_users_total),
            "devices_total": int(devices_total),
            "devices_active": int(devices_active),
            "avg_devices_per_tenant": avg_devices_per_tenant,
            "backups_total": int(backups_total),
            "backups_success": int(backups_success),
            "backups_failed": int(backups_failed),
            "backups_success_rate": backups_success_rate,
            "backups_rate_delta": backups_rate_delta,
            "invoices_pending": int(invoices_pending),
            "invoices_failed": int(invoices_failed),
            "invoices_paid": int(invoices_paid),
            "invoices_period_total": int(invoices_period_total),
            "invoices_period_paid": int(invoices_period_paid),
            "invoices_period_pending": int(invoices_period_pending),
            "invoices_period_failed": int(invoices_period_failed),
            "invoices_collection_rate": invoices_collection_rate,
            "subscriptions_active": int(subscriptions_active),
            "subscriptions_past_due": int(subscriptions_past_due),
            "subscriptions_trial": int(subscriptions_trial),
            "tenants_payment_active": int(tenants_payment_active),
            "tenants_payment_pending": int(tenants_payment_pending),
            "tenants_payment_canceled": int(tenants_payment_canceled),
            "trial_expiring_7d": int(trial_expiring_7d),
            "plans_total": int(plans_total),
            "plans_active": int(plans_active),
            "tenants_without_plan": int(tenants_without_plan),
            "mrr": _to_reais(mrr_cents),
            "new_tenants_30d": int(new_tenants_30d),
            "prev_tenants_30d": int(prev_tenants_30d),
            "tenants_growth_delta": tenants_growth_delta,
            "tenants_growth_pct": tenants_growth_pct,
            "revenue_at_risk": _to_reais(pending_amount_cents + failed_amount_cents),
            "pending_amount": _to_reais(pending_amount_cents),
            "failed_amount": _to_reais(failed_amount_cents),
            "tenants_without_devices": int(tenants_without_devices),
            "tenants_without_admin": int(tenants_without_admin),
            "risk_tenants_count": len(risk_tenants),
        }

        charts = {
            "labels": chart_labels,
            "backup_success": backup_success_series,
            "backup_failed": backup_failed_series,
            "invoice_paid": invoice_paid_series,
            "invoice_pending": invoice_pending_series,
            "invoice_failed": invoice_failed_series,
            "payment_distribution": payment_distribution,
        }

        links = {
            "risk_clients": url_for("superadmin_billing.list_billing", focus="at_risk"),
            "revenue_risk": url_for("superadmin_billing.list_billing", focus="pending_or_failed"),
            "period_failures": url_for("superadmin_billing.list_billing", focus="failed"),
            "mrr_active": url_for("superadmin_billing.list_billing", focus="active"),
            "clients_total": url_for("superadmin_tenants.list_tenants"),
            "devices_total": url_for("superadmin_tenants.list_tenants", sort="created_desc"),
            "admin_users": url_for("superadmin_users.list_users", scope="platform"),
            "backup_total": url_for("superadmin_tenants.list_tenants", ops="payment_risk"),
            "invoices_period": url_for("superadmin_billing.list_billing"),
            "trial_expiring": url_for("superadmin_tenants.list_tenants", subscription="trial"),
            "without_plan": url_for("superadmin_tenants.list_tenants", ops="no_plan"),
            "growth_clients": url_for("superadmin_tenants.list_tenants", sort="created_desc"),
            "manage_tenants": url_for("superadmin_tenants.list_tenants"),
            "manage_users": url_for("superadmin_users.list_users"),
            "manage_billing": url_for("superadmin_billing.list_billing"),
            "payment_settings": url_for("superadmin_billing.payment_settings"),
            "manage_types": url_for("superadmin_device_types.list_types"),
            "without_devices": url_for("superadmin_tenants.list_tenants", ops="no_devices"),
            "without_admin": url_for("superadmin_tenants.list_tenants", ops="no_admin"),
        }

        return render_template(
            "superadmin/dashboard.html",
            stats=stats,
            range_options={
                key: value["label"] for key, value in RANGE_OPTIONS.items()
            },
            selected_range=selected_range,
            range_label=range_cfg["label"],
            recent_tenants=recent_tenants,
            risk_tenants=risk_tenants,
            top_activity_tenants=top_activity_tenants,
            recent_activities=recent_activities,
            alerts=alerts,
            plan_usage=plan_usage,
            payment_setup=payment_setup,
            charts=charts,
            links=links,
            tenant_rows=tenant_rows,
        )
    finally:
        db.close()


@bp.route("/")
def admin_root():
    if session.get("user_role") != UserRole.SUPER_ADMIN.value:
        return redirect(url_for("auth.login"))
    return redirect(url_for("superadmin_dashboard.dashboard"))


@bp.route("/search")
def search():
    if session.get("user_role") != UserRole.SUPER_ADMIN.value:
        return redirect(url_for("auth.login"))

    q = (request.args.get("q") or "").strip()
    db = SessionLocal()
    try:
        tenant_results = []
        user_results = []
        plan_results = []
        type_results = []
        invoice_results = []

        if q:
            term = f"%{q}%"
            tenants = (
                db.query(Tenant)
                .filter(
                    Tenant.deleted_at.is_(None),
                    or_(
                        Tenant.name.ilike(term),
                        Tenant.slug.ilike(term),
                        Tenant.company_name.ilike(term),
                        Tenant.email.ilike(term),
                    )
                )
                .order_by(Tenant.name.asc())
                .limit(8)
                .all()
            )
            tenant_results = [
                {
                    "title": tenant.name,
                    "subtitle": f"{tenant.slug} • {tenant.email}",
                    "url": url_for("superadmin_tenants.view_tenant", tenant_id=tenant.id),
                }
                for tenant in tenants
            ]

            users = (
                db.query(User)
                .options(joinedload(User.tenant))
                .outerjoin(Tenant, User.tenant_id == Tenant.id)
                .filter(
                    or_(
                        User.full_name.ilike(term),
                        User.email.ilike(term),
                        Tenant.name.ilike(term),
                        Tenant.slug.ilike(term),
                    )
                )
                .order_by(User.created_at.desc())
                .limit(8)
                .all()
            )
            user_results = [
                {
                    "title": user.full_name,
                    "subtitle": f"{user.email} • {(user.tenant.name if user.tenant else 'Plataforma')}",
                    "url": url_for("superadmin_users.edit_user", user_id=user.id),
                }
                for user in users
            ]

            plans = (
                db.query(Plan)
                .filter(
                    or_(
                        Plan.name.ilike(term),
                        Plan.slug.ilike(term),
                        Plan.description.ilike(term),
                    )
                )
                .order_by(Plan.name.asc())
                .limit(6)
                .all()
            )
            plan_results = [
                {
                    "title": plan.name,
                    "subtitle": f"{plan.slug} • R$ {float(plan.price_monthly or 0) / 100.0:.2f}/mes",
                    "url": url_for("superadmin_plans.edit_plan", plan_id=plan.id),
                }
                for plan in plans
            ]

            device_types = (
                db.query(DeviceType)
                .filter(
                    or_(
                        DeviceType.name.ilike(term),
                        DeviceType.slug.ilike(term),
                        DeviceType.script_name.ilike(term),
                    )
                )
                .order_by(DeviceType.name.asc())
                .limit(8)
                .all()
            )
            type_results = [
                {
                    "title": dev_type.name,
                    "subtitle": f"{dev_type.script_name} • {'Telnet' if dev_type.use_telnet else 'SSH'}",
                    "url": url_for("superadmin_device_types.edit_type", type_id=dev_type.id),
                }
                for dev_type in device_types
            ]

            invoices = (
                db.query(Invoice)
                .options(joinedload(Invoice.tenant))
                .outerjoin(Tenant, Invoice.tenant_id == Tenant.id)
                .filter(
                    or_(
                        Invoice.invoice_number.ilike(term),
                        Tenant.name.ilike(term),
                        Tenant.slug.ilike(term),
                    )
                )
                .order_by(Invoice.created_at.desc())
                .limit(8)
                .all()
            )
            invoice_results = [
                {
                    "title": invoice.invoice_number,
                    "subtitle": f"{invoice.tenant.name if invoice.tenant else '-'} • {invoice.status.value}",
                    "url": url_for("superadmin_billing.list_billing", q=invoice.invoice_number),
                }
                for invoice in invoices
            ]

        total_results = (
            len(tenant_results)
            + len(user_results)
            + len(plan_results)
            + len(type_results)
            + len(invoice_results)
        )

        return render_template(
            "superadmin/search.html",
            q=q,
            total_results=total_results,
            tenant_results=tenant_results,
            user_results=user_results,
            plan_results=plan_results,
            type_results=type_results,
            invoice_results=invoice_results,
        )
    finally:
        db.close()
