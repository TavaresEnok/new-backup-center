from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import joinedload

from app.core.database import SessionLocal
from app.models.invoice import Invoice, InvoiceStatus
from app.models.tenant import Tenant
from app.models.user import UserRole
from app.services.mercadopago_service import MercadoPagoService
from app.services.platform_settings_service import PlatformSettingsService

bp = Blueprint("superadmin_billing", __name__, url_prefix="/admin/billing")


@bp.before_request
def check_superadmin():
    if session.get("user_role") != UserRole.SUPER_ADMIN.value:
        return redirect(url_for("auth.login"))


@bp.route("/")
def list_billing():
    q = (request.args.get("q") or "").strip()
    subscription = (request.args.get("subscription") or "all").strip().lower()
    focus = (request.args.get("focus") or "all").strip().lower()

    db = SessionLocal()
    try:
        tenants_query = db.query(Tenant).options(joinedload(Tenant.plan)).filter(Tenant.deleted_at.is_(None))
        if q:
            term = f"%{q}%"
            tenants_query = tenants_query.filter(
                or_(
                    Tenant.name.ilike(term),
                    Tenant.slug.ilike(term),
                    Tenant.company_name.ilike(term),
                    Tenant.email.ilike(term),
                )
            )
        if subscription != "all":
            tenants_query = tenants_query.filter(Tenant.subscription_status == subscription)

        if focus == "pending":
            pending_subq = db.query(Invoice.tenant_id).filter(Invoice.status == InvoiceStatus.PENDING).subquery()
            tenants_query = tenants_query.filter(Tenant.id.in_(select(pending_subq.c.tenant_id)))
        elif focus == "failed":
            failed_subq = db.query(Invoice.tenant_id).filter(Invoice.status == InvoiceStatus.FAILED).subquery()
            tenants_query = tenants_query.filter(Tenant.id.in_(select(failed_subq.c.tenant_id)))
        elif focus == "pending_or_failed":
            pending_or_failed_subq = (
                db.query(Invoice.tenant_id)
                .filter(Invoice.status.in_([InvoiceStatus.PENDING, InvoiceStatus.FAILED]))
                .subquery()
            )
            tenants_query = tenants_query.filter(Tenant.id.in_(select(pending_or_failed_subq.c.tenant_id)))
        elif focus == "at_risk":
            at_risk_subq = (
                db.query(Invoice.tenant_id)
                .filter(Invoice.status.in_([InvoiceStatus.PENDING, InvoiceStatus.FAILED]))
                .subquery()
            )
            tenants_query = tenants_query.filter(
                Tenant.subscription_status.in_(["trial", "past_due", "pending_payment", "canceled"]) | Tenant.id.in_(select(at_risk_subq.c.tenant_id))
            )
        elif focus == "active":
            tenants_query = tenants_query.filter(Tenant.subscription_status == "active")
        else:
            focus = "all"
        tenants = tenants_query.order_by(Tenant.name.asc()).all()

        tenant_ids = [t.id for t in tenants]
        invoice_stats = {}
        if tenant_ids:
            rows = (
                db.query(
                    Invoice.tenant_id,
                    func.sum(case((Invoice.status == InvoiceStatus.PAID, 1), else_=0)).label("paid"),
                    func.sum(case((Invoice.status == InvoiceStatus.PENDING, 1), else_=0)).label("pending"),
                    func.sum(case((Invoice.status == InvoiceStatus.FAILED, 1), else_=0)).label("failed"),
                    func.min(
                        case(
                            (
                                Invoice.status.in_([InvoiceStatus.PENDING, InvoiceStatus.FAILED]),
                                Invoice.due_date,
                            ),
                            else_=None,
                        )
                    ).label("next_due"),
                )
                .filter(Invoice.tenant_id.in_(tenant_ids))
                .group_by(Invoice.tenant_id)
                .all()
            )
            invoice_stats = {
                str(tenant_id): {
                    "paid": int(paid or 0),
                    "pending": int(pending or 0),
                    "failed": int(failed or 0),
                    "next_due": next_due,
                }
                for tenant_id, paid, pending, failed, next_due in rows
            }

        tenant_rows = []
        for tenant in tenants:
            key = str(tenant.id)
            stat = invoice_stats.get(
                key,
                {"paid": 0, "pending": 0, "failed": 0, "next_due": None},
            )
            tenant_rows.append(
                {
                    "tenant": tenant,
                    "paid": stat["paid"],
                    "pending": stat["pending"],
                    "failed": stat["failed"],
                    "next_due": stat["next_due"],
                }
            )

        recent_invoices = (
            db.query(Invoice)
            .options(joinedload(Invoice.tenant))
            .join(Tenant, Invoice.tenant_id == Tenant.id)
            .filter(Tenant.deleted_at.is_(None))
            .order_by(Invoice.created_at.desc())
            .limit(80)
            .all()
        )

        stats = {
            "invoices_total": db.query(func.count(Invoice.id)).join(Tenant, Invoice.tenant_id == Tenant.id).filter(Tenant.deleted_at.is_(None)).scalar() or 0,
            "invoices_paid": db.query(func.count(Invoice.id)).join(Tenant, Invoice.tenant_id == Tenant.id).filter(Tenant.deleted_at.is_(None), Invoice.status == InvoiceStatus.PAID).scalar()
            or 0,
            "invoices_pending": db.query(func.count(Invoice.id))
            .join(Tenant, Invoice.tenant_id == Tenant.id)
            .filter(Tenant.deleted_at.is_(None), Invoice.status == InvoiceStatus.PENDING)
            .scalar()
            or 0,
            "invoices_failed": db.query(func.count(Invoice.id)).join(Tenant, Invoice.tenant_id == Tenant.id).filter(Tenant.deleted_at.is_(None), Invoice.status == InvoiceStatus.FAILED).scalar()
            or 0,
            "tenants_active_payment": db.query(func.count(Tenant.id))
            .filter(Tenant.deleted_at.is_(None), Tenant.subscription_status == "active")
            .scalar()
            or 0,
            "tenants_pending_payment": db.query(func.count(Tenant.id))
            .filter(Tenant.deleted_at.is_(None), Tenant.subscription_status.in_(["trial", "past_due", "pending_payment"]))
            .scalar()
            or 0,
        }

        return render_template(
            "superadmin/billing/list.html",
            tenant_rows=tenant_rows,
            recent_invoices=recent_invoices,
            stats=stats,
            q=q,
            subscription=subscription,
            focus=focus,
        )
    finally:
        db.close()


@bp.route("/settings", methods=["GET", "POST"])
def payment_settings():
    if request.method == "POST":
        try:
            PlatformSettingsService.save_payment_config(
                app_public_url=(request.form.get("app_public_url") or "").strip(),
                webhook_url=(request.form.get("mercado_pago_webhook_url") or "").strip(),
                use_sandbox=(request.form.get("mercado_pago_use_sandbox") == "on"),
                access_token=request.form.get("mercado_pago_access_token"),
                public_key=request.form.get("mercado_pago_public_key"),
                webhook_token=request.form.get("mercado_pago_webhook_token"),
                clear_access_token=(request.form.get("clear_access_token") == "on"),
                clear_public_key=(request.form.get("clear_public_key") == "on"),
                clear_webhook_token=(request.form.get("clear_webhook_token") == "on"),
            )
            flash("Configuracao de pagamento salva com sucesso.", "success")
            return redirect(url_for("superadmin_billing.payment_settings"))
        except Exception as exc:
            flash(f"Erro ao salvar configuracao de pagamento: {exc}", "error")

    config = PlatformSettingsService.get_payment_config()
    app_public_url = (config.get("app_public_url") or "").strip()
    webhook_url = (config.get("mercado_pago_webhook_url") or "").strip()
    access_token = (config.get("mercado_pago_access_token") or "").strip()
    public_key = (config.get("mercado_pago_public_key") or "").strip()
    webhook_token = (config.get("mercado_pago_webhook_token") or "").strip()
    sandbox_mode = bool(config.get("mercado_pago_use_sandbox"))

    effective_webhook = webhook_url or (
        f"{app_public_url.rstrip('/')}/webhooks/billing/mercadopago" if app_public_url else None
    )

    setup_items = [
        {
            "name": "APP_PUBLIC_URL",
            "configured": bool(app_public_url),
            "required": True,
            "description": "Base publica usada nos retornos do checkout e no webhook automatico.",
        },
        {
            "name": "MERCADO_PAGO_ACCESS_TOKEN",
            "configured": bool(access_token),
            "required": True,
            "description": "Token privado usado para criar checkout e consultar pagamentos.",
        },
        {
            "name": "MERCADO_PAGO_PUBLIC_KEY",
            "configured": bool(public_key),
            "required": False,
            "description": "Chave publica opcional. So sera necessaria para experiencias de checkout embutido no futuro.",
        },
        {
            "name": "MERCADO_PAGO_WEBHOOK_URL",
            "configured": bool(effective_webhook),
            "required": True,
            "description": "URL de callback para confirmacao automatica. Se vazia, o sistema tenta derivar a partir de APP_PUBLIC_URL.",
        },
        {
            "name": "MERCADO_PAGO_WEBHOOK_TOKEN",
            "configured": bool(webhook_token),
            "required": False,
            "description": "Token adicional para proteger o endpoint de webhook.",
        },
        {
            "name": "MERCADO_PAGO_USE_SANDBOX",
            "configured": True,
            "required": False,
            "description": "Define se o checkout usa ambiente de teste ou producao.",
            "value": "sandbox" if sandbox_mode else "producao",
        },
    ]

    missing_required = [
        item["name"]
        for item in setup_items
        if item.get("required") and not item.get("configured")
    ]

    return render_template(
        "superadmin/billing/settings.html",
        setup_items=setup_items,
        ready=not missing_required,
        missing_required=missing_required,
        effective_webhook=effective_webhook,
        sandbox_mode=sandbox_mode,
        form_data={
            "app_public_url": app_public_url,
            "mercado_pago_webhook_url": webhook_url,
            "mercado_pago_use_sandbox": sandbox_mode,
            "has_access_token": bool(access_token),
            "has_public_key": bool(public_key),
            "has_webhook_token": bool(webhook_token),
        },
    )


@bp.route("/settings/mode", methods=["POST"])
def payment_settings_mode():
    mode = (request.form.get("mode") or "").strip().lower()
    if mode not in {"sandbox", "production"}:
        flash("Modo de pagamento invalido.", "error")
        return redirect(url_for("superadmin_billing.payment_settings"))

    try:
        PlatformSettingsService.set_payment_mode(use_sandbox=(mode == "sandbox"))
        flash(
            "Ambiente de pagamento alterado para Sandbox."
            if mode == "sandbox"
            else "Ambiente de pagamento alterado para Produção.",
            "success",
        )
    except Exception as exc:
        flash(f"Erro ao alternar ambiente de pagamento: {exc}", "error")

    return redirect(url_for("superadmin_billing.payment_settings"))


@bp.route("/settings/test", methods=["POST"])
def payment_settings_test():
    try:
        config = PlatformSettingsService.get_payment_config()
        access_token = (config.get("mercado_pago_access_token") or "").strip()
        if not access_token:
            flash("Defina o Access Token antes de testar a integração.", "warning")
            return redirect(url_for("superadmin_billing.payment_settings"))

        mp = MercadoPagoService(access_token)
        account = mp.get_current_user()
        nickname = account.get("nickname") or account.get("email") or account.get("id") or "conta identificada"
        flash(f"Integração Mercado Pago validada com sucesso: {nickname}", "success")
    except Exception as exc:
        flash(f"Falha ao testar integração do Mercado Pago: {exc}", "error")
    return redirect(url_for("superadmin_billing.payment_settings"))
