from flask import Blueprint, render_template, session, redirect, url_for, request, flash

from app.core.database import SessionLocal
from app.models.invoice import Invoice
from app.models.tenant import Tenant
from app.models.user import UserRole
from app.services.platform_settings_service import PlatformSettingsService
from app.services.plan_limits_service import PlanLimitsService
from app.web.auth.decorators import login_required, tenant_owner_required
from app.web.billing.controller import BillingController

bp = Blueprint("billing", __name__, url_prefix="/tenant/<tenant_slug>/billing")


def _guard_tenant_access(tenant_slug: str) -> bool:
    return (
        session.get("user_role") == UserRole.SUPER_ADMIN.value
        or session.get("tenant_slug") == tenant_slug
    )


def _request_base_url() -> str:
    config = PlatformSettingsService.get_payment_config()
    if config.get("app_public_url"):
        return str(config["app_public_url"]).rstrip("/")
    return request.url_root.rstrip("/")


@bp.route("/")
@login_required
@tenant_owner_required
def dashboard(tenant_slug):
    if not _guard_tenant_access(tenant_slug):
        return redirect(url_for("auth.login"))

    db = SessionLocal()
    try:
        PlanLimitsService.ensure_schema()
        tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
        if not tenant:
            return "Tenant Not Found", 404

        plans = BillingController.get_available_plans()
        invoices = (
            db.query(Invoice)
            .filter(Invoice.tenant_id == tenant.id)
            .order_by(Invoice.created_at.desc())
            .all()
        )
        pending_invoice = next((inv for inv in invoices if str(getattr(inv.status, "value", inv.status)) == "pending"), None)
        payment_ready = BillingController.is_checkout_available()
        current_device_count = BillingController.get_tenant_device_count(tenant.id)
        plan_capacity = BillingController.get_plan_capacity_map(tenant.id, plans)
        usage_snapshot = PlanLimitsService.build_usage_snapshot(db, tenant)

        return render_template(
            "billing/index.html",
            tenant=tenant,
            plans=plans,
            invoices=invoices,
            pending_invoice=pending_invoice,
            payment_ready=payment_ready,
            current_device_count=current_device_count,
            plan_capacity=plan_capacity,
            usage_snapshot=usage_snapshot,
        )
    finally:
        db.close()


@bp.route("/subscribe/<plan_id>", methods=["POST"])
@login_required
@tenant_owner_required
def subscribe(tenant_slug, plan_id):
    if not _guard_tenant_access(tenant_slug):
        return redirect(url_for("auth.login"))

    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
        if not tenant:
            flash("Tenant nao encontrado.", "error")
            return redirect(url_for("billing.dashboard", tenant_slug=tenant_slug))
    finally:
        db.close()

    billing_cycle = (request.form.get("billing_cycle") or "monthly").strip().lower()

    try:
        result = BillingController.create_checkout_for_plan(
            tenant_id=tenant.id,
            tenant_slug=tenant.slug,
            plan_id=plan_id,
            payer_email=tenant.email,
            base_url=_request_base_url(),
            billing_cycle=billing_cycle,
        )
        return redirect(result["checkout_url"])
    except Exception as exc:
        flash(
            BillingController.public_checkout_error(
                exc,
                "Erro ao iniciar pagamento online. Tente novamente mais tarde.",
            ),
            "error",
        )
        return redirect(url_for("billing.dashboard", tenant_slug=tenant_slug))


@bp.route("/invoice/<invoice_id>/pay", methods=["POST"])
@login_required
@tenant_owner_required
def pay_invoice(tenant_slug, invoice_id):
    if not _guard_tenant_access(tenant_slug):
        return redirect(url_for("auth.login"))

    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
        if not tenant:
            flash("Tenant nao encontrado.", "error")
            return redirect(url_for("billing.dashboard", tenant_slug=tenant_slug))
    finally:
        db.close()

    try:
        result = BillingController.create_checkout_for_existing_invoice(
            tenant_id=tenant.id,
            tenant_slug=tenant.slug,
            invoice_id=invoice_id,
            payer_email=tenant.email,
            base_url=_request_base_url(),
        )
        return redirect(result["checkout_url"])
    except Exception as exc:
        flash(
            BillingController.public_checkout_error(
                exc,
                "Erro ao reabrir pagamento da fatura. Tente novamente mais tarde.",
            ),
            "error",
        )
        return redirect(url_for("billing.dashboard", tenant_slug=tenant_slug))


@bp.route("/payment-return", methods=["GET"])
@login_required
@tenant_owner_required
def payment_return(tenant_slug):
    if not _guard_tenant_access(tenant_slug):
        return redirect(url_for("auth.login"))

    payment_id = (
        request.args.get("payment_id")
        or request.args.get("collection_id")
        or request.args.get("data.id")
    )
    result_hint = (request.args.get("result") or "").strip().lower()

    if payment_id:
        try:
            BillingController.process_mercadopago_payment(payment_id=payment_id, source="return")
            flash("Pagamento processado com sucesso.", "success")
        except Exception:
            flash(
                "Nao foi possivel confirmar o pagamento agora. Se a cobranca ja foi concluida, a assinatura sera atualizada automaticamente apos a confirmacao do gateway.",
                "warning",
            )
    else:
        if result_hint == "pending":
            flash("Pagamento pendente. Assim que for confirmado, a assinatura sera ativada.", "warning")
        elif result_hint == "failure":
            flash("Pagamento nao concluido. Tente novamente.", "error")
        else:
            flash("Retorno de pagamento recebido.", "info")

    return redirect(url_for("billing.dashboard", tenant_slug=tenant_slug))
