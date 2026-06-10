import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy import desc

from app.core.database import SessionLocal
from app.models.device import Device
from app.models.invoice import Invoice, InvoiceStatus
from app.models.payment import Subscription, SubscriptionStatus
from app.models.plan import Plan
from app.models.tenant import Tenant
from app.models.user import User
from app.services.billing_policy_service import BillingPolicyService
from app.services.mercadopago_service import MercadoPagoError, MercadoPagoService
from app.services.plan_limits_service import PlanLimitsService
from app.services.platform_settings_service import PlatformSettingsService
from app.services.tenant_access_service import TenantAccessService


class BillingController:
    @staticmethod
    def payment_config() -> Dict[str, Any]:
        return PlatformSettingsService.get_payment_config()

    @staticmethod
    def is_checkout_available() -> bool:
        config = BillingController.payment_config()
        return bool((config.get("mercado_pago_access_token") or "").strip())

    @staticmethod
    def public_checkout_error(exc: Exception, fallback: str) -> str:
        message = str(exc or "").strip().lower()
        if isinstance(exc, MercadoPagoError):
            return "Nao foi possivel iniciar o pagamento online no momento. Tente novamente mais tarde ou fale com o suporte comercial."
        if "suporta ate" in message and "dispositivos" in message:
            return str(exc)
        if "mercado_pago_access_token" in message or "pagamento nao configurado" in message:
            return "Pagamento online indisponivel no momento. Fale com o suporte comercial para concluir a assinatura."
        return fallback

    @staticmethod
    def get_available_plans():
        BillingPolicyService.ensure_schema()
        PlanLimitsService.ensure_schema()
        db = SessionLocal()
        try:
            return db.query(Plan).filter(Plan.is_active.is_(True)).order_by(Plan.price_monthly.asc()).all()
        finally:
            db.close()

    @staticmethod
    def get_tenant_device_count(tenant_id: Any) -> int:
        tenant_uuid = BillingController._parse_uuid(tenant_id, "tenant_id")
        db = SessionLocal()
        try:
            return int(db.query(Device.id).filter(Device.tenant_id == tenant_uuid).count() or 0)
        finally:
            db.close()

    @staticmethod
    def get_plan_capacity_map(tenant_id: Any, plans: list[Plan]) -> dict[str, dict[str, Any]]:
        PlanLimitsService.ensure_schema()
        device_count = BillingController.get_tenant_device_count(tenant_id)
        tenant_uuid = BillingController._parse_uuid(tenant_id, "tenant_id")
        db = SessionLocal()
        try:
            user_count = int(
                db.query(User.id)
                .filter(User.tenant_id == tenant_uuid, User.is_active.is_(True))
                .count()
                or 0
            )
            storage_used_bytes = PlanLimitsService.get_storage_used_bytes(db, tenant_uuid)
        finally:
            db.close()

        capacity = {}
        for plan in plans:
            reasons = []
            max_devices = int(plan.max_devices or 0)
            max_users = int(plan.max_users or 0)
            storage_limit_bytes = PlanLimitsService.storage_limit_bytes(plan)
            eligible = True
            if max_devices > 0 and device_count > max_devices:
                eligible = False
                reasons.append(
                    f"Esse plano suporta ate {max_devices} dispositivos e este cliente possui {device_count}."
                )
            if max_users > 0 and user_count > max_users:
                eligible = False
                reasons.append(
                    f"Esse plano suporta ate {max_users} usuarios ativos e este cliente possui {user_count}."
                )
            if storage_limit_bytes > 0 and storage_used_bytes > storage_limit_bytes:
                eligible = False
                reasons.append(
                    "Storage atual acima do limite do plano "
                    f"({PlanLimitsService.format_bytes(storage_used_bytes)} / {PlanLimitsService.format_bytes(storage_limit_bytes)})."
                )
            capacity[str(plan.id)] = {
                "eligible": eligible,
                "device_count": device_count,
                "max_devices": max_devices,
                "user_count": user_count,
                "max_users": max_users,
                "storage_used_bytes": storage_used_bytes,
                "storage_limit_bytes": storage_limit_bytes,
                "reason": " ".join(reasons),
            }
        return capacity

    @staticmethod
    def get_tenant_invoices(tenant_id):
        db = SessionLocal()
        try:
            return (
                db.query(Invoice)
                .filter(Invoice.tenant_id == tenant_id)
                .order_by(desc(Invoice.created_at))
                .all()
            )
        finally:
            db.close()

    @staticmethod
    def _parse_uuid(value: Any, label: str) -> uuid.UUID:
        try:
            return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
        except Exception as exc:
            raise ValueError(f"{label} invalido.") from exc

    @staticmethod
    def _plan_amount_cents(plan: Plan, billing_cycle: str) -> int:
        cycle = (billing_cycle or "monthly").strip().lower()
        if cycle == "yearly":
            if not plan.price_yearly or plan.price_yearly <= 0:
                raise ValueError("Plano nao possui valor anual configurado.")
            return int(plan.price_yearly)
        return int(plan.price_monthly)

    @staticmethod
    def _period_delta_days(plan: Plan, billing_cycle: str) -> int:
        custom_period = BillingPolicyService.plan_period_days(plan)
        if custom_period > 0:
            return custom_period
        return 365 if (billing_cycle or "").strip().lower() == "yearly" else 30

    @staticmethod
    def _build_url(base_url: str, path: str) -> str:
        base = (base_url or "").strip().rstrip("/")
        if not base:
            return path
        return f"{base}{path}"

    @staticmethod
    def _build_notification_url(base_url: str) -> str:
        config = BillingController.payment_config()
        webhook_url = (config.get("mercado_pago_webhook_url") or "").strip()
        if webhook_url:
            return webhook_url
        token = (config.get("mercado_pago_webhook_token") or "").strip()
        url = BillingController._build_url(base_url, "/webhooks/billing/mercadopago")
        if token:
            sep = "&" if "?" in url else "?"
            return f"{url}{sep}token={token}"
        return url

    @staticmethod
    def _new_invoice_number() -> str:
        return f"INV-{uuid.uuid4().hex[:10].upper()}"

    @staticmethod
    def _new_external_reference(tenant_id: uuid.UUID, plan_id: uuid.UUID, invoice_id: uuid.UUID) -> str:
        return f"tenant:{tenant_id}|plan:{plan_id}|invoice:{invoice_id}"

    @staticmethod
    def _parse_external_reference(reference: str) -> Dict[str, str]:
        parts = {}
        raw = (reference or "").strip()
        if not raw:
            return parts
        for item in raw.split("|"):
            if ":" not in item:
                continue
            key, value = item.split(":", 1)
            parts[key.strip()] = value.strip()
        return parts

    @staticmethod
    def _invoice_status_from_payment_status(payment_status: str) -> InvoiceStatus:
        status = (payment_status or "").strip().lower()
        if status == "approved":
            return InvoiceStatus.PAID
        if status in {"pending", "in_process", "in_mediation", "authorized"}:
            return InvoiceStatus.PENDING
        if status in {"cancelled", "cancelled_by_user", "refunded", "charged_back"}:
            return InvoiceStatus.CANCELLED
        return InvoiceStatus.FAILED

    @staticmethod
    def _cancel_existing_subscriptions(db, tenant_id: uuid.UUID):
        active_subs = (
            db.query(Subscription)
            .filter(
                Subscription.tenant_id == tenant_id,
                Subscription.status.in_(
                    [
                        SubscriptionStatus.ACTIVE,
                        SubscriptionStatus.TRIAL,
                        SubscriptionStatus.PAST_DUE,
                    ]
                ),
            )
            .all()
        )
        for sub in active_subs:
            sub.status = SubscriptionStatus.CANCELED
            sub.canceled_at = datetime.utcnow()
            sub.cancel_at_period_end = False

    @staticmethod
    def _activate_subscription(db, tenant: Tenant, plan: Plan, period_start: datetime, period_end: datetime):
        BillingController._cancel_existing_subscriptions(db, tenant.id)
        subscription = Subscription(
            tenant_id=tenant.id,
            plan_id=plan.id,
            status=SubscriptionStatus.ACTIVE,
            current_period_start=period_start,
            current_period_end=period_end,
            provider_subscription_id=f"mercadopago_{uuid.uuid4().hex[:14]}",
        )
        db.add(subscription)
        tenant.plan_id = plan.id
        tenant.subscription_status = SubscriptionStatus.ACTIVE.value
        tenant.current_period_end = period_end
        tenant.is_active = True
        tenant.billing_blocked_at = None
        return subscription

    @staticmethod
    def _build_preference_payload(
        tenant: Tenant,
        plan: Plan,
        invoice: Invoice,
        amount_cents: int,
        tenant_slug: str,
        payer_email: str,
        billing_cycle: str,
        base_url: str,
    ) -> Dict[str, Any]:
        amount = round(amount_cents / 100.0, 2)
        external_reference = BillingController._new_external_reference(tenant.id, plan.id, invoice.id)
        return {
            "items": [
                {
                    "id": str(plan.id),
                    "title": f"Assinatura {plan.name} ({tenant.name})",
                    "description": plan.description or f"Plano {plan.name} - Backup Center",
                    "quantity": 1,
                    "currency_id": "BRL",
                    "unit_price": amount,
                }
            ],
            "payer": {"email": payer_email},
            "external_reference": external_reference,
            "metadata": {
                "tenant_id": str(tenant.id),
                "plan_id": str(plan.id),
                "invoice_id": str(invoice.id),
                "tenant_slug": tenant_slug,
                "billing_cycle": (billing_cycle or "monthly").strip().lower(),
            },
            "notification_url": BillingController._build_notification_url(base_url),
            "back_urls": {
                "success": BillingController._build_url(
                    base_url, f"/tenant/{tenant_slug}/billing/payment-return?result=success"
                ),
                "failure": BillingController._build_url(
                    base_url, f"/tenant/{tenant_slug}/billing/payment-return?result=failure"
                ),
                "pending": BillingController._build_url(
                    base_url, f"/tenant/{tenant_slug}/billing/payment-return?result=pending"
                ),
            },
            "auto_return": "approved",
        }

    @staticmethod
    def create_checkout_for_plan(
        tenant_id: Any,
        tenant_slug: str,
        plan_id: Any,
        payer_email: str,
        base_url: str,
        billing_cycle: str = "monthly",
    ) -> Dict[str, Any]:
        BillingPolicyService.ensure_schema()
        config = BillingController.payment_config()
        access_token = (config.get("mercado_pago_access_token") or "").strip()
        use_sandbox = bool(config.get("mercado_pago_use_sandbox"))
        if not access_token:
            raise ValueError("Pagamento online nao configurado.")

        tenant_uuid = BillingController._parse_uuid(tenant_id, "tenant_id")
        plan_uuid = BillingController._parse_uuid(plan_id, "plan_id")
        db = SessionLocal()
        try:
            tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
            if not tenant:
                raise ValueError("Tenant nao encontrado.")

            plan = db.query(Plan).filter(Plan.id == plan_uuid, Plan.is_active.is_(True)).first()
            if not plan:
                raise ValueError("Plano nao encontrado ou inativo.")
            TenantAccessService.validate_plan_selection(
                plan,
                TenantAccessService.get_device_count(db, tenant.id),
                user_count=TenantAccessService.get_active_user_count(db, tenant.id),
                storage_used_bytes=TenantAccessService.get_storage_used_bytes(db, tenant.id),
            )

            amount_cents = BillingController._plan_amount_cents(plan, billing_cycle)
            now = datetime.utcnow()
            period_end = now + timedelta(days=BillingController._period_delta_days(plan, billing_cycle))
            invoice = Invoice(
                tenant_id=tenant.id,
                invoice_number=BillingController._new_invoice_number(),
                amount=amount_cents,
                currency="BRL",
                period_start=now,
                period_end=period_end,
                status=InvoiceStatus.PENDING,
                due_date=now + timedelta(days=1),
                payment_method="mercado_pago",
            )
            db.add(invoice)
            db.flush()

            payload = BillingController._build_preference_payload(
                tenant=tenant,
                plan=plan,
                invoice=invoice,
                amount_cents=amount_cents,
                tenant_slug=tenant_slug,
                payer_email=payer_email or tenant.email,
                billing_cycle=billing_cycle,
                base_url=base_url,
            )
            mp = MercadoPagoService(access_token)
            preference = mp.create_preference(payload)
            checkout_url = MercadoPagoService.select_checkout_url(
                preference,
                use_sandbox=use_sandbox,
            )
            if not checkout_url:
                raise MercadoPagoError("Mercado Pago nao retornou URL de checkout.")

            invoice.payment_gateway_id = str(preference.get("id") or "")
            db.commit()

            return {
                "checkout_url": checkout_url,
                "invoice_id": str(invoice.id),
                "preference_id": str(preference.get("id") or ""),
            }
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def create_checkout_for_existing_invoice(
        tenant_id: Any,
        tenant_slug: str,
        invoice_id: Any,
        payer_email: str,
        base_url: str,
    ) -> Dict[str, Any]:
        BillingPolicyService.ensure_schema()
        config = BillingController.payment_config()
        access_token = (config.get("mercado_pago_access_token") or "").strip()
        use_sandbox = bool(config.get("mercado_pago_use_sandbox"))
        if not access_token:
            raise ValueError("Pagamento online nao configurado.")

        tenant_uuid = BillingController._parse_uuid(tenant_id, "tenant_id")
        invoice_uuid = BillingController._parse_uuid(invoice_id, "invoice_id")
        db = SessionLocal()
        try:
            tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
            if not tenant:
                raise ValueError("Tenant nao encontrado.")

            invoice = (
                db.query(Invoice)
                .filter(Invoice.id == invoice_uuid, Invoice.tenant_id == tenant.id)
                .first()
            )
            if not invoice:
                raise ValueError("Fatura nao encontrada.")
            if invoice.status == InvoiceStatus.PAID:
                raise ValueError("Essa fatura ja esta paga.")

            plan = db.query(Plan).filter(Plan.id == tenant.plan_id).first() if tenant.plan_id else None
            if not plan:
                # fallback para o menor plano ativo para manter fluxo de pagamento consistente
                plan = db.query(Plan).filter(Plan.is_active.is_(True)).order_by(Plan.price_monthly.asc()).first()
            if not plan:
                raise ValueError("Nenhum plano ativo disponivel para gerar checkout.")

            billing_cycle = "monthly"
            payload = BillingController._build_preference_payload(
                tenant=tenant,
                plan=plan,
                invoice=invoice,
                amount_cents=int(invoice.amount),
                tenant_slug=tenant_slug,
                payer_email=payer_email or tenant.email,
                billing_cycle=billing_cycle,
                base_url=base_url,
            )
            mp = MercadoPagoService(access_token)
            preference = mp.create_preference(payload)
            checkout_url = MercadoPagoService.select_checkout_url(
                preference,
                use_sandbox=use_sandbox,
            )
            if not checkout_url:
                raise MercadoPagoError("Mercado Pago nao retornou URL de checkout.")

            invoice.payment_gateway_id = str(preference.get("id") or "")
            invoice.status = InvoiceStatus.PENDING
            db.commit()
            return {
                "checkout_url": checkout_url,
                "invoice_id": str(invoice.id),
                "preference_id": str(preference.get("id") or ""),
            }
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def process_mercadopago_payment(payment_id: Any, source: str = "manual") -> Dict[str, Any]:
        BillingPolicyService.ensure_schema()
        config = BillingController.payment_config()
        access_token = (config.get("mercado_pago_access_token") or "").strip()
        if not access_token:
            raise ValueError("Pagamento online nao configurado.")
        payment_id = str(payment_id or "").strip()
        if not payment_id:
            raise ValueError("payment_id nao informado.")

        mp = MercadoPagoService(access_token)
        payment = mp.get_payment(payment_id)
        payment_status = str(payment.get("status") or "").lower().strip()
        external_reference = str(payment.get("external_reference") or "").strip()
        refs = BillingController._parse_external_reference(external_reference)
        invoice_id = refs.get("invoice") or refs.get("invoice_id")
        tenant_id = refs.get("tenant") or refs.get("tenant_id")
        plan_id = refs.get("plan") or refs.get("plan_id")

        db = SessionLocal()
        try:
            invoice = None
            if invoice_id:
                try:
                    invoice_uuid = uuid.UUID(invoice_id)
                    invoice = db.query(Invoice).filter(Invoice.id == invoice_uuid).first()
                except Exception:
                    invoice = None
            if not invoice:
                logging.getLogger(__name__).warning(
                    "mercadopago payment without resolvable invoice source=%s payment_id=%s ext_ref=%s",
                    source,
                    payment_id,
                    external_reference,
                )
                return {"handled": False, "reason": "invoice_not_found"}

            invoice_status = BillingController._invoice_status_from_payment_status(payment_status)
            invoice.status = invoice_status
            invoice.payment_gateway_id = payment_id
            invoice.payment_method = f"mercado_pago:{payment.get('payment_type_id') or payment.get('payment_method_id') or 'unknown'}"
            if invoice_status == InvoiceStatus.PAID:
                invoice.paid_at = datetime.utcnow()

            tenant = db.query(Tenant).filter(Tenant.id == invoice.tenant_id).first()
            if not tenant:
                db.commit()
                return {"handled": True, "reason": "tenant_not_found"}

            if invoice_status == InvoiceStatus.PAID:
                plan = None
                if plan_id:
                    try:
                        plan = db.query(Plan).filter(Plan.id == uuid.UUID(plan_id)).first()
                    except Exception:
                        plan = None
                if not plan:
                    if tenant.plan_id:
                        plan = db.query(Plan).filter(Plan.id == tenant.plan_id).first()
                if not plan:
                    plan = db.query(Plan).filter(Plan.is_active.is_(True)).order_by(Plan.price_monthly.asc()).first()

                if not plan:
                    raise ValueError("Pagamento aprovado, mas nenhum plano ativo foi encontrado.")

                period_start = invoice.period_start or datetime.utcnow()
                period_end = invoice.period_end or (period_start + timedelta(days=30))
                BillingController._activate_subscription(
                    db=db,
                    tenant=tenant,
                    plan=plan,
                    period_start=period_start,
                    period_end=period_end,
                )
            elif invoice_status in (InvoiceStatus.FAILED, InvoiceStatus.CANCELLED):
                tenant.subscription_status = SubscriptionStatus.PAST_DUE.value

            db.commit()
            return {
                "handled": True,
                "invoice_id": str(invoice.id),
                "tenant_id": str(tenant.id),
                "payment_status": payment_status,
                "invoice_status": invoice_status.value,
            }
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def get_latest_subscription(tenant_id: Any) -> Optional[Subscription]:
        tenant_uuid = BillingController._parse_uuid(tenant_id, "tenant_id")
        db = SessionLocal()
        try:
            return (
                db.query(Subscription)
                .filter(Subscription.tenant_id == tenant_uuid)
                .order_by(desc(Subscription.created_at))
                .first()
            )
        finally:
            db.close()
