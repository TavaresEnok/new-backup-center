from app.celery_app import celery_app
from app.services.billing_policy_service import BillingPolicyService
import logging


logger = logging.getLogger(__name__)


@celery_app.task
def enforce_tenant_billing_access():
    """
    Aplica politica de cobranca:
    - marca clientes em atraso como past_due durante janela de aviso;
    - bloqueia acesso (tenant.is_active=False) apos o fim da janela;
    - nao remove dados.
    """
    result = BillingPolicyService.enforce_access_policy()
    logger.info(
        "Billing policy aplicada: processed=%s past_due=%s blocked=%s reactivated=%s",
        result.get("processed"),
        result.get("marked_past_due"),
        result.get("blocked"),
        result.get("reactivated"),
    )
    return result
