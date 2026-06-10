import logging
from typing import Any, Dict, Optional

import requests


class MercadoPagoError(Exception):
    pass


class MercadoPagoService:
    BASE_URL = "https://api.mercadopago.com"

    def __init__(self, access_token: str, timeout_seconds: int = 20):
        self.access_token = (access_token or "").strip()
        self.timeout_seconds = timeout_seconds
        if not self.access_token:
            raise MercadoPagoError("MERCADO_PAGO_ACCESS_TOKEN nao configurado.")

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def create_preference(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.BASE_URL}/checkout/preferences"
        response = requests.post(
            url,
            headers=self._headers(),
            json=payload,
            timeout=self.timeout_seconds,
        )
        if response.status_code >= 400:
            logging.getLogger(__name__).error(
                "mercadopago preference error status=%s body=%s",
                response.status_code,
                response.text[:1500],
            )
            raise MercadoPagoError(f"Erro ao criar checkout ({response.status_code}).")
        return response.json()

    def get_payment(self, payment_id: str) -> Dict[str, Any]:
        payment_id = str(payment_id or "").strip()
        if not payment_id:
            raise MercadoPagoError("payment_id invalido.")
        url = f"{self.BASE_URL}/v1/payments/{payment_id}"
        response = requests.get(
            url,
            headers=self._headers(),
            timeout=self.timeout_seconds,
        )
        if response.status_code >= 400:
            logging.getLogger(__name__).error(
                "mercadopago payment lookup error id=%s status=%s body=%s",
                payment_id,
                response.status_code,
                response.text[:1500],
            )
            raise MercadoPagoError(f"Erro ao consultar pagamento ({response.status_code}).")
        return response.json()

    def get_current_user(self) -> Dict[str, Any]:
        url = f"{self.BASE_URL}/users/me"
        response = requests.get(
            url,
            headers=self._headers(),
            timeout=self.timeout_seconds,
        )
        if response.status_code >= 400:
            logging.getLogger(__name__).error(
                "mercadopago current user lookup error status=%s body=%s",
                response.status_code,
                response.text[:1500],
            )
            raise MercadoPagoError(f"Erro ao validar credenciais ({response.status_code}).")
        return response.json()

    @staticmethod
    def select_checkout_url(preference: Dict[str, Any], use_sandbox: bool = False) -> Optional[str]:
        if use_sandbox:
            return preference.get("sandbox_init_point") or preference.get("init_point")
        return preference.get("init_point") or preference.get("sandbox_init_point")
