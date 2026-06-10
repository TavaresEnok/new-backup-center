from __future__ import annotations

from threading import Lock
from typing import Any

from app.core.config import settings
from app.core.database import SessionLocal, engine
from app.core.security import decrypt_password, encrypt_password
from app.models.system_setting import SystemSetting


PAYMENT_SETTING_KEYS = {
    "APP_PUBLIC_URL": {"secret": False, "default": lambda: settings.APP_PUBLIC_URL or ""},
    "MERCADO_PAGO_ACCESS_TOKEN": {"secret": True, "default": lambda: settings.MERCADO_PAGO_ACCESS_TOKEN or ""},
    "MERCADO_PAGO_PUBLIC_KEY": {"secret": True, "default": lambda: settings.MERCADO_PAGO_PUBLIC_KEY or ""},
    "MERCADO_PAGO_WEBHOOK_URL": {"secret": False, "default": lambda: settings.MERCADO_PAGO_WEBHOOK_URL or ""},
    "MERCADO_PAGO_WEBHOOK_TOKEN": {"secret": True, "default": lambda: settings.MERCADO_PAGO_WEBHOOK_TOKEN or ""},
    "MERCADO_PAGO_USE_SANDBOX": {"secret": False, "default": lambda: "1" if settings.MERCADO_PAGO_USE_SANDBOX else "0"},
}


class PlatformSettingsService:
    _schema_lock = Lock()
    _schema_ready = False

    @classmethod
    def ensure_schema(cls) -> None:
        if cls._schema_ready:
            return
        with cls._schema_lock:
            if cls._schema_ready:
                return
            SystemSetting.__table__.create(bind=engine, checkfirst=True)
            cls._schema_ready = True

    @staticmethod
    def _normalize_bool(value: Any) -> bool:
        return str(value or "").strip().lower() in {"1", "true", "yes", "on"}

    @classmethod
    def _row_value(cls, row: SystemSetting | None, key: str) -> str:
        if row:
            if row.is_secret and row.value_encrypted:
                try:
                    return decrypt_password(row.value_encrypted)
                except Exception:
                    return ""
            return str(row.value_text or "")

        meta = PAYMENT_SETTING_KEYS.get(key)
        if not meta:
            return ""
        default_factory = meta.get("default")
        return str(default_factory() if callable(default_factory) else "")

    @classmethod
    def get_many(cls, keys: list[str]) -> dict[str, str]:
        cls.ensure_schema()
        db = SessionLocal()
        try:
            rows = db.query(SystemSetting).filter(SystemSetting.key.in_(keys)).all()
            rows_by_key = {row.key: row for row in rows}
            return {key: cls._row_value(rows_by_key.get(key), key) for key in keys}
        finally:
            db.close()

    @classmethod
    def get_payment_config(cls) -> dict[str, Any]:
        raw = cls.get_many(list(PAYMENT_SETTING_KEYS.keys()))
        return {
            "app_public_url": raw["APP_PUBLIC_URL"].strip(),
            "mercado_pago_access_token": raw["MERCADO_PAGO_ACCESS_TOKEN"].strip(),
            "mercado_pago_public_key": raw["MERCADO_PAGO_PUBLIC_KEY"].strip(),
            "mercado_pago_webhook_url": raw["MERCADO_PAGO_WEBHOOK_URL"].strip(),
            "mercado_pago_webhook_token": raw["MERCADO_PAGO_WEBHOOK_TOKEN"].strip(),
            "mercado_pago_use_sandbox": cls._normalize_bool(raw["MERCADO_PAGO_USE_SANDBOX"]),
        }

    @classmethod
    def save_payment_config(
        cls,
        *,
        app_public_url: str,
        webhook_url: str,
        use_sandbox: bool,
        access_token: str | None = None,
        public_key: str | None = None,
        webhook_token: str | None = None,
        clear_access_token: bool = False,
        clear_public_key: bool = False,
        clear_webhook_token: bool = False,
    ) -> None:
        cls.ensure_schema()
        db = SessionLocal()
        try:
            rows = db.query(SystemSetting).filter(SystemSetting.key.in_(PAYMENT_SETTING_KEYS.keys())).all()
            rows_by_key = {row.key: row for row in rows}

            def upsert_text(key: str, value: str) -> None:
                row = rows_by_key.get(key)
                if not row:
                    row = SystemSetting(key=key, is_secret=False)
                    db.add(row)
                    rows_by_key[key] = row
                row.is_secret = False
                row.value_text = (value or "").strip() or None
                row.value_encrypted = None

            def upsert_secret(key: str, new_value: str | None, clear_flag: bool) -> None:
                row = rows_by_key.get(key)
                if not row:
                    row = SystemSetting(key=key, is_secret=True)
                    db.add(row)
                    rows_by_key[key] = row
                row.is_secret = True
                row.value_text = None
                if clear_flag:
                    row.value_encrypted = None
                    return
                normalized = (new_value or "").strip()
                if normalized:
                    row.value_encrypted = encrypt_password(normalized)

            upsert_text("APP_PUBLIC_URL", app_public_url)
            upsert_text("MERCADO_PAGO_WEBHOOK_URL", webhook_url)
            upsert_text("MERCADO_PAGO_USE_SANDBOX", "1" if use_sandbox else "0")
            upsert_secret("MERCADO_PAGO_ACCESS_TOKEN", access_token, clear_access_token)
            upsert_secret("MERCADO_PAGO_PUBLIC_KEY", public_key, clear_public_key)
            upsert_secret("MERCADO_PAGO_WEBHOOK_TOKEN", webhook_token, clear_webhook_token)

            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @classmethod
    def set_payment_mode(cls, *, use_sandbox: bool) -> None:
        cls.ensure_schema()
        db = SessionLocal()
        try:
            row = db.query(SystemSetting).filter(SystemSetting.key == "MERCADO_PAGO_USE_SANDBOX").first()
            if not row:
                row = SystemSetting(key="MERCADO_PAGO_USE_SANDBOX", is_secret=False)
                db.add(row)
            row.is_secret = False
            row.value_text = "1" if use_sandbox else "0"
            row.value_encrypted = None
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
