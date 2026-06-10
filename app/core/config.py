from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
import os

class Settings(BaseSettings):
    # App
    APP_NAME: str = "Backup Center"
    APP_ENV: str = "development"
    DEBUG: bool = True
    APP_TIMEZONE: str = "America/Recife"
    SECRET_KEY: str = "change-me-in-production"
    AUTO_CREATE_SCHEMA: bool = True
    SESSION_MAX_AGE_MINUTES: int = 480
    SESSION_COOKIE_SECURE: bool = False
    SESSION_COOKIE_SAMESITE: str = "Lax"
    LOG_FORMAT: str = "json"
    AUDIT_USER_SCOPING_ENABLED: bool = True
    AUDIT_AUTO_LOG_REQUESTS_ENABLED: bool = False
    
    # Auth
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 1 week
    
    # Database
    DATABASE_URL: str = "postgresql://user:password@127.0.0.1:5432/backup_center"
    
    # Redis & Celery
    REDIS_URL: str = "redis://localhost:6379/0"

    # Backup retention
    DEFAULT_RETENTION_DAYS: int = 90
    REALTIME_LOG_RETENTION_DAYS: int = 90
    ACTIVITY_LOG_RETENTION_DAYS: int = 7

    # Billing / Payments
    APP_PUBLIC_URL: Optional[str] = None
    MERCADO_PAGO_ACCESS_TOKEN: Optional[str] = None
    MERCADO_PAGO_PUBLIC_KEY: Optional[str] = None
    MERCADO_PAGO_WEBHOOK_URL: Optional[str] = None
    MERCADO_PAGO_WEBHOOK_TOKEN: Optional[str] = None
    MERCADO_PAGO_USE_SANDBOX: bool = False
    
    # Encryption
    ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY", "AYCJU4fRMZE61g04GsT653mApiwswOwvwlrpUK1lmgk=")
    
    # Mail
    SMTP_SERVER: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    MAIL_FROM: str = "noreply@backupcenter.com"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()

def validate_settings():
    from cryptography.fernet import Fernet

    if settings.APP_ENV != "development" and settings.SECRET_KEY == "change-me-in-production":
        raise RuntimeError("SECRET_KEY must be set for non-development environments.")
    if settings.APP_ENV != "development" and settings.ENCRYPTION_KEY.startswith("AYCJU4fRMZE61g04GsT653mApiwswOwvwlrpUK1lmgk"):
        raise RuntimeError("ENCRYPTION_KEY must be rotated for non-development environments.")

    # Force secure defaults in non-dev environments
    if settings.APP_ENV.lower() != "development":
        settings.DEBUG = False
        settings.AUTO_CREATE_SCHEMA = False
        settings.SESSION_COOKIE_SECURE = True
        if (settings.SESSION_COOKIE_SAMESITE or "").lower() not in {"lax", "strict"}:
            settings.SESSION_COOKIE_SAMESITE = "Lax"

    try:
        Fernet(settings.ENCRYPTION_KEY.encode())
    except Exception as exc:
        raise RuntimeError("ENCRYPTION_KEY must be a valid Fernet key.") from exc
