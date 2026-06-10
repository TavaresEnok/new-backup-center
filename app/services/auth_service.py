from threading import Lock

from sqlalchemy.orm import Session
from sqlalchemy import inspect, text
from app.core.database import is_sqlite_engine
from app.models.user import User, UserRole
from app.models.tenant import Tenant
from app.models.plan import Plan
from app.core.security import get_password_hash, verify_password
from app.services.tenant_access_service import TenantAccessService
from typing import Optional
from datetime import datetime
import re
import uuid

class AuthService:
    _schema_lock = Lock()
    _schema_ready = False

    @staticmethod
    def ensure_schema(db: Session) -> None:
        if AuthService._schema_ready:
            return
        with AuthService._schema_lock:
            if AuthService._schema_ready:
                return
            if is_sqlite_engine():
                AuthService._schema_ready = True
                return
            inspector = inspect(db.bind)
            user_columns = {col["name"] for col in inspector.get_columns("users")}
            if {"must_change_password", "password_changed_at"}.issubset(user_columns):
                AuthService._schema_ready = True
                return
            db.execute(text("SET LOCAL lock_timeout = '3s'"))
            db.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE"))
            db.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP NULL"))
            db.commit()
            AuthService._schema_ready = True

    @staticmethod
    def _build_unique_slug(db: Session, company_name: str) -> str:
        base = re.sub(r"[^a-z0-9-]+", "-", (company_name or "").strip().lower())
        base = re.sub(r"-{2,}", "-", base).strip("-") or "cliente"
        slug = base
        suffix = 1
        while db.query(Tenant.id).filter(Tenant.slug == slug).first():
            suffix += 1
            slug = f"{base}-{suffix}"
        return slug

    @staticmethod
    def register_tenant(
        db: Session,
        email: str,
        password: str,
        full_name: str,
        company_name: str,
        plan_id: str | None = None,
        activate_trial: bool = True,
        require_password_change: bool = False,
    ) -> User:
        AuthService.ensure_schema(db)
        selected_plan = None
        if plan_id:
            try:
                plan_uuid = uuid.UUID(str(plan_id))
            except Exception as exc:
                raise ValueError("Plano invalido.") from exc
            selected_plan = (
                db.query(Plan)
                .filter(Plan.id == plan_uuid, Plan.is_active.is_(True))
                .first()
            )
        if not selected_plan:
            selected_plan = (
                db.query(Plan)
                .filter(Plan.is_active.is_(True))
                .order_by(Plan.price_monthly.asc(), Plan.created_at.asc())
                .first()
            )
        if not selected_plan:
            raise ValueError("Nao existe plano ativo disponivel para novos clientes.")

        # Create Tenant
        slug = AuthService._build_unique_slug(db, company_name)
        tenant = Tenant(
            name=company_name,
            slug=slug,
            email=email,
            company_name=company_name,
            is_active=bool(activate_trial),
        )
        if activate_trial:
            TenantAccessService.seed_trial_plan_fields(tenant, selected_plan)
        else:
            TenantAccessService.seed_pending_payment_plan_fields(tenant, selected_plan)
        db.add(tenant)
        db.flush()  # Get tenant.id
        
        # Create User (Owner)
        user = User(
            email=email,
            password_hash=get_password_hash(password),
            full_name=full_name,
            tenant_id=tenant.id,
            role=UserRole.TENANT_OWNER,
            email_verified=False,
            must_change_password=bool(require_password_change),
            password_changed_at=None if require_password_change else datetime.utcnow(),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user

    @staticmethod
    def get_password_hash(password: str) -> str:
        return get_password_hash(password)
