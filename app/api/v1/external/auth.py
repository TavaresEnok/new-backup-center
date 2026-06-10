"""
Dependency de autenticação para a API externa.

Valida o Bearer token enviado no header Authorization e retorna o tenant.
"""

from fastapi import HTTPException, Security, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.tenant import Tenant
from app.services.api_token_service import ApiTokenService


bearer_scheme = HTTPBearer(auto_error=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_api_tenant(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    db: Session = Depends(get_db),
) -> Tenant:
    """
    Dependency FastAPI que valida o Bearer token e retorna o Tenant.

    Uso:
        @router.get("/something")
        def my_endpoint(tenant: Tenant = Depends(get_current_api_tenant)):
            ...
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de API não fornecido. Use: Authorization: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_token = credentials.credentials
    api_token = ApiTokenService.verify_token(db, raw_token)

    if not api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido, expirado ou revogado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    tenant = db.query(Tenant).filter(
        Tenant.id == api_token.tenant_id,
        Tenant.is_active == True,
    ).first()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant não encontrado ou inativo.",
        )

    return tenant
