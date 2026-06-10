import enum
import secrets
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime
from app.core.database import Base
from app.models.base import TimestampMixin


class ApiToken(Base, TimestampMixin):
    """
    Token de API para acesso externo ao Backup Center.

    Permite que sistemas externos (ex: ERPs) acessem os backups de um tenant
    de forma segura, sem precisar de login interativo.

    O token real é exibido apenas uma vez na criação.
    Armazenamos apenas o hash para validação.
    """
    __tablename__ = 'api_tokens'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id'), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)

    # Identificação
    name = Column(String(100), nullable=False)          # Ex: "AjustERP", "Sistema X"
    token_prefix = Column(String(12), nullable=False)   # Primeiros chars para identificação visual
    token_hash = Column(String(200), nullable=False)    # Hash do token (nunca armazenamos o valor real)

    # Controle
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)        # Null = sem expiração

    # Relationships
    tenant = relationship('Tenant')
    user = relationship('User')

    __table_args__ = (
        Index('idx_api_token_tenant', 'tenant_id'),
        Index('idx_api_token_prefix', 'token_prefix'),
    )

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    @property
    def is_valid(self) -> bool:
        return self.is_active and not self.is_expired
