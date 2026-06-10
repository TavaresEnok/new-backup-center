import enum
from sqlalchemy import Column, String, Boolean, DateTime, Enum, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.core.database import Base
from app.models.base import TimestampMixin

class UserRole(str, enum.Enum):
    SUPER_ADMIN = 'super_admin'
    TENANT_OWNER = 'tenant_owner'
    TENANT_ADMIN = 'tenant_admin'
    TENANT_TECHNICIAN = 'tenant_technician'
    TENANT_VIEWER = 'tenant_viewer'

class User(Base, TimestampMixin):
    __tablename__ = 'users'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id'), nullable=True)
    
    # Auth
    email = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(200), nullable=False)
    
    # Profile
    full_name = Column(String(100), nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.TENANT_VIEWER)
    
    # Security
    is_active = Column(Boolean, default=True)
    email_verified = Column(Boolean, default=False)
    totp_secret = Column(String(32), nullable=True)  # 2FA
    last_login = Column(DateTime, nullable=True)
    must_change_password = Column(Boolean, default=False, nullable=False)
    password_changed_at = Column(DateTime, nullable=True)
    
    # Relationships
    tenant = relationship('Tenant', back_populates='users')
    notifications = relationship('Notification', back_populates='user', cascade='all, delete-orphan')

    __table_args__ = (
        Index('idx_user_tenant', 'tenant_id'),
        Index('idx_user_role', 'role'),
    )
