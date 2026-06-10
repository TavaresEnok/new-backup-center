from sqlalchemy import Column, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime
from app.core.database import Base
from app.models.base import TimestampMixin

class Tenant(Base, TimestampMixin):
    __tablename__ = 'tenants'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    slug = Column(String(50), unique=True, nullable=False, index=True)
    company_name = Column(String(200))
    cnpj = Column(String(18))
    email = Column(String(100), nullable=False)
    phone = Column(String(20))
    
    # Status
    is_active = Column(Boolean, default=True)
    trial_ends_at = Column(DateTime, nullable=True)
    subscription_status = Column(String(20), default='trial') # trial, active, past_due, canceled
    current_period_end = Column(DateTime, nullable=True)
    billing_blocked_at = Column(DateTime, nullable=True)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(UUID(as_uuid=True), nullable=True)
    delete_reason = Column(Text, nullable=True)
    deleted_was_active = Column(Boolean, default=False, nullable=False)
    
    # Billing
    plan_id = Column(UUID(as_uuid=True), ForeignKey('plans.id'), nullable=True)
    access_unlimited = Column(Boolean, default=False, nullable=False)
    protected_system_tenant = Column(Boolean, default=False, nullable=False)
    
    # Relationships
    users = relationship('User', back_populates='tenant', cascade='all, delete-orphan')
    devices = relationship('Device', back_populates='tenant', cascade='all, delete-orphan')
    invoices = relationship('Invoice', back_populates='tenant', cascade='all, delete-orphan')
    device_groups = relationship('DeviceGroup', back_populates='tenant', cascade='all, delete-orphan')
    device_subgroups = relationship('DeviceSubgroup', back_populates='tenant', cascade='all, delete-orphan')
    plan = relationship('Plan', back_populates='tenants')
