from sqlalchemy import Column, String, Integer, Boolean, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.core.database import Base
from app.models.base import TimestampMixin

class Plan(Base, TimestampMixin):
    __tablename__ = 'plans'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    name = Column(String(50), nullable=False)
    slug = Column(String(50), unique=True, nullable=False)
    description = Column(Text)
    
    # Pricing
    price_monthly = Column(Integer, nullable=False)  # In cents
    price_yearly = Column(Integer, nullable=False)
    trial_days = Column(Integer, default=14)
    billing_period_days = Column(Integer, nullable=False, default=30)
    payment_grace_days = Column(Integer, nullable=False, default=3)
    
    # Limits
    max_devices = Column(Integer, nullable=False)
    max_users = Column(Integer, nullable=False)
    backup_retention_days = Column(Integer, default=30)
    storage_quota_gb = Column(Integer, nullable=False, default=10)
    download_quota_gb_month = Column(Integer, nullable=False, default=20)
    max_download_rate_mbps = Column(Integer, nullable=False, default=0)
    
    # Features (JSON for flexibility)
    features = Column(JSON, default=dict)
    
    is_active = Column(Boolean, default=True)
    
    # Relationships
    tenants = relationship('Tenant', back_populates='plan')
