from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Enum
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid
import enum
from app.core.database import Base
from app.models.base import TimestampMixin

class PaymentMethodType(str, enum.Enum):
    CREDIT_CARD = 'credit_card'
    BOLETO = 'boleto'
    PIX = 'pix'

class SubscriptionStatus(str, enum.Enum):
    ACTIVE = 'active'
    PAST_DUE = 'past_due'
    CANCELED = 'canceled'
    TRIAL = 'trial'

class PaymentMethod(Base, TimestampMixin):
    __tablename__ = 'payment_methods'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id'), nullable=False)
    
    type = Column(Enum(PaymentMethodType), default=PaymentMethodType.CREDIT_CARD)
    provider = Column(String(50), default='mock') # stripe, asaas, mock
    
    # Store minimal info, never full card numbers
    last_four = Column(String(4))
    brand = Column(String(20)) # visa, mastercard
    exp_month = Column(Integer)
    exp_year = Column(Integer)
    
    token = Column(String(255)) # Token from the provider
    is_default = Column(Integer, default=False) # Boolean as Integer for compatibility or just Boolean
    
    tenant = relationship('Tenant', backref='payment_methods')

class Subscription(Base, TimestampMixin):
    __tablename__ = 'subscriptions'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id'), nullable=False)
    plan_id = Column(UUID(as_uuid=True), ForeignKey('plans.id'), nullable=False)
    
    status = Column(Enum(SubscriptionStatus), default=SubscriptionStatus.ACTIVE)
    current_period_start = Column(DateTime, nullable=False)
    current_period_end = Column(DateTime, nullable=False)
    
    cancel_at_period_end = Column(Boolean, default=False)
    canceled_at = Column(DateTime, nullable=True)
    
    provider_subscription_id = Column(String(100)) # ID on Stripe/Asaas
    
    tenant = relationship('Tenant', backref='subscriptions')
    plan = relationship('Plan')
