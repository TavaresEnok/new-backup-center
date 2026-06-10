import enum
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime
from app.core.database import Base
from app.models.base import TimestampMixin

class InvoiceStatus(str, enum.Enum):
    DRAFT = 'draft'
    PENDING = 'pending'
    PAID = 'paid'
    FAILED = 'failed'
    CANCELLED = 'cancelled'

class Invoice(Base, TimestampMixin):
    __tablename__ = 'invoices'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id'), nullable=False)
    
    # Invoice Data
    invoice_number = Column(String(20), unique=True, nullable=False)
    amount = Column(Integer, nullable=False)  # In cents
    currency = Column(String(3), default='BRL')
    
    # Billing Period
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    
    # Status
    status = Column(Enum(InvoiceStatus), default=InvoiceStatus.DRAFT)
    due_date = Column(DateTime, nullable=False)
    paid_at = Column(DateTime, nullable=True)
    
    # Payment
    payment_method = Column(String(50), nullable=True)
    payment_gateway_id = Column(String(100), nullable=True)
    
    # Relationships
    tenant = relationship('Tenant', back_populates='invoices')
