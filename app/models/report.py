from sqlalchemy import Column, String, Boolean, DateTime, Text, ForeignKey, Enum, JSON, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
import enum
from datetime import datetime
from app.core.database import Base


class ReportType(str, enum.Enum):
    DAILY_SUMMARY = 'daily_summary'
    WEEKLY_REPORT = 'weekly_report'
    MONTHLY_REPORT = 'monthly_report'
    FAILURE_ALERT = 'failure_alert'


class ReportSchedule(str, enum.Enum):
    DAILY = 'daily'
    WEEKLY = 'weekly'
    MONTHLY = 'monthly'


class Report(Base):
    __tablename__ = 'reports'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id'), nullable=False)
    
    # Configuration
    name = Column(String(100), nullable=False)
    report_type = Column(Enum(ReportType), nullable=False, default=ReportType.DAILY_SUMMARY)
    schedule = Column(Enum(ReportSchedule), nullable=False, default=ReportSchedule.DAILY)
    
    # Recipients (JSON array of email addresses)
    recipients = Column(JSON, default=[])
    
    # Execution
    is_active = Column(Boolean, default=True)
    last_sent_at = Column(DateTime, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    tenant = relationship('Tenant')

    __table_args__ = (
        Index('idx_report_tenant', 'tenant_id'),
        Index('idx_report_schedule', 'schedule'),
    )
