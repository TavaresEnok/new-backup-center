import enum
from sqlalchemy import Column, String, Boolean, DateTime, Text, ForeignKey, Enum, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime
from app.core.database import Base

class NotificationType(str, enum.Enum):
    BACKUP_SUCCESS = 'backup_success'
    BACKUP_FAILED = 'backup_failed'
    DEVICE_OFFLINE = 'device_offline'
    INVOICE_GENERATED = 'invoice_generated'
    PAYMENT_SUCCESS = 'payment_success'
    TRIAL_ENDING = 'trial_ending'

class Notification(Base):
    __tablename__ = 'notifications'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    
    type = Column(Enum(NotificationType), nullable=False)
    title = Column(String(200), nullable=False)
    message = Column(Text, nullable=False)
    data = Column(JSON, default=dict)  # Extra data
    
    is_read = Column(Boolean, default=False)
    read_at = Column(DateTime, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship('User', back_populates='notifications')
