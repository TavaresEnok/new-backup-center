from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import TimestampMixin
import uuid

class ActivityLog(Base, TimestampMixin):
    __tablename__ = "activity_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    action = Column(String(50), nullable=False)  # ex: LOGIN, CREATE_USER, BACKUP_START
    details = Column(Text, nullable=True)        # JSON ou texto livre
    ip_address = Column(String(45), nullable=True)
    
    # Relacionamentos
    tenant = relationship("Tenant")
    user = relationship("User")

    __table_args__ = (
        Index('idx_activity_tenant', 'tenant_id'),
        Index('idx_activity_created_at', 'created_at'),
        Index('idx_activity_action', 'action'),
    )
