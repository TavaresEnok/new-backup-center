import enum
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, ForeignKey, Enum, JSON, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime
from app.core.database import Base

class BackupStatus(str, enum.Enum):
    PENDING = 'pending'
    IN_PROGRESS = 'in_progress'
    SUCCESS = 'success'
    FAILED = 'failed'

class Backup(Base):
    __tablename__ = 'backups'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey('devices.id'), nullable=False)
    
    # Backup Data
    config_data = Column(JSON, nullable=True)  # Parsed config
    file_path = Column(String(500), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    hash_sha256 = Column(String(64), nullable=True)
    
    # Status
    status = Column(Enum(BackupStatus, values_callable=lambda obj: [e.value for e in obj]), default=BackupStatus.PENDING)
    error_message = Column(Text, nullable=True)
    
    # Execution Info
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    
    # Metadata
    is_manual = Column(Boolean, default=False)
    triggered_by_user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    device = relationship('Device', back_populates='backups')
    triggered_by = relationship('User')

    __table_args__ = (
        Index('idx_backup_device', 'device_id'),
        Index('idx_backup_created_at', 'created_at'),
        Index('idx_backup_status', 'status'),
        Index('idx_backup_device_created', 'device_id', 'created_at'),
    )

    @property
    def status_value(self):
        """Retorna o valor do status de forma segura (seja Enum ou string)."""
        if hasattr(self.status, 'value'):
            return self.status.value
        return str(self.status)
