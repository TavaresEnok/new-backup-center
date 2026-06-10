from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, ForeignKey, Index, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime
from app.core.database import Base
from app.models.base import TimestampMixin


class Device(Base, TimestampMixin):
    __tablename__ = 'devices'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id'), nullable=False)
    
    # Group (optional - for organization by provider/location)
    group_id = Column(UUID(as_uuid=True), ForeignKey('device_groups.id'), nullable=True)
    subgroup_id = Column(UUID(as_uuid=True), ForeignKey('device_subgroups.id'), nullable=True)
    
    # Device Type (links to global DeviceType)
    device_type_id = Column(UUID(as_uuid=True), ForeignKey('device_types.id'), nullable=True)
    
    # Legacy ID for migration
    legacy_id = Column(Integer, nullable=True, index=True)
    
    # Device Info
    name = Column(String(150), nullable=False)
    ip_address = Column(String(45), nullable=False)
    port = Column(Integer, default=22)
    username = Column(String(50), nullable=False)
    password_encrypted = Column(Text, nullable=False)  # Fernet encrypted
    
    # Connection options
    use_telnet = Column(Boolean, default=False)
    is_vpn_gateway = Column(Boolean, default=False)
    
    # Backup settings
    backup_scheduled = Column(Boolean, default=False)
    
    # Metadata
    model = Column(String(50), nullable=True)
    firmware_version = Column(String(50), nullable=True)
    description = Column(Text, nullable=True)
    tags = Column(JSON, default=list)
    
    # Additional parameters (stored encrypted as JSON)
    extra_parameters = Column(JSON, default=dict)
    
    # Status
    is_active = Column(Boolean, default=True)
    last_backup_at = Column(DateTime, nullable=True)
    last_backup_status = Column(String(20), default='never')  # success, failure, never
    last_connection_status = Column(String(20), default='unknown')  # online, offline, error
    
    # Relationships
    tenant = relationship('Tenant', back_populates='devices')
    group = relationship('DeviceGroup', back_populates='devices')
    subgroup = relationship('DeviceSubgroup', back_populates='devices')
    type = relationship('DeviceType', back_populates='devices')
    backups = relationship('Backup', back_populates='device', cascade='all, delete-orphan')
    schedules = relationship('Schedule', back_populates='device', cascade='all, delete-orphan')
    
    # Indexes
    __table_args__ = (
        Index('idx_device_tenant', 'tenant_id'),
        Index('idx_device_group', 'group_id'),
        Index('idx_device_subgroup', 'subgroup_id'),
        Index('idx_device_ip', 'ip_address'),
        Index('idx_device_type', 'device_type_id'),
    )
