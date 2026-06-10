from sqlalchemy import Column, String, Integer, Boolean, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.core.database import Base
from app.models.base import TimestampMixin


class DeviceType(Base, TimestampMixin):
    """
    Tipos de equipamento (Global - gerenciado apenas pelo Super Admin).
    Todos os tenants podem usar estes tipos para seus dispositivos.
    """
    __tablename__ = 'device_types'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Info
    name = Column(String(100), unique=True, nullable=False)  # Ex: "OLT Huawei", "MikroTik RouterOS"
    slug = Column(String(100), unique=True, nullable=False)  # Ex: "olt_huawei", "mikrotik_ros"
    description = Column(Text, nullable=True)
    
    # Script configuration
    script_name = Column(String(100), nullable=False)  # Ex: "huawei_olt.py"
    required_parameters = Column(Text, nullable=True)  # Ex: "password\nenable_password"
    
    # Connection settings
    default_port = Column(Integer, default=22)
    use_telnet = Column(Boolean, default=False)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Category for organization
    category = Column(String(50), default='other')  # olt, router, switch, firewall, server, erp
    
    # Relationships
    devices = relationship('Device', back_populates='type')
