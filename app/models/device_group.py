from sqlalchemy import Column, String, Boolean, Text, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.core.database import Base
from app.models.base import TimestampMixin


class DeviceGroup(Base, TimestampMixin):
    """
    Grupos de dispositivos dentro de um Tenant.
    Permite organizar dispositivos por provedor/unidade/localização.
    """
    __tablename__ = 'device_groups'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id'), nullable=False)
    
    # Info
    name = Column(String(150), nullable=False)  # Ex: "Meganet", "Vibe Telecom"
    slug = Column(String(150), nullable=False)
    description = Column(Text, nullable=True)
    
    # Connection Type: 'direct', 'vpn', 'jump_host'
    connection_type = Column(String(50), default='direct')
    
    # VPN Configuration (L2TP/IPsec)
    uses_vpn = Column(Boolean, default=False)
    vpn_type = Column(String(50), default='l2tp')
    vpn_server = Column(String(255), nullable=True)
    vpn_username = Column(String(255), nullable=True)
    vpn_password_encrypted = Column(Text, nullable=True)  # Fernet encrypted
    vpn_ipsec_secret_encrypted = Column(Text, nullable=True)  # Fernet encrypted
    
    # SSH Jump Host / Bastion Configuration
    uses_jump_host = Column(Boolean, default=False)
    jump_host = Column(String(255), nullable=True)  # Ex: "ssh.provedor.com.br"
    jump_port = Column(Integer, default=22)
    jump_username = Column(String(255), nullable=True)
    jump_password_encrypted = Column(Text, nullable=True)  # Fernet encrypted
    jump_key_encrypted = Column(Text, nullable=True)  # SSH Private Key (encrypted)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Relationships
    tenant = relationship('Tenant', back_populates='device_groups')
    devices = relationship('Device', back_populates='group')
    subgroups = relationship('DeviceSubgroup', back_populates='group', cascade='all, delete-orphan')

