from sqlalchemy import Column, String, Boolean, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base
from app.models.base import TimestampMixin


class DeviceSubgroup(Base, TimestampMixin):
    """
    Subgrupo interno de dispositivos dentro de um grupo principal.
    Ex.: Grupo principal I4 -> Subgrupo "VPN legado", "Jump secundario", etc.
    """

    __tablename__ = "device_subgroups"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    group_id = Column(UUID(as_uuid=True), ForeignKey("device_groups.id"), nullable=False)

    name = Column(String(150), nullable=False)
    connection_type = Column(String(50), nullable=False, default="direct")  # direct|vpn|jump_host
    is_active = Column(Boolean, nullable=False, default=True)

    tenant = relationship("Tenant", back_populates="device_subgroups")
    group = relationship("DeviceGroup", back_populates="subgroups")
    devices = relationship("Device", back_populates="subgroup")

    __table_args__ = (
        Index("idx_device_subgroup_tenant", "tenant_id"),
        Index("idx_device_subgroup_group", "group_id"),
    )

