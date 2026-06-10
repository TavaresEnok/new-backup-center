import enum
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Enum, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime
from app.core.database import Base
from app.models.base import TimestampMixin

class ScheduleFrequency(str, enum.Enum):
    DAILY = 'daily'
    # Legado: mantidos apenas para compatibilidade com dados antigos.
    WEEKLY = 'weekly'
    MONTHLY = 'monthly'

class Schedule(Base, TimestampMixin):
    __tablename__ = 'schedules'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey('devices.id'), nullable=False)
    
    # Runtime atual: rotina diaria global por tenant. Os campos abaixo
    # permanecem por compatibilidade de banco, mas o fluxo operacional
    # normaliza tudo para DAILY.
    frequency = Column(
        Enum(
            ScheduleFrequency,
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
    )
    time = Column(String(5), nullable=False)  # HH:MM 24h format
    day_of_week = Column(Integer, nullable=True)  # legado
    day_of_month = Column(Integer, nullable=True)  # legado
    
    # Status
    is_active = Column(Boolean, default=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    
    # Relationships
    device = relationship('Device', back_populates='schedules')

    __table_args__ = (
        Index('idx_schedule_device', 'device_id'),
        Index('idx_schedule_next_run', 'next_run_at'),
        Index('idx_schedule_active', 'is_active'),
    )
