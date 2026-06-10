from sqlalchemy import Boolean, Column, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.core.database import Base
from app.models.base import TimestampMixin


class SystemSetting(Base, TimestampMixin):
    __tablename__ = "system_settings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key = Column(String(120), nullable=False, unique=True)
    value_text = Column(Text, nullable=True)
    value_encrypted = Column(Text, nullable=True)
    is_secret = Column(Boolean, default=False, nullable=False)

    __table_args__ = (
        Index("idx_system_setting_key", "key", unique=True),
    )
