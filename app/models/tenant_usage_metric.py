import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Column, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from app.core.database import Base


class TenantUsageMetric(Base):
    __tablename__ = "tenant_usage_metrics"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    metric_key = Column(String(64), nullable=False)
    period_key = Column(String(16), nullable=False)
    value_bytes = Column(BigInteger, nullable=False, default=0)
    events_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "metric_key", "period_key", name="uq_tenant_usage_metric_period"),
    )
