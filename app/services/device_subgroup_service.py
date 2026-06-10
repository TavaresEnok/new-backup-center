from __future__ import annotations

from threading import Lock
from typing import Any

from sqlalchemy import func, inspect, text
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, engine, is_sqlite_engine
from app.models.device import Device
from app.models.device_subgroup import DeviceSubgroup


class DeviceSubgroupService:
    _schema_lock = Lock()
    _schema_ready = False

    @classmethod
    def ensure_schema(cls) -> None:
        if cls._schema_ready:
            return
        with cls._schema_lock:
            if cls._schema_ready:
                return
            if is_sqlite_engine():
                cls._schema_ready = True
                return

            inspector = inspect(engine)
            has_subgroups_table = inspector.has_table("device_subgroups")
            device_columns = {col["name"] for col in inspector.get_columns("devices")}
            device_fk_names = {fk.get("name") for fk in inspector.get_foreign_keys("devices")}
            if (
                has_subgroups_table
                and "subgroup_id" in device_columns
                and "fk_devices_subgroup_id" in device_fk_names
            ):
                cls._schema_ready = True
                return

            with engine.begin() as conn:
                conn.execute(text("SET LOCAL lock_timeout = '3s'"))
                conn.execute(
                    text(
                        """
                        CREATE TABLE IF NOT EXISTS device_subgroups (
                            id UUID PRIMARY KEY,
                            tenant_id UUID NOT NULL REFERENCES tenants(id),
                            group_id UUID NOT NULL REFERENCES device_groups(id),
                            name VARCHAR(150) NOT NULL,
                            connection_type VARCHAR(50) NOT NULL DEFAULT 'direct',
                            is_active BOOLEAN NOT NULL DEFAULT TRUE,
                            created_at TIMESTAMP NULL DEFAULT now(),
                            updated_at TIMESTAMP NULL DEFAULT now()
                        )
                        """
                    )
                )
                conn.execute(
                    text(
                        "ALTER TABLE devices "
                        "ADD COLUMN IF NOT EXISTS subgroup_id UUID NULL"
                    )
                )
                conn.execute(
                    text(
                        """
                        DO $$
                        BEGIN
                            IF NOT EXISTS (
                                SELECT 1
                                FROM pg_constraint
                                WHERE conname = 'fk_devices_subgroup_id'
                            ) THEN
                                ALTER TABLE devices
                                ADD CONSTRAINT fk_devices_subgroup_id
                                FOREIGN KEY (subgroup_id)
                                REFERENCES device_subgroups(id)
                                ON DELETE SET NULL;
                            END IF;
                        END $$;
                        """
                    )
                )
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS idx_device_subgroup_group ON device_subgroups(group_id)"
                    )
                )
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS idx_device_subgroup_tenant ON device_subgroups(tenant_id)"
                    )
                )
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS idx_device_subgroup ON devices(subgroup_id)"
                    )
                )

            cls._schema_ready = True

    @staticmethod
    def get_group_subgroups_with_count(
        db: Session,
        tenant_id,
        group_id,
    ) -> list[dict[str, Any]]:
        rows = (
            db.query(
                DeviceSubgroup,
                func.count(Device.id).label("device_count"),
            )
            .outerjoin(
                Device,
                (Device.subgroup_id == DeviceSubgroup.id)
                & (Device.is_active.isnot(False)),
            )
            .filter(
                DeviceSubgroup.tenant_id == tenant_id,
                DeviceSubgroup.group_id == group_id,
                DeviceSubgroup.is_active.is_(True),
            )
            .group_by(DeviceSubgroup.id)
            .order_by(DeviceSubgroup.name.asc())
            .all()
        )
        return [{"subgroup": row[0], "device_count": int(row[1] or 0)} for row in rows]

    @classmethod
    def get_or_create_by_name(
        cls,
        db: Session,
        *,
        tenant_id,
        group_id,
        name: str,
        connection_type: str,
    ) -> DeviceSubgroup:
        normalized = (name or "").strip()
        row = (
            db.query(DeviceSubgroup)
            .filter(
                DeviceSubgroup.tenant_id == tenant_id,
                DeviceSubgroup.group_id == group_id,
                DeviceSubgroup.is_active.is_(True),
                func.lower(DeviceSubgroup.name) == normalized.lower(),
            )
            .first()
        )
        if row:
            if row.connection_type != connection_type:
                row.connection_type = connection_type
            return row

        row = DeviceSubgroup(
            tenant_id=tenant_id,
            group_id=group_id,
            name=normalized,
            connection_type=connection_type,
            is_active=True,
        )
        db.add(row)
        db.flush()
        return row


def ensure_device_subgroup_schema_now() -> None:
    """
    Utilitário para execução manual em scripts quando necessário.
    """
    DeviceSubgroupService.ensure_schema()
    db = SessionLocal()
    db.close()
