from __future__ import annotations

from typing import Iterable, Set

from app.models.device_type import DeviceType


MASS_BACKUP_EXCLUDED_TYPE_KEYWORDS = ("grafana", "zabbix")


def is_mass_backup_excluded_type(name: str | None, script_name: str | None) -> bool:
    content = f"{name or ''} {script_name or ''}".strip().lower()
    return any(keyword in content for keyword in MASS_BACKUP_EXCLUDED_TYPE_KEYWORDS)


def resolve_mass_backup_excluded_type_ids(db) -> Set:
    excluded_type_ids: Set = set()
    type_rows: Iterable = db.query(DeviceType.id, DeviceType.name, DeviceType.script_name).all()
    for row in type_rows:
        if is_mass_backup_excluded_type(row.name, row.script_name):
            excluded_type_ids.add(row.id)
    return excluded_type_ids
