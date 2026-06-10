from __future__ import annotations

from collections import Counter

from sqlalchemy import and_, or_

from app.core.database import SessionLocal
from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.models.device_type import DeviceType
from app.models.device_subgroup import DeviceSubgroup
from app.services.device_subgroup_service import DeviceSubgroupService


def _is_mikrotik(type_row: DeviceType | None) -> bool:
    if not type_row:
        return False
    name = str(getattr(type_row, "name", "") or "").strip().lower()
    script_name = str(getattr(type_row, "script_name", "") or "").strip().lower()
    return (
        "mikrotik" in name
        or "routeros" in name
        or "mikrotik" in script_name
        or "routeros" in script_name
    )


def _group_has_vpn(group: DeviceGroup | None) -> bool:
    if not group:
        return False
    vpn_server = str(getattr(group, "vpn_server", "") or "").strip()
    vpn_user = str(getattr(group, "vpn_username", "") or "").strip()
    vpn_pass = getattr(group, "vpn_password_encrypted", None)
    return bool(vpn_server and vpn_user and vpn_pass)


def main() -> None:
    DeviceSubgroupService.ensure_schema()
    db = SessionLocal()
    stats = Counter()
    try:
        rows = (
            db.query(Device, DeviceGroup, DeviceType, DeviceSubgroup)
            .join(DeviceGroup, Device.group_id == DeviceGroup.id)
            .join(DeviceType, Device.device_type_id == DeviceType.id)
            .outerjoin(DeviceSubgroup, Device.subgroup_id == DeviceSubgroup.id)
            .filter(
                Device.is_active.is_(True),
                DeviceGroup.is_active.is_(True),
                DeviceGroup.connection_type.in_(["jump_host", "jump"]),
            )
            .all()
        )

        subgroup_cache: dict[tuple[str, str, str], DeviceSubgroup] = {}

        for device, group, dev_type, current_subgroup in rows:
            if not _is_mikrotik(dev_type):
                continue
            stats["mikrotik_candidates"] += 1

            target_mode = "vpn" if _group_has_vpn(group) else "direct"
            target_name = "MikroTik - VPN Auto" if target_mode == "vpn" else "MikroTik - Direto Auto"
            cache_key = (str(group.tenant_id), str(group.id), target_mode)

            subgroup = subgroup_cache.get(cache_key)
            if subgroup is None:
                subgroup = DeviceSubgroupService.get_or_create_by_name(
                    db,
                    tenant_id=group.tenant_id,
                    group_id=group.id,
                    name=target_name,
                    connection_type=target_mode,
                )
                subgroup_cache[cache_key] = subgroup
                stats["subgroup_ensured"] += 1

            # Atualiza subgroup existente se for diferente da estrategia alvo.
            if not current_subgroup or str(current_subgroup.id) != str(subgroup.id):
                device.subgroup_id = subgroup.id
                stats["devices_reassigned"] += 1

            # Mantem hint no extra_parameters para auditoria.
            extra = dict(device.extra_parameters or {})
            if extra.get("connection_subgroup_type") != target_mode:
                extra["connection_subgroup_type"] = target_mode
                extra["connection_subgroup_enabled"] = True
                extra["connection_subgroup_origin"] = "auto_mikrotik_jump_split"
                device.extra_parameters = extra
                stats["device_extra_updated"] += 1

        db.commit()
        print("auto_route_mikrotik_jump_groups: OK")
        for k in sorted(stats):
            print(f"{k}={stats[k]}")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
