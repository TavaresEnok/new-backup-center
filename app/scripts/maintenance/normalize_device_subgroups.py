from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from app import create_flask_app
from app.core.database import SessionLocal
from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.models.device_subgroup import DeviceSubgroup
from app.models.tenant import Tenant


CANONICAL_NAMES = {
    "direct": "Conexão Direta",
    "vpn": "Conexão VPN",
    "jump_host": "Conexão Jump Host",
}


def _normalize_type(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    if raw in {"direct", "direta", "direto"}:
        return "direct"
    if raw in {"vpn"}:
        return "vpn"
    if raw in {"jump", "jump_host", "jump host"}:
        return "jump_host"
    return raw


def _subgroup_sort_key(item):
    subgroup, device_count = item
    canonical = CANONICAL_NAMES.get(_normalize_type(subgroup.connection_type), "")
    name = str(subgroup.name or "").strip()
    return (
        0 if name.lower() == canonical.lower() else 1,
        0 if bool(getattr(subgroup, "is_active", True)) else 1,
        -int(device_count or 0),
        str(getattr(subgroup, "created_at", "") or ""),
        str(subgroup.id),
    )


def _normalize(args):
    app = create_flask_app()
    with app.app_context():
        db = SessionLocal()
        try:
            tenant = db.query(Tenant).filter(Tenant.slug == args.tenant_slug).first()
            if not tenant:
                raise RuntimeError(f"Tenant nao encontrado: {args.tenant_slug}")

            groups = db.query(DeviceGroup).filter(DeviceGroup.tenant_id == tenant.id).all()
            group_names = {str(group.id): str(group.name or "") for group in groups}
            subgroups = db.query(DeviceSubgroup).filter(DeviceSubgroup.tenant_id == tenant.id).all()
            device_counts = dict(
                db.query(Device.subgroup_id, Device.id)
                .filter(Device.tenant_id == tenant.id, Device.subgroup_id.isnot(None))
                .all()
            )
            # A query acima nao agrega; mantemos contador separado para evitar dialetos especificos.
            counts = Counter()
            for subgroup_id, _device_id in db.query(Device.subgroup_id, Device.id).filter(
                Device.tenant_id == tenant.id,
                Device.subgroup_id.isnot(None),
            ):
                counts[str(subgroup_id)] += 1

            buckets: dict[tuple[str, str], list[DeviceSubgroup]] = defaultdict(list)
            unknown_subgroups = []
            for subgroup in subgroups:
                normalized_type = _normalize_type(subgroup.connection_type)
                if normalized_type not in CANONICAL_NAMES:
                    unknown_subgroups.append(subgroup)
                    continue
                buckets[(str(subgroup.group_id), normalized_type)].append(subgroup)

            actions = []
            stats = Counter()

            for (group_id, connection_type), items in sorted(buckets.items(), key=lambda pair: (group_names.get(pair[0][0], ""), pair[0][1])):
                canonical_name = CANONICAL_NAMES[connection_type]
                decorated = [(subgroup, counts.get(str(subgroup.id), 0)) for subgroup in items]
                decorated.sort(key=_subgroup_sort_key)
                keeper = decorated[0][0]
                keeper_old_name = str(keeper.name or "")
                keeper_old_type = str(keeper.connection_type or "")

                rename_needed = keeper_old_name != canonical_name or keeper_old_type != connection_type
                duplicate_items = [subgroup for subgroup, _count in decorated[1:]]

                if rename_needed or duplicate_items:
                    action = {
                        "group_id": group_id,
                        "group_name": group_names.get(group_id, group_id),
                        "connection_type": connection_type,
                        "keeper_id": str(keeper.id),
                        "keeper_old_name": keeper_old_name,
                        "keeper_new_name": canonical_name,
                        "duplicates": [],
                    }

                    if rename_needed:
                        stats["renamed_keepers"] += 1
                        if args.apply:
                            keeper.name = canonical_name
                            keeper.connection_type = connection_type
                            keeper.is_active = True

                    for duplicate in duplicate_items:
                        duplicate_id = str(duplicate.id)
                        moved_count = counts.get(duplicate_id, 0)
                        action["duplicates"].append(
                            {
                                "subgroup_id": duplicate_id,
                                "name": str(duplicate.name or ""),
                                "devices_moved": int(moved_count),
                            }
                        )
                        stats["deleted_duplicate_subgroups"] += 1
                        stats["moved_devices"] += int(moved_count)
                        if args.apply:
                            db.query(Device).filter(Device.subgroup_id == duplicate.id).update(
                                {Device.subgroup_id: keeper.id},
                                synchronize_session=False,
                            )
                            db.delete(duplicate)

                    actions.append(action)

            if args.apply:
                db.commit()
            else:
                db.rollback()

            output = {
                "applied": bool(args.apply),
                "tenant_slug": args.tenant_slug,
                "generated_at_utc": datetime.utcnow().isoformat() + "Z",
                "stats": dict(stats),
                "actions": actions,
                "unknown_subgroups": [
                    {
                        "group_id": str(subgroup.group_id),
                        "group_name": group_names.get(str(subgroup.group_id), str(subgroup.group_id)),
                        "subgroup_id": str(subgroup.id),
                        "name": str(subgroup.name or ""),
                        "connection_type": str(subgroup.connection_type or ""),
                    }
                    for subgroup in unknown_subgroups
                ],
            }
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
            print(
                json.dumps(
                    {
                        "applied": bool(args.apply),
                        "stats": dict(stats),
                        "actions": len(actions),
                        "unknown_subgroups": len(unknown_subgroups),
                        "output": str(out_path),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


def main():
    parser = argparse.ArgumentParser(description="Normaliza subgrupos para no maximo um por tipo de conexao em cada grupo.")
    parser.add_argument("--tenant-slug", default="ajust-consulting")
    parser.add_argument("--output", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    _normalize(args)


if __name__ == "__main__":
    main()
