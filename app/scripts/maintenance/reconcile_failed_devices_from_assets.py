from __future__ import annotations

import argparse
import csv
import json
import re
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import joinedload

from app import create_flask_app
from app.core.database import SessionLocal
from app.core.security import decrypt_password, encrypt_password
from app.models.backup import Backup, BackupStatus
from app.models.device import Device
from app.models.tenant import Tenant


def _normalize(value: str | None) -> str:
    text = unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode("ascii")
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return " ".join(text.split())


def _parse_protocol_port(value: str | None) -> tuple[str, int, bool]:
    match = re.search(r"(ssh|telnet)/(\d+)", str(value or ""), re.IGNORECASE)
    if not match:
        return "ssh", 22, False
    protocol = match.group(1).lower()
    return protocol, int(match.group(2)), protocol == "telnet"


def _parse_asset_refs(value: str | None) -> list[tuple[str, str]]:
    refs: list[tuple[str, str]] = []
    for name, asset_id in re.findall(r'([^,\[\]"]+?)\(([0-9a-fA-F-]{36})\)', str(value or "")):
        refs.append((name.strip(), asset_id.strip()))
    return refs


def _load_assets(path: Path):
    assets = []
    with path.open(encoding="utf-8-sig", newline="") as fp:
        for row in csv.DictReader(fp):
            protocol, port, use_telnet = _parse_protocol_port(row.get("Grupo de Protocolo"))
            asset = {
                "asset_id": str(row.get("ID") or "").strip().lstrip("'"),
                "name": str(row.get("*Nome") or "").strip(),
                "name_norm": _normalize(row.get("*Nome")),
                "ip": str(row.get("*Endereço") or "").strip(),
                "platform": str(row.get("*Plataforma") or "").strip(),
                "port": int(port),
                "protocol": protocol,
                "use_telnet": bool(use_telnet),
            }
            if asset["asset_id"] and asset["name"] and asset["ip"]:
                assets.append(asset)
    asset_by_id = {asset["asset_id"]: asset for asset in assets}
    by_name = defaultdict(list)
    by_name_ip = defaultdict(list)
    for asset in assets:
        by_name[asset["name_norm"]].append(asset)
        by_name_ip[(asset["name_norm"], asset["ip"])].append(asset)
    return asset_by_id, by_name, by_name_ip


def _load_accounts(path: Path):
    accounts_by_asset = defaultdict(list)
    with path.open(encoding="utf-8-sig", newline="") as fp:
        for row in csv.DictReader(fp):
            username = str(row.get("Nome de usuário") or "").strip()
            password = str(row.get("Texto cifrado") or "")
            if not username or not password:
                continue
            for _asset_name, asset_id in _parse_asset_refs(row.get("*Ativos")):
                accounts_by_asset[asset_id].append(
                    {
                        "account_id": str(row.get("ID") or "").strip().lstrip("'"),
                        "account_name": str(row.get("Nome") or "").strip(),
                        "username": username,
                        "password": password,
                    }
                )
    return accounts_by_asset


def _choose_account(device: Device, accounts_by_asset, asset_id: str):
    rows = accounts_by_asset.get(asset_id, [])
    if not rows:
        return None, "no_account"

    deduped = []
    seen = set()
    for row in rows:
        key = (row["username"], row["password"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    rows = deduped

    same_username = [row for row in rows if row["username"] == str(device.username or "").strip()]
    if len(same_username) == 1:
        return same_username[0], "account_current_username"
    if len(rows) == 1:
        return rows[0], "account_unique"
    return None, "ambiguous_accounts"


def _resolve_asset(device: Device, asset_by_id, by_name, by_name_ip):
    extra = device.extra_parameters if isinstance(device.extra_parameters, dict) else {}
    asset_id = str(extra.get("asset_id") or "").strip()
    if asset_id and asset_id in asset_by_id:
        return asset_by_id[asset_id], "asset_id"

    name_key = _normalize(device.name)
    ip = str(device.ip_address or "").strip()
    same_name_ip = by_name_ip.get((name_key, ip), [])
    if len(same_name_ip) == 1:
        return same_name_ip[0], "name_ip_unique"
    if len(same_name_ip) > 1:
        port = int(device.port or 22)
        narrowed = [asset for asset in same_name_ip if int(asset["port"]) == port]
        if len(narrowed) == 1:
            return narrowed[0], "name_ip_port_unique"
        return None, "ambiguous_name_ip"

    same_name = by_name.get(name_key, [])
    if len(same_name) == 1:
        # Seguro para relatorio, mas nao para aplicar automaticamente: poderia trocar IP
        # de um homonimo importado errado. Deixa para decisao manual.
        return same_name[0], "name_unique_report_only"
    if len(same_name) > 1:
        return None, "ambiguous_name"
    return None, "no_asset_match"


def _current_plain_password(device: Device) -> str:
    try:
        return decrypt_password(device.password_encrypted) if device.password_encrypted else ""
    except Exception:
        return "__DECRYPT_ERROR__"


def _reconcile(args):
    asset_by_id, by_name, by_name_ip = _load_assets(Path(args.asset_csv))
    accounts_by_asset = _load_accounts(Path(args.account_csv))
    route_ids = set(Path(args.exclude_ids_file).read_text().split()) if args.exclude_ids_file else set()

    app = create_flask_app()
    with app.app_context():
        db = SessionLocal()
        try:
            tenant = db.query(Tenant).filter(Tenant.slug == args.tenant_slug).first()
            if not tenant:
                raise RuntimeError(f"Tenant nao encontrado: {args.tenant_slug}")

            devices = (
                db.query(Device)
                .options(joinedload(Device.group), joinedload(Device.subgroup), joinedload(Device.type))
                .filter(
                    Device.tenant_id == tenant.id,
                    Device.is_active.is_(True),
                    Device.last_backup_status == "failure",
                )
                .all()
            )

            stats = Counter()
            rows = []
            updated_device_ids = []

            for device in devices:
                has_success = (
                    db.query(Backup.id)
                    .filter(Backup.device_id == device.id, Backup.status == BackupStatus.SUCCESS)
                    .first()
                    is not None
                )
                if not has_success:
                    stats["excluded_never_success"] += 1
                    continue
                if str(device.id) in route_ids:
                    stats["excluded_route_probe"] += 1
                    continue

                stats["candidate"] += 1
                asset, match_rule = _resolve_asset(device, asset_by_id, by_name, by_name_ip)
                base_row = {
                    "device_id": str(device.id),
                    "device_name": str(device.name or ""),
                    "group": str(device.group.name if device.group else ""),
                    "type": str(device.type.name if device.type else ""),
                    "current_ip": str(device.ip_address or ""),
                    "current_port": int(device.port or 22),
                    "current_username": str(device.username or ""),
                    "current_protocol": "telnet" if bool(device.use_telnet) else "ssh",
                }

                if not asset:
                    stats[f"blocked_{match_rule}"] += 1
                    rows.append({**base_row, "status": "blocked", "reason": match_rule})
                    continue

                if match_rule == "name_unique_report_only":
                    stats["blocked_name_unique_report_only"] += 1
                    rows.append(
                        {
                            **base_row,
                            "status": "blocked",
                            "reason": match_rule,
                            "asset_id": asset["asset_id"],
                            "asset_name": asset["name"],
                            "asset_ip": asset["ip"],
                            "asset_port": asset["port"],
                            "asset_protocol": asset["protocol"],
                        }
                    )
                    continue

                account, account_rule = _choose_account(device, accounts_by_asset, asset["asset_id"])
                if not account:
                    stats[f"blocked_{account_rule}"] += 1
                    rows.append(
                        {
                            **base_row,
                            "status": "blocked",
                            "reason": account_rule,
                            "match_rule": match_rule,
                            "asset_id": asset["asset_id"],
                            "asset_name": asset["name"],
                        }
                    )
                    continue

                changes = []
                if str(device.username or "").strip() != account["username"]:
                    changes.append("username")
                if _current_plain_password(device) != account["password"]:
                    changes.append("password")
                if str(device.ip_address or "").strip() != asset["ip"] and match_rule == "asset_id":
                    changes.append("ip_address")
                if int(device.port or 22) != int(asset["port"]):
                    changes.append("port")
                if bool(device.use_telnet) != bool(asset["use_telnet"]):
                    changes.append("use_telnet")

                status = "safe_update" if changes else "already_ok"
                stats[status] += 1
                stats[f"match_{match_rule}"] += 1
                rows.append(
                    {
                        **base_row,
                        "status": status,
                        "match_rule": match_rule,
                        "account_rule": account_rule,
                        "asset_id": asset["asset_id"],
                        "asset_name": asset["name"],
                        "asset_ip": asset["ip"],
                        "asset_port": asset["port"],
                        "asset_protocol": asset["protocol"],
                        "changes": changes,
                    }
                )

                if args.apply and changes:
                    if "username" in changes:
                        device.username = account["username"]
                    if "password" in changes:
                        device.password_encrypted = encrypt_password(account["password"])
                    if "ip_address" in changes:
                        device.ip_address = asset["ip"]
                    if "port" in changes:
                        device.port = int(asset["port"])
                    if "use_telnet" in changes:
                        device.use_telnet = bool(asset["use_telnet"])
                    extra = dict(device.extra_parameters or {})
                    extra["asset_id"] = asset["asset_id"]
                    extra["sync_source"] = "asset/account csv safe reconcile"
                    extra["asset_platform"] = asset["platform"]
                    extra["credential_reconciled_at"] = datetime.utcnow().isoformat() + "Z"
                    extra["credential_reconcile_match_rule"] = match_rule
                    extra["credential_reconcile_changes"] = changes
                    device.extra_parameters = extra
                    updated_device_ids.append(str(device.id))

            if args.apply:
                db.commit()
            else:
                db.rollback()

            output = {
                "applied": bool(args.apply),
                "tenant_slug": args.tenant_slug,
                "generated_at_utc": datetime.utcnow().isoformat() + "Z",
                "stats": dict(stats),
                "updated_device_ids": updated_device_ids,
                "rows": rows,
            }
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps({"stats": dict(stats), "updated": len(updated_device_ids), "output": str(out_path)}, ensure_ascii=False, indent=2))
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


def main():
    parser = argparse.ArgumentParser(description="Reconcilia dispositivos em falha com CSVs de asset/account sem matches fracos.")
    parser.add_argument("--tenant-slug", default="ajust-consulting")
    parser.add_argument("--asset-csv", required=True)
    parser.add_argument("--account-csv", required=True)
    parser.add_argument("--exclude-ids-file", default="")
    parser.add_argument("--output", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    _reconcile(args)


if __name__ == "__main__":
    main()
