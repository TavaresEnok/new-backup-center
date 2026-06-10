from __future__ import annotations

import argparse
import csv
import re
import unicodedata
from collections import Counter
from datetime import datetime
from pathlib import Path

from app.core.database import SessionLocal
from app.core.security import encrypt_password
from app.models.device import Device
from app.models.tenant import Tenant


def _normalize_name(value: str | None) -> str:
    text = unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode("ascii")
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return " ".join(text.split())


def _parse_bool(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "on", "yes", "sim"}


def _safe_int(value, default: int = 22) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return int(default)


def _build_indexes(payload_rows: list[dict]) -> tuple[dict[str, list[dict]], dict[tuple[str, int], list[dict]]]:
    by_name: dict[str, list[dict]] = {}
    by_ip_port: dict[tuple[str, int], list[dict]] = {}
    for row in payload_rows:
        pwd = str(row.get("password") or "")
        usr = str(row.get("username") or "")
        ip = str(row.get("ip_address") or "").strip()
        port = _safe_int(row.get("port"), 22)
        if not pwd or not usr or not ip:
            continue
        key_name = _normalize_name(row.get("name"))
        if key_name:
            by_name.setdefault(key_name, []).append(row)
        by_ip_port.setdefault((ip, port), []).append(row)
    return by_name, by_ip_port


def _load_failed_device_ids(path: str | None) -> set[str]:
    if not path:
        return set()
    src = Path(path)
    if not src.exists():
        raise FileNotFoundError(f"Arquivo de falhas nao encontrado: {src}")
    ids: set[str] = set()
    with src.open("r", encoding="utf-8", newline="") as fp:
        reader = csv.DictReader(fp)
        for row in reader:
            dev_id = str(row.get("device_id") or "").strip()
            if dev_id:
                ids.add(dev_id)
    return ids


def _resolve_candidate(
    device: Device,
    by_name: dict[str, list[dict]],
    by_ip_port: dict[tuple[str, int], list[dict]],
) -> tuple[dict | None, str]:
    name_key = _normalize_name(getattr(device, "name", ""))
    ip_key = str(getattr(device, "ip_address", "") or "").strip()
    port_key = _safe_int(getattr(device, "port", 22), 22)

    name_rows = by_name.get(name_key, [])
    ip_port_rows = by_ip_port.get((ip_key, port_key), [])

    if len(name_rows) == 1:
        return name_rows[0], "name_exact"
    if len(ip_port_rows) == 1:
        return ip_port_rows[0], "ip_port_exact"

    if len(name_rows) > 1:
        narrowed = [
            row
            for row in name_rows
            if str(row.get("ip_address") or "").strip() == ip_key
            and _safe_int(row.get("port"), 22) == port_key
        ]
        if len(narrowed) == 1:
            return narrowed[0], "name_disambiguated_ip_port"
        return None, "ambiguous_name"

    if len(ip_port_rows) > 1:
        return None, "ambiguous_ip_port"

    return None, "no_match"


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Sincroniza credenciais de dispositivos a partir de CSV consolidado "
            "(username/password/port/use_telnet), com match por nome e ip:porta."
        )
    )
    parser.add_argument(
        "--csv",
        default="/app/app/tmp/payload_credentials_merged.csv",
        help="CSV consolidado de credenciais.",
    )
    parser.add_argument(
        "--failed-csv",
        default="",
        help="Opcional: CSV de falhas (coluna device_id) para limitar o alvo.",
    )
    parser.add_argument(
        "--tenant-slug",
        default="",
        help="Opcional: restringe a um tenant especifico.",
    )
    parser.add_argument(
        "--update-ip-by-name",
        action="store_true",
        help="Se ativo, atualiza ip_address quando o match for por nome.",
    )
    parser.add_argument(
        "--report-dir",
        default="/app/app/tmp",
        help="Diretorio para salvar relatorio CSV.",
    )
    args = parser.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV de credenciais nao encontrado: {csv_path}")

    with csv_path.open("r", encoding="utf-8", newline="") as fp:
        payload_rows = list(csv.DictReader(fp))
    by_name, by_ip_port = _build_indexes(payload_rows)

    failed_ids = _load_failed_device_ids(args.failed_csv)

    db = SessionLocal()
    stats = Counter()
    report_rows: list[dict] = []
    try:
        tenant_id_filter = None
        if args.tenant_slug:
            tenant = db.query(Tenant).filter(Tenant.slug == args.tenant_slug).first()
            if not tenant:
                raise RuntimeError(f"Tenant slug nao encontrado: {args.tenant_slug}")
            tenant_id_filter = str(tenant.id)

        query = db.query(Device).filter(Device.is_active.is_(True))
        if tenant_id_filter:
            query = query.filter(Device.tenant_id == tenant_id_filter)
        devices = query.all()

        for device in devices:
            device_id = str(device.id)
            if failed_ids and device_id not in failed_ids:
                continue

            stats["scanned"] += 1
            candidate, match_rule = _resolve_candidate(device, by_name, by_ip_port)
            if not candidate:
                stats[f"unresolved_{match_rule}"] += 1
                report_rows.append(
                    {
                        "device_id": device_id,
                        "device_name": str(device.name or ""),
                        "status": "unresolved",
                        "match_rule": match_rule,
                        "changes": "",
                    }
                )
                continue

            changed_fields: list[str] = []
            new_user = str(candidate.get("username") or "").strip()
            new_pass = str(candidate.get("password") or "")
            new_ip = str(candidate.get("ip_address") or "").strip()
            new_port = _safe_int(candidate.get("port"), device.port or 22)
            new_telnet = _parse_bool(candidate.get("use_telnet"))

            if new_user and str(device.username or "") != new_user:
                device.username = new_user
                changed_fields.append("username")

            if new_pass:
                encrypted = encrypt_password(new_pass)
                if str(device.password_encrypted or "") != str(encrypted):
                    device.password_encrypted = encrypted
                    changed_fields.append("password")

            if int(device.port or 22) != int(new_port):
                device.port = int(new_port)
                changed_fields.append("port")

            if bool(device.use_telnet) != bool(new_telnet):
                device.use_telnet = bool(new_telnet)
                changed_fields.append("use_telnet")

            if args.update_ip_by_name and match_rule.startswith("name_") and new_ip and str(device.ip_address or "") != new_ip:
                device.ip_address = new_ip
                changed_fields.append("ip_address")

            if changed_fields:
                stats["updated"] += 1
                stats[f"match_{match_rule}"] += 1
                report_rows.append(
                    {
                        "device_id": device_id,
                        "device_name": str(device.name or ""),
                        "status": "updated",
                        "match_rule": match_rule,
                        "changes": ",".join(changed_fields),
                    }
                )
            else:
                stats["already_ok"] += 1
                stats[f"match_{match_rule}"] += 1
                report_rows.append(
                    {
                        "device_id": device_id,
                        "device_name": str(device.name or ""),
                        "status": "already_ok",
                        "match_rule": match_rule,
                        "changes": "",
                    }
                )

        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"credentials_sync_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    with report_path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=["device_id", "device_name", "status", "match_rule", "changes"])
        writer.writeheader()
        writer.writerows(report_rows)

    print("sync_device_credentials_from_csv: OK")
    for key in sorted(stats):
        print(f"{key}={stats[key]}")
    print(f"report={report_path}")


if __name__ == "__main__":
    main()
