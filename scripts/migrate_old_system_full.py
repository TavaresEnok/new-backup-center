#!/usr/bin/env python3
"""
Migra dados do sistema antigo para o novo Backup Center.

Fluxo:
1) Limpa dados do tenant alvo (grupos, dispositivos, agendamentos e backups).
2) Importa provedores antigos como grupos.
3) Importa dispositivos + parametros.
4) Importa historico de log_backup (incluindo copia de arquivos quando existirem).
5) Corrige script_name de device_types conforme tipo_equipamento legado.
6) Gera relatorio de comparacao de scripts antigo x novo.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import psycopg2
import psycopg2.extras
from cryptography.fernet import Fernet


DEFAULT_OLD_SQL = Path("/home/app/projects/sistema_antigo_backup/backup_center_db.sql")
DEFAULT_OLD_BACKUPS = Path("/home/app/projects/sistema_antigo_backup/backups")
DEFAULT_NEW_BACKUPS = Path("/home/app/projects/backup_center/storage/backups")
DEFAULT_NEW_SCRIPT_DIR = Path("/home/app/projects/backup_center/app/scripts/backup_scripts")
DEFAULT_OLD_SCRIPT_DIR = Path("/home/app/projects/sistema_antigo_backup/backup_scripts")
DEFAULT_REPORT_DIR = Path("/home/app/projects/backup_center/reports")

LEGACY_FERNET_KEY = "QNfC_3GDRMkG8NN8Pw3fPbK1qhYBCoItYgEaXEEUZCU="

DB_DEFAULTS = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("DB_PORT", "5436")),
    "database": os.getenv("DB_NAME", "backup_center"),
    "user": os.getenv("DB_USER", "backup_user"),
    "password": os.getenv("DB_PASSWORD", "BackupSecure2024!"),
}


@dataclass
class Stats:
    groups_created: int = 0
    devices_created: int = 0
    schedules_created: int = 0
    backup_rows_created: int = 0
    backup_files_copied: int = 0
    backup_files_missing: int = 0
    device_types_updated: int = 0
    device_types_missing_script_file: int = 0
    legacy_type_rows_missing_in_new: int = 0


def load_env_file(env_path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not env_path.exists():
        return values
    for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        values[key.strip()] = val.strip()
    return values


def mysql_unescape(value: str) -> str:
    out: List[str] = []
    i = 0
    escapes = {
        "0": "\0",
        "b": "\b",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "Z": "\x1a",
        "\\": "\\",
        "'": "'",
        '"': '"',
    }
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            out.append(escapes.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def parse_scalar(raw: str):
    raw = raw.strip()
    if raw == "NULL":
        return None
    if raw.startswith("'") and raw.endswith("'"):
        return mysql_unescape(raw[1:-1])
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    if re.fullmatch(r"-?\d+\.\d+", raw):
        return float(raw)
    return raw


def iter_insert_value_blocks(sql_text: str, table_name: str) -> Iterable[str]:
    needle = f"INSERT INTO `{table_name}` VALUES"
    pos = 0
    while True:
        idx = sql_text.find(needle, pos)
        if idx == -1:
            break
        start = idx + len(needle)
        while start < len(sql_text) and sql_text[start].isspace():
            start += 1

        in_str = False
        esc = False
        depth = 0
        end = start
        while end < len(sql_text):
            ch = sql_text[end]
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == "'" and not esc:
                in_str = not in_str
            elif not in_str:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                elif ch == ";" and depth == 0:
                    break
            end += 1

        yield sql_text[start:end]
        pos = end + 1


def parse_values_block(values_str: str) -> List[Tuple]:
    rows: List[Tuple] = []
    current_row: List = []
    current_value: List[str] = []
    in_str = False
    esc = False
    depth = 0

    for ch in values_str:
        if esc:
            current_value.append(ch)
            esc = False
            continue
        if ch == "\\":
            current_value.append(ch)
            esc = True
            continue
        if ch == "'" and not esc:
            in_str = not in_str

        if not in_str:
            if ch == "(":
                depth += 1
                if depth == 1:
                    current_row = []
                    current_value = []
                    continue
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    if current_value or current_row:
                        current_row.append(parse_scalar("".join(current_value).strip()))
                    rows.append(tuple(current_row))
                    current_value = []
                    continue
            elif ch == "," and depth == 1:
                current_row.append(parse_scalar("".join(current_value).strip()))
                current_value = []
                continue

        if depth >= 1:
            current_value.append(ch)

    return rows


def parse_table_rows(sql_text: str, table_name: str) -> List[Tuple]:
    all_rows: List[Tuple] = []
    for block in iter_insert_value_blocks(sql_text, table_name):
        all_rows.extend(parse_values_block(block))
    return all_rows


def slugify(text: str, fallback: str) -> str:
    norm = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    norm = norm.lower()
    norm = re.sub(r"[^a-z0-9]+", "-", norm).strip("-")
    return norm[:150] if norm else fallback


def sanitize_path_piece(name: str) -> str:
    if not name:
        return "unnamed"
    sanitized = "".join(c for c in name if c.isalnum() or c in (" ", "_", "-")).strip().replace(" ", "_")
    return sanitized or "unnamed"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def decrypt_legacy_if_possible(cipher: Fernet, value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()
    if not value:
        return None
    if not value.startswith("gAAAAA"):
        return value
    try:
        return cipher.decrypt(value.encode()).decode()
    except Exception:
        return value


def map_legacy_path_to_source(old_path: str, old_backups_root: Path) -> Optional[Path]:
    if not old_path:
        return None
    candidates: List[Path] = []

    prefix = "/srv/mikrotik_manager/backups/"
    if old_path.startswith(prefix):
        candidates.append(old_backups_root / old_path[len(prefix):])
    if "/backups/" in old_path:
        candidates.append(old_backups_root / old_path.split("/backups/", 1)[1])
    candidates.append(old_backups_root / Path(old_path).name)

    for cand in candidates:
        if cand.exists() and cand.is_file():
            return cand
    return None


def read_script_hashes(script_dir: Path) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    if not script_dir.exists():
        return hashes
    for path in sorted(script_dir.glob("*.py")):
        hashes[path.name] = sha256_file(path)
    return hashes


def build_script_comparison_report(
    old_script_dir: Path,
    new_script_dir: Path,
    old_type_rows: List[Tuple],
    report_dir: Path,
) -> Dict:
    old_hashes = read_script_hashes(old_script_dir)
    new_hashes = read_script_hashes(new_script_dir)

    old_files = set(old_hashes.keys())
    new_files = set(new_hashes.keys())
    common = sorted(old_files & new_files)

    changed = [name for name in common if old_hashes[name] != new_hashes[name]]
    missing_in_new = sorted(old_files - new_files)
    missing_in_old = sorted(new_files - old_files)

    legacy_type_scripts = sorted({row[2] for row in old_type_rows if len(row) >= 3 and row[2]})
    scripts_referenced_but_absent = sorted(
        [name for name in legacy_type_scripts if name not in old_files and name not in new_files]
    )

    report = {
        "generated_at_utc": datetime.utcnow().isoformat(),
        "old_script_dir": str(old_script_dir),
        "new_script_dir": str(new_script_dir),
        "old_script_files": len(old_files),
        "new_script_files": len(new_files),
        "common_script_files": len(common),
        "changed_content_files": len(changed),
        "changed_files": changed,
        "missing_in_new": missing_in_new,
        "missing_in_old": missing_in_old,
        "legacy_type_scripts_referenced": legacy_type_scripts,
        "legacy_type_scripts_referenced_but_absent": scripts_referenced_but_absent,
    }

    report_dir.mkdir(parents=True, exist_ok=True)
    out = report_dir / "script_comparison_legacy_vs_new.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description="Migra dados do sistema antigo para o novo Backup Center.")
    parser.add_argument("--old-sql", default=str(DEFAULT_OLD_SQL))
    parser.add_argument("--old-backups", default=str(DEFAULT_OLD_BACKUPS))
    parser.add_argument("--new-backups", default=str(DEFAULT_NEW_BACKUPS))
    parser.add_argument("--tenant-slug", default="ajust-consulting")
    parser.add_argument("--db-host", default=DB_DEFAULTS["host"])
    parser.add_argument("--db-port", type=int, default=DB_DEFAULTS["port"])
    parser.add_argument("--db-name", default=DB_DEFAULTS["database"])
    parser.add_argument("--db-user", default=DB_DEFAULTS["user"])
    parser.add_argument("--db-password", default=DB_DEFAULTS["password"])
    parser.add_argument("--new-script-dir", default=str(DEFAULT_NEW_SCRIPT_DIR))
    parser.add_argument("--old-script-dir", default=str(DEFAULT_OLD_SCRIPT_DIR))
    parser.add_argument("--report-dir", default=str(DEFAULT_REPORT_DIR))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    old_sql_path = Path(args.old_sql)
    old_backups_root = Path(args.old_backups)
    new_backups_root = Path(args.new_backups)
    new_script_dir = Path(args.new_script_dir)
    old_script_dir = Path(args.old_script_dir)
    report_dir = Path(args.report_dir)

    if not old_sql_path.exists():
        raise FileNotFoundError(f"Dump SQL não encontrado: {old_sql_path}")
    if not old_backups_root.exists():
        raise FileNotFoundError(f"Diretório de backups antigo não encontrado: {old_backups_root}")

    env_values = load_env_file(Path("/home/app/projects/backup_center/.env"))
    new_fernet_key = env_values.get("ENCRYPTION_KEY") or os.getenv("ENCRYPTION_KEY")
    if not new_fernet_key:
        raise RuntimeError("ENCRYPTION_KEY não encontrado no .env e no ambiente.")

    legacy_cipher = Fernet(LEGACY_FERNET_KEY.encode())
    new_cipher = Fernet(new_fernet_key.encode())

    print(f"[1/8] Lendo SQL legado: {old_sql_path}")
    sql_text = old_sql_path.read_text(encoding="utf-8", errors="replace")

    print("[2/8] Parse das tabelas legadas...")
    provider_rows = parse_table_rows(sql_text, "provedor")
    type_rows = parse_table_rows(sql_text, "tipo_equipamento")
    device_rows = parse_table_rows(sql_text, "dispositivo")
    param_rows = parse_table_rows(sql_text, "parametro_dispositivo")
    log_rows = parse_table_rows(sql_text, "log_backup")
    setting_rows = parse_table_rows(sql_text, "setting")

    settings_map = {str(r[1]): str(r[2]) for r in setting_rows if len(r) >= 3}
    scheduler_hour = int(settings_map.get("scheduler_hour", "3"))
    scheduler_minute = int(settings_map.get("scheduler_minute", "0"))
    schedule_time = f"{scheduler_hour:02d}:{scheduler_minute:02d}"

    print(
        f"    provedores={len(provider_rows)} tipos={len(type_rows)} dispositivos={len(device_rows)} "
        f"parametros={len(param_rows)} log_backup={len(log_rows)}"
    )

    print("[3/8] Gerando comparação de scripts...")
    script_report = build_script_comparison_report(old_script_dir, new_script_dir, type_rows, report_dir)
    print(
        f"    scripts comuns={script_report['common_script_files']} "
        f"alterados={script_report['changed_content_files']} "
        f"ausentes (referenciados)={len(script_report['legacy_type_scripts_referenced_but_absent'])}"
    )

    print("[4/8] Conectando no PostgreSQL...")
    conn = psycopg2.connect(
        host=args.db_host,
        port=args.db_port,
        dbname=args.db_name,
        user=args.db_user,
        password=args.db_password,
    )
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    stats = Stats()
    started_at = datetime.utcnow()

    try:
        cur.execute("SELECT id, slug FROM tenants WHERE slug = %s", (args.tenant_slug,))
        tenant = cur.fetchone()
        if not tenant:
            raise RuntimeError(f"Tenant não encontrado: {args.tenant_slug}")
        tenant_id = tenant["id"]

        print(f"[5/8] Limpando dados do tenant {args.tenant_slug} ({tenant_id})...")
        cur.execute(
            """
            DELETE FROM backups b
            USING devices d
            WHERE b.device_id = d.id AND d.tenant_id = %s
            """,
            (tenant_id,),
        )
        cur.execute(
            """
            DELETE FROM schedules s
            USING devices d
            WHERE s.device_id = d.id AND d.tenant_id = %s
            """,
            (tenant_id,),
        )
        cur.execute("DELETE FROM devices WHERE tenant_id = %s", (tenant_id,))
        cur.execute("DELETE FROM device_groups WHERE tenant_id = %s", (tenant_id,))

        tenant_backup_dir = new_backups_root / args.tenant_slug
        if tenant_backup_dir.exists():
            shutil.rmtree(tenant_backup_dir)
        tenant_backup_dir.mkdir(parents=True, exist_ok=True)

        print("[6/8] Importando tipos, grupos, dispositivos e agendamentos...")

        # 6.1 Atualiza script_name dos tipos existentes com base no legado
        cur.execute("SELECT id, name, script_name FROM device_types")
        new_types = {row["name"]: row for row in cur.fetchall()}

        for row in type_rows:
            legacy_type_id, type_name, script_name, required_params = row[:4]
            new_row = new_types.get(type_name)
            if not new_row:
                stats.legacy_type_rows_missing_in_new += 1
                continue
            cur.execute(
                """
                UPDATE device_types
                SET script_name = %s, required_parameters = %s, updated_at = NOW()
                WHERE id = %s
                """,
                (script_name, required_params, new_row["id"]),
            )
            stats.device_types_updated += 1
            if script_name and not (new_script_dir / script_name).exists():
                stats.device_types_missing_script_file += 1

        # 6.2 Grupos (provedores)
        provider_map: Dict[int, uuid.UUID] = {}
        for row in provider_rows:
            (
                legacy_provider_id,
                provider_name,
                use_vpn,
                vpn_type,
                vpn_server,
                vpn_user,
                vpn_password_raw,
                vpn_ipsec_raw,
            ) = row[:8]

            vpn_password = decrypt_legacy_if_possible(legacy_cipher, vpn_password_raw)
            vpn_ipsec = decrypt_legacy_if_possible(legacy_cipher, vpn_ipsec_raw)
            vpn_password_enc = new_cipher.encrypt(vpn_password.encode()).decode() if vpn_password else None
            vpn_ipsec_enc = new_cipher.encrypt(vpn_ipsec.encode()).decode() if vpn_ipsec else None

            group_id = uuid.uuid4()
            slug = slugify(str(provider_name or ""), f"provedor-{legacy_provider_id}")
            cur.execute(
                """
                INSERT INTO device_groups (
                    id, tenant_id, name, slug, description, connection_type, uses_vpn, vpn_type, vpn_server, vpn_username,
                    vpn_password_encrypted, vpn_ipsec_secret_encrypted, is_active, created_at, updated_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, true, NOW(), NOW()
                )
                """,
                (
                    str(group_id),
                    tenant_id,
                    str(provider_name or f"Provedor {legacy_provider_id}")[:150],
                    slug,
                    f"Migrado do sistema antigo (provedor_id={legacy_provider_id})",
                    "vpn" if bool(use_vpn) else "direct",
                    bool(use_vpn),
                    (vpn_type or "l2tp")[:50] if vpn_type else "l2tp",
                    vpn_server,
                    vpn_user,
                    vpn_password_enc,
                    vpn_ipsec_enc,
                ),
            )
            provider_map[int(legacy_provider_id)] = group_id
            stats.groups_created += 1

        # 6.3 Mapa de tipo por nome
        cur.execute("SELECT id, name FROM device_types")
        type_name_to_id = {row["name"]: row["id"] for row in cur.fetchall()}
        legacy_type_name = {int(row[0]): row[1] for row in type_rows if row and row[0] is not None}

        # 6.4 Parametros por device
        params_by_device: Dict[int, Dict[str, str]] = {}
        for row in param_rows:
            _, param_name, param_value_raw, legacy_device_id = row[:4]
            if legacy_device_id is None:
                continue
            legacy_device_id = int(legacy_device_id)
            params_by_device.setdefault(legacy_device_id, {})
            value_dec = decrypt_legacy_if_possible(legacy_cipher, param_value_raw)
            params_by_device[legacy_device_id][str(param_name)] = value_dec if value_dec is not None else ""

        # 6.5 Dispositivos
        legacy_device_to_new: Dict[int, Dict] = {}
        for row in device_rows:
            legacy_device_id = int(row[0])
            name = (str(row[1] or "").strip() or f"Dispositivo_{legacy_device_id}")[:100]
            ip_addr = (str(row[2] or "").strip() or "0.0.0.0")[:45]
            username = (str(row[3] or "").strip() or "admin")[:50]
            port = int(row[4] or 22)
            backup_scheduled = bool(row[5])
            legacy_provider_id = int(row[6]) if row[6] is not None else None
            legacy_type_id = int(row[7]) if row[7] is not None else None
            is_legacy = bool(row[8]) if len(row) > 8 else False
            use_telnet = bool(row[9]) if len(row) > 9 else False
            is_vpn_gateway = bool(row[10]) if len(row) > 10 else False

            legacy_params = dict(params_by_device.get(legacy_device_id, {}))
            plain_password = legacy_params.pop("password", None) or "SENHA_NAO_MIGRADA"
            password_encrypted = new_cipher.encrypt(plain_password.encode()).decode()

            type_name = legacy_type_name.get(legacy_type_id)
            device_type_id = type_name_to_id.get(type_name) if type_name else None
            group_id = provider_map.get(legacy_provider_id) if legacy_provider_id is not None else None

            device_id = uuid.uuid4()
            cur.execute(
                """
                INSERT INTO devices (
                    id, tenant_id, group_id, device_type_id, legacy_id, name, ip_address, port, username,
                    password_encrypted, use_telnet, is_vpn_gateway, backup_scheduled, description,
                    extra_parameters, is_active, last_backup_status, last_connection_status, created_at, updated_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb,
                    true, 'never', 'unknown', NOW(), NOW()
                )
                """,
                (
                    str(device_id),
                    tenant_id,
                    str(group_id) if group_id else None,
                    str(device_type_id) if device_type_id else None,
                    legacy_device_id,
                    name,
                    ip_addr,
                    port,
                    username,
                    password_encrypted,
                    use_telnet,
                    is_vpn_gateway,
                    backup_scheduled,
                    "Migrado do sistema antigo" + (" (legacy)" if is_legacy else ""),
                    json.dumps(legacy_params, ensure_ascii=False),
                ),
            )

            legacy_device_to_new[legacy_device_id] = {
                "id": device_id,
                "name": name,
                "group_id": group_id,
                "backup_scheduled": backup_scheduled,
            }
            stats.devices_created += 1

            if backup_scheduled:
                sched_id = uuid.uuid4()
                cur.execute(
                    """
                    INSERT INTO schedules (
                        id, device_id, frequency, time, day_of_week, day_of_month, is_active,
                        created_at, updated_at
                    ) VALUES (
                        %s, %s, 'daily', %s, NULL, NULL, true, NOW(), NOW()
                    )
                    """,
                    (str(sched_id), str(device_id), schedule_time),
                )
                stats.schedules_created += 1

        print("[7/8] Importando histórico de backups e copiando arquivos...")
        device_latest: Dict[uuid.UUID, Tuple[datetime, str]] = {}
        backup_rows_to_insert: List[Tuple] = []
        seen_file_rel_paths: set = set()

        cur.execute("SELECT id, name FROM device_groups WHERE tenant_id = %s", (tenant_id,))
        group_id_to_name = {row["id"]: row["name"] for row in cur.fetchall()}

        for row in log_rows:
            # log_backup: id, timestamp, status, mensagem, caminho_arquivo, dispositivo_id, error_category
            _, log_ts_raw, legacy_status, message, legacy_file_path, legacy_device_id_raw, _ = row[:7]
            if legacy_device_id_raw is None:
                continue
            legacy_device_id = int(legacy_device_id_raw)
            device_info = legacy_device_to_new.get(legacy_device_id)
            if not device_info:
                continue

            log_ts = parse_dt(log_ts_raw) or datetime.utcnow()
            status_legacy = (legacy_status or "").strip().lower()
            if status_legacy == "sucesso":
                status_new = "success"
            elif status_legacy == "falha":
                status_new = "failed"
            elif status_legacy == "pendente":
                status_new = "pending"
            else:
                status_new = "failed"

            new_rel_path = None
            file_size = None
            file_hash = None
            source_path = map_legacy_path_to_source(str(legacy_file_path), old_backups_root) if legacy_file_path else None

            if source_path:
                group_name = group_id_to_name.get(device_info["group_id"], "Sem Grupo")
                target_dir = (
                    new_backups_root
                    / args.tenant_slug
                    / sanitize_path_piece(group_name)
                    / sanitize_path_piece(device_info["name"])
                )
                target_dir.mkdir(parents=True, exist_ok=True)
                target_file = target_dir / source_path.name
                new_rel_path = str(target_file.relative_to(new_backups_root))

                if new_rel_path not in seen_file_rel_paths:
                    shutil.copy2(source_path, target_file)
                    stats.backup_files_copied += 1
                    seen_file_rel_paths.add(new_rel_path)

                file_size = target_file.stat().st_size
                file_hash = sha256_file(target_file)
            elif legacy_file_path and status_new == "success":
                stats.backup_files_missing += 1

            backup_id = uuid.uuid4()
            backup_rows_to_insert.append(
                (
                    str(backup_id),
                    str(device_info["id"]),
                    new_rel_path,
                    file_size,
                    file_hash,
                    status_new,
                    (str(message)[:10000] if message else None),
                    log_ts,
                    log_ts,
                    False,
                    log_ts,
                )
            )

            prev = device_latest.get(device_info["id"])
            if prev is None or log_ts > prev[0]:
                final_status = "success" if status_new == "success" else ("failure" if status_new == "failed" else "never")
                device_latest[device_info["id"]] = (log_ts, final_status)

        psycopg2.extras.execute_batch(
            cur,
            """
            INSERT INTO backups (
                id, device_id, file_path, file_size_bytes, hash_sha256, status, error_message,
                started_at, completed_at, is_manual, created_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            """,
            backup_rows_to_insert,
            page_size=1000,
        )
        stats.backup_rows_created = len(backup_rows_to_insert)

        for device_id, (last_ts, last_status) in device_latest.items():
            cur.execute(
                """
                UPDATE devices
                SET last_backup_at = %s, last_backup_status = %s, updated_at = NOW()
                WHERE id = %s
                """,
                (last_ts, last_status, str(device_id)),
            )

        if args.dry_run:
            conn.rollback()
            print("[8/8] DRY-RUN concluído (rollback aplicado).")
        else:
            conn.commit()
            print("[8/8] Migração concluída e commit aplicado.")

        ended_at = datetime.utcnow()
        print("\nResumo:")
        print(f"  Início UTC: {started_at.isoformat()}")
        print(f"  Fim UTC:    {ended_at.isoformat()}")
        print(f"  Grupos criados:                    {stats.groups_created}")
        print(f"  Dispositivos criados:              {stats.devices_created}")
        print(f"  Agendamentos criados:              {stats.schedules_created}")
        print(f"  Backups (linhas) importados:       {stats.backup_rows_created}")
        print(f"  Arquivos de backup copiados:       {stats.backup_files_copied}")
        print(f"  Arquivos de backup ausentes:       {stats.backup_files_missing}")
        print(f"  Device types atualizados:          {stats.device_types_updated}")
        print(f"  Tipos com script ausente em disco: {stats.device_types_missing_script_file}")
        print(f"  Tipos legados ausentes no novo:    {stats.legacy_type_rows_missing_in_new}")
        print(f"  Relatório scripts: {report_dir / 'script_comparison_legacy_vs_new.json'}")

    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()
