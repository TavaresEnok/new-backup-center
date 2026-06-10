#!/usr/bin/env python3
"""Migrate legacy Mikrotik Manager (MariaDB + files) to new Backup Center (PostgreSQL)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import pymysql
import psycopg2
import psycopg2.extras
from cryptography.fernet import Fernet
from passlib.context import CryptContext

# Legacy (old system)
MYSQL_CONFIG = {
    "host": os.getenv("LEGACY_DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("LEGACY_DB_PORT", "3306")),
    "user": os.getenv("LEGACY_DB_USER", "backup_user"),
    "password": os.getenv("LEGACY_DB_PASSWORD", "AezakmipHIMpTiONIEl"),
    "database": os.getenv("LEGACY_DB_NAME", "backup_center_db"),
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
}

# New system
PG_CONFIG = {
    "host": os.getenv("NEW_DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("NEW_DB_PORT", "5436")),
    "user": os.getenv("NEW_DB_USER", "backup_user"),
    "password": os.getenv("NEW_DB_PASSWORD", "BackupSecure2024!"),
    "dbname": os.getenv("NEW_DB_NAME", "backup_center"),
}

NEW_STORAGE_ROOT = Path(os.getenv("NEW_STORAGE_ROOT", "/new/storage/backups"))
LEGACY_BACKUP_ROOT = Path(os.getenv("LEGACY_BACKUP_ROOT", "/old/backups"))
TARGET_FILE_PREFIX = os.getenv("TARGET_FILE_PREFIX", "ajust-consulting-legacy")
TENANT_SLUG = os.getenv("TENANT_SLUG", "ajust-consulting")
TENANT_NAME = os.getenv("TENANT_NAME", "Ajust Consulting")
TENANT_EMAIL = os.getenv("TENANT_EMAIL", "contato@ajustconsulting.com.br")

LEGACY_FERNET_KEY = os.getenv("LEGACY_FERNET_KEY", "QNfC_3GDRMkG8NN8Pw3fPbK1qhYBCoItYgEaXEEUZCU=")
NEW_ENCRYPTION_KEY = os.getenv("NEW_ENCRYPTION_KEY")

if not NEW_ENCRYPTION_KEY:
    raise RuntimeError("NEW_ENCRYPTION_KEY is required")

legacy_fernet = Fernet(LEGACY_FERNET_KEY.encode())
new_fernet = Fernet(NEW_ENCRYPTION_KEY.encode())
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

SUPER_ADMIN_EMAILS = {
    "admin@backupcenter.com",
}
TENANT_OWNER_EMAILS = {
    "enok@ajustconsulting.com.br",
    "audemario@ajustconsulting.com.br",
    "arthur@ajustconsulting.com.br",
    "cleyton@ajustconsulting.com.br",
}


def sanitize_slug(value: str, max_len: int = 150) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", value.lower().strip())
    slug = re.sub(r"-+", "-", slug).strip("-")
    return (slug or "item")[:max_len]


def decrypt_legacy_blob(blob_value) -> str | None:
    if not blob_value:
        return None
    try:
        if isinstance(blob_value, str):
            raw = blob_value.encode()
        else:
            raw = bytes(blob_value)
        return legacy_fernet.decrypt(raw).decode()
    except Exception:
        return None


def encrypt_new(value: str | None) -> str | None:
    if not value:
        return None
    return new_fernet.encrypt(value.encode()).decode()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_legacy_datetime(value) -> datetime:
    if isinstance(value, datetime):
        return value
    if value is None:
        return datetime.utcnow()
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
    return datetime.utcnow()


def normalize_email(username: str) -> str:
    username = (username or "").strip().lower()
    if "@" in username:
        return username
    return f"{username}@ajustconsulting.com.br"


def resolve_user_role(email: str, is_admin: int):
    if email in SUPER_ADMIN_EMAILS:
        return "SUPER_ADMIN", None
    if email in TENANT_OWNER_EMAILS:
        return "TENANT_OWNER", "tenant"
    if int(is_admin or 0) == 1:
        return "TENANT_ADMIN", "tenant"
    return "TENANT_TECHNICIAN", "tenant"


def category_from_type(name: str) -> str:
    v = (name or "").lower()
    if "mikrotik" in v or "router" in v or "ne" in v:
        return "router"
    if "olt" in v:
        return "olt"
    if "switch" in v:
        return "switch"
    if "firewall" in v:
        return "firewall"
    if "zabbix" in v or "grafana" in v:
        return "server"
    if "erp" in v:
        return "erp"
    return "other"


def main() -> int:
    print("[1/7] Connecting databases...")
    my = pymysql.connect(**MYSQL_CONFIG)
    pg = psycopg2.connect(**PG_CONFIG)
    pg.autocommit = False

    stats = {
        "users": 0,
        "types": 0,
        "groups": 0,
        "devices": 0,
        "backups_rows": 0,
        "files_copied": 0,
        "files_missing": 0,
    }

    try:
        with my.cursor() as myc, pg.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as pgc:
            print("[2/7] Ensuring tenant exists...")
            pgc.execute("SELECT id FROM tenants WHERE slug=%s", (TENANT_SLUG,))
            row = pgc.fetchone()
            if row:
                tenant_id = row["id"]
            else:
                tenant_id = str(uuid.uuid4())
                pgc.execute(
                    """
                    INSERT INTO tenants (id, name, slug, company_name, email, is_active, subscription_status, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, true, 'active', NOW(), NOW())
                    """,
                    (tenant_id, TENANT_NAME, TENANT_SLUG, TENANT_NAME, TENANT_EMAIL),
                )

            # Clean existing tenant data for full re-import
            print("[3/7] Cleaning tenant data for full re-import...")
            pgc.execute("DELETE FROM backups b USING devices d WHERE b.device_id=d.id AND d.tenant_id=%s", (tenant_id,))
            pgc.execute("DELETE FROM schedules s USING devices d WHERE s.device_id=d.id AND d.tenant_id=%s", (tenant_id,))
            pgc.execute("DELETE FROM devices WHERE tenant_id=%s", (tenant_id,))
            pgc.execute("DELETE FROM device_groups WHERE tenant_id=%s", (tenant_id,))

            # Users
            print("[4/7] Migrating users...")
            myc.execute("SELECT id, username, is_admin FROM user ORDER BY id")
            for u in myc.fetchall():
                email = normalize_email(u["username"])
                role, target = resolve_user_role(email, u["is_admin"])
                tenant_for_user = tenant_id if target == "tenant" else None
                name = email.split("@")[0].replace(".", " ").replace("_", " ").title()
                password_hash = pwd_context.hash("123456")

                pgc.execute("SELECT id FROM users WHERE email=%s", (email,))
                existing = pgc.fetchone()
                if existing:
                    pgc.execute(
                        """
                        UPDATE users
                        SET tenant_id=%s, full_name=%s, password_hash=%s, role=%s, is_active=true, email_verified=true, updated_at=NOW()
                        WHERE id=%s
                        """,
                        (tenant_for_user, name, password_hash, role, existing["id"]),
                    )
                else:
                    pgc.execute(
                        """
                        INSERT INTO users (id, tenant_id, email, full_name, password_hash, role, is_active, email_verified, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, true, true, NOW(), NOW())
                        """,
                        (str(uuid.uuid4()), tenant_for_user, email, name, password_hash, role),
                    )
                stats["users"] += 1

            # Device types
            print("[5/7] Migrating device types, groups and devices...")
            myc.execute("SELECT id, nome, script_backup, parametros_necessarios FROM tipo_equipamento ORDER BY id")
            type_id_map = {}
            for t in myc.fetchall():
                type_name = t["nome"].strip()
                slug = sanitize_slug(type_name.replace("_", "-"), 100)
                pgc.execute("SELECT id FROM device_types WHERE name=%s", (type_name,))
                ex = pgc.fetchone()
                if ex:
                    type_id_map[t["id"]] = ex["id"]
                else:
                    new_id = str(uuid.uuid4())
                    pgc.execute(
                        """
                        INSERT INTO device_types (id, name, slug, description, script_name, required_parameters, default_port, use_telnet, is_active, category, created_at, updated_at)
                        VALUES (%s,%s,%s,%s,%s,%s,22,false,true,%s,NOW(),NOW())
                        """,
                        (
                            new_id,
                            type_name,
                            slug,
                            f"Migrado do legado: {type_name}",
                            (t["script_backup"] or "").strip() or "mikrotik_ros_netmiko.py",
                            t["parametros_necessarios"],
                            category_from_type(type_name),
                        ),
                    )
                    type_id_map[t["id"]] = new_id
                    stats["types"] += 1

            # Providers -> groups
            myc.execute(
                "SELECT id, nome, usa_vpn, vpn_tipo, vpn_servidor, vpn_usuario, vpn_senha, vpn_ipsec_secret FROM provedor ORDER BY id"
            )
            group_id_map = {}
            for p in myc.fetchall():
                group_id = str(uuid.uuid4())
                name = p["nome"].strip()
                slug = sanitize_slug(name)
                connection_type = "vpn" if int(p["usa_vpn"] or 0) == 1 else "direct"
                pgc.execute(
                    """
                    INSERT INTO device_groups (
                        id, tenant_id, name, slug, description, connection_type, uses_vpn, vpn_type, vpn_server, vpn_username,
                        vpn_password_encrypted, vpn_ipsec_secret_encrypted, uses_jump_host, jump_host, jump_port, jump_username,
                        jump_password_encrypted, jump_key_encrypted, is_active, created_at, updated_at
                    )
                    VALUES (
                        %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                        %s,%s,false,NULL,22,NULL,
                        NULL,NULL,true,NOW(),NOW()
                    )
                    """,
                    (
                        group_id,
                        tenant_id,
                        name,
                        slug,
                        f"Migrado do provedor legado: {name}",
                        connection_type,
                        bool(int(p["usa_vpn"] or 0)),
                        (p["vpn_tipo"] or "l2tp"),
                        p["vpn_servidor"],
                        p["vpn_usuario"],
                        encrypt_new(decrypt_legacy_blob(p["vpn_senha"])),
                        encrypt_new(decrypt_legacy_blob(p["vpn_ipsec_secret"])),
                    ),
                )
                group_id_map[p["id"]] = group_id
                stats["groups"] += 1

            # Params by device
            myc.execute("SELECT dispositivo_id, nome, valor FROM parametro_dispositivo")
            params_by_device = defaultdict(dict)
            for pr in myc.fetchall():
                params_by_device[pr["dispositivo_id"]][pr["nome"]] = decrypt_legacy_blob(pr["valor"])

            # Devices
            myc.execute(
                """
                SELECT id, nome, ip, usuario, porta, backup_agendado, provedor_id, tipo_id, is_legacy, use_telnet, is_vpn_gateway
                FROM dispositivo ORDER BY id
                """
            )
            legacy_to_new_device = {}
            new_device_meta = {}
            for d in myc.fetchall():
                dev_id = str(uuid.uuid4())
                params = dict(params_by_device.get(d["id"], {}))
                plain_password = params.pop("password", None) or "123456"
                encrypted_password = encrypt_new(plain_password)
                group_id = group_id_map.get(d["provedor_id"])
                type_id = type_id_map.get(d["tipo_id"])
                name = (d["nome"] or f"device-{d['id']}").strip()
                ip = (d["ip"] or "0.0.0.0").strip()

                pgc.execute(
                    """
                    INSERT INTO devices (
                        id, tenant_id, group_id, device_type_id, legacy_id, name, ip_address, port, username, password_encrypted,
                        use_telnet, is_vpn_gateway, backup_scheduled, model, firmware_version, description, tags, extra_parameters,
                        is_active, last_backup_at, last_backup_status, last_connection_status, created_at, updated_at
                    )
                    VALUES (
                        %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                        %s,%s,%s,NULL,NULL,%s,'[]'::json,%s,
                        true,NULL,'never','unknown',NOW(),NOW()
                    )
                    """,
                    (
                        dev_id,
                        tenant_id,
                        group_id,
                        type_id,
                        d["id"],
                        name,
                        ip,
                        int(d["porta"] or 22),
                        (d["usuario"] or "admin")[:50],
                        encrypted_password,
                        bool(int(d.get("use_telnet") or 0)),
                        bool(int(d.get("is_vpn_gateway") or 0)),
                        bool(int(d.get("backup_agendado") or 0)),
                        f"Migrado do legado (id={d['id']})",
                        psycopg2.extras.Json({k: v for k, v in params.items() if v not in (None, "")}),
                    ),
                )

                if bool(int(d.get("backup_agendado") or 0)):
                    pgc.execute(
                        """
                        INSERT INTO schedules (id, device_id, frequency, time, day_of_week, day_of_month, is_active, last_run_at, next_run_at, created_at, updated_at)
                        VALUES (%s, %s, 'daily', '03:00', NULL, NULL, true, NULL, NULL, NOW(), NOW())
                        """,
                        (str(uuid.uuid4()), dev_id),
                    )

                legacy_to_new_device[d["id"]] = dev_id
                new_device_meta[d["id"]] = {
                    "name": name,
                    "group_name": next((k for k, v in group_id_map.items() if v == group_id), None),
                    "group_id": group_id,
                }
                stats["devices"] += 1

            # For path mapping, fetch group names by old provider id
            myc.execute("SELECT id, nome FROM provedor")
            provider_name = {r["id"]: r["nome"] for r in myc.fetchall()}
            myc.execute("SELECT id, nome, provedor_id FROM dispositivo")
            device_info = {r["id"]: r for r in myc.fetchall()}

            print("[6/7] Migrating backup logs and file paths...")
            myc.execute(
                "SELECT id, timestamp, status, mensagem, caminho_arquivo, dispositivo_id FROM log_backup ORDER BY id"
            )

            latest_status_by_device = {}
            backup_rows = []
            copied_cache = {}

            target_root = NEW_STORAGE_ROOT / TARGET_FILE_PREFIX
            target_root.mkdir(parents=True, exist_ok=True)

            for lb in myc.fetchall():
                old_device_id = lb["dispositivo_id"]
                new_device_id = legacy_to_new_device.get(old_device_id)
                if not new_device_id:
                    continue

                raw_status = (lb["status"] or "").strip().lower()
                status = "success" if raw_status.startswith("sucesso") else "failed"
                started_at = parse_legacy_datetime(lb["timestamp"])
                message = (lb["mensagem"] or "").strip() or None

                rel_path = None
                file_size = None
                file_hash = None

                src_path_str = lb["caminho_arquivo"]
                if src_path_str:
                    src_path = Path(src_path_str)
                    if not src_path.exists() and str(src_path).startswith("/srv/mikrotik_manager/"):
                        src_path = Path(str(src_path).replace("/srv/mikrotik_manager/", "/old/", 1))
                    if src_path.exists() and src_path.is_file():
                        if str(src_path).startswith(str(LEGACY_BACKUP_ROOT)):
                            rel_from_legacy = src_path.relative_to(LEGACY_BACKUP_ROOT)
                        elif str(src_path).startswith("/old/backups/"):
                            rel_from_legacy = src_path.relative_to(Path("/old/backups"))
                        else:
                            rel_from_legacy = Path(src_path.name)
                        dst_path = target_root / rel_from_legacy
                        dst_path.parent.mkdir(parents=True, exist_ok=True)
                        key = str(src_path)
                        if key not in copied_cache:
                            if not dst_path.exists() or dst_path.stat().st_size != src_path.stat().st_size:
                                shutil.copy2(src_path, dst_path)
                                stats["files_copied"] += 1
                            copied_cache[key] = dst_path
                        else:
                            dst_path = copied_cache[key]

                        rel_path = f"{TARGET_FILE_PREFIX}/{rel_from_legacy.as_posix()}"
                        file_size = int(dst_path.stat().st_size)
                        file_hash = sha256_file(dst_path)
                    else:
                        stats["files_missing"] += 1
                        if status == "success":
                            status = "failed"
                            if not message:
                                message = "Arquivo de backup não encontrado no legado durante migração"

                backup_rows.append(
                    (
                        str(uuid.uuid4()),
                        new_device_id,
                        rel_path,
                        file_size,
                        file_hash,
                        status,
                        message,
                        started_at,
                        started_at,
                        started_at,
                        False,
                    )
                )

                prev = latest_status_by_device.get(new_device_id)
                if prev is None or started_at > prev[0]:
                    latest_status_by_device[new_device_id] = (started_at, status)

            if backup_rows:
                psycopg2.extras.execute_values(
                    pgc,
                    """
                    INSERT INTO backups (
                        id, device_id, file_path, file_size_bytes, hash_sha256, status, error_message,
                        started_at, completed_at, created_at, is_manual, triggered_by_user_id
                    ) VALUES %s
                    """,
                    backup_rows,
                    template="(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL)",
                    page_size=1000,
                )
                stats["backups_rows"] = len(backup_rows)

            for dev_id, (last_at, st) in latest_status_by_device.items():
                pgc.execute(
                    "UPDATE devices SET last_backup_at=%s, last_backup_status=%s, updated_at=NOW() WHERE id=%s",
                    (last_at, st, dev_id),
                )

        pg.commit()
        print("[7/7] Migration committed.")
        print(json.dumps(stats, ensure_ascii=False))
        return 0
    except Exception as exc:
        pg.rollback()
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
    finally:
        my.close()
        pg.close()


if __name__ == "__main__":
    raise SystemExit(main())
