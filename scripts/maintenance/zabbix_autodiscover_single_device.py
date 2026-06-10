#!/usr/bin/env python3
"""
Autodetecta e opcionalmente aplica credenciais de banco do Zabbix em 1 dispositivo.

Uso:
  python scripts/maintenance/zabbix_autodiscover_single_device.py \
      --device-id <uuid> --dry-run

  python scripts/maintenance/zabbix_autodiscover_single_device.py \
      --device-id <uuid> --apply
"""

from __future__ import annotations

import argparse
import json
import uuid
from typing import Any

from app.core.database import SessionLocal
from app.core.security import decrypt_password
from app.models.device import Device

ZABBIX_AUTODISCOVERY_MODE_KEY = "db_credentials_mode"
ZABBIX_AUTODISCOVERY_MODE_AUTOMATIC = "automatic"
ZABBIX_DEFAULT_EXCLUDE_TABLES = (
    "history,history_uint,history_str,history_log,history_text,trends,trends_uint"
)
ZABBIX_DB_CONF_PATH = "/etc/zabbix/zabbix_server.conf"


def _mask(value: str) -> str:
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 3:
        return "*" * len(text)
    return f"{text[:2]}{'*' * (len(text) - 3)}{text[-1]}"


def _is_zabbix_device(device: Device) -> bool:
    script_name = str(getattr(getattr(device, "type", None), "script_name", "") or "").strip().lower()
    return script_name == "zabbix_backup.py"


def _safe_extra(device: Device) -> dict[str, Any]:
    raw = getattr(device, "extra_parameters", None)
    return dict(raw) if isinstance(raw, dict) else {}


def _parse_zabbix_db_config(output: str) -> dict[str, str]:
    parsed = {}
    for raw_line in str(output or "").splitlines():
        line = str(raw_line or "").strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key not in {"DBName", "DBUser", "DBPassword"}:
            continue
        if (
            (value.startswith('"') and value.endswith('"'))
            or (value.startswith("'") and value.endswith("'"))
        ):
            value = value[1:-1]
        parsed[key] = value
    return parsed


def _discover_zabbix_db_params_ssh(host: str, port: int, username: str, password: str) -> dict[str, str]:
    from netmiko import ConnectHandler

    device_config = {
        "device_type": "linux",
        "host": host,
        "port": int(port),
        "username": username,
        "password": password,
        "conn_timeout": 35,
        "banner_timeout": 35,
        "auth_timeout": 35,
        "fast_cli": False,
    }
    commands = [
        f"grep -E '^(DB(Name|User|Password))=' {ZABBIX_DB_CONF_PATH} 2>/dev/null",
        f"sudo grep -E '^(DB(Name|User|Password))=' {ZABBIX_DB_CONF_PATH} 2>/dev/null",
        f"sudo -n grep -E '^(DB(Name|User|Password))=' {ZABBIX_DB_CONF_PATH} 2>/dev/null",
    ]
    with ConnectHandler(**device_config) as net_connect:
        if hasattr(net_connect, "is_alive") and not net_connect.is_alive():
            raise RuntimeError("Conexao SSH estabelecida, mas sessao nao permaneceu ativa.")
        probe = net_connect.send_command_timing(
            "echo __BC_ZABBIX_AUTODISCOVERY_OK__",
            read_timeout=15,
            strip_command=False,
            strip_prompt=False,
        )
        if "__BC_ZABBIX_AUTODISCOVERY_OK__" not in str(probe or ""):
            raise RuntimeError("Conexao SSH valida, mas shell remoto nao respondeu conforme esperado.")
        parsed = {}
        for command in commands:
            output = net_connect.send_command_timing(
                command,
                read_timeout=20,
                strip_command=False,
                strip_prompt=False,
            )
            parsed = _parse_zabbix_db_config(output)
            if parsed:
                break
        if not parsed:
            raise RuntimeError(
                (
                    f"Nao foi possivel ler DBName/DBUser/DBPassword em {ZABBIX_DB_CONF_PATH}. "
                    "Valide permissao de leitura e conteudo do arquivo."
                )
            )
        return parsed


def run(device_id: str, apply_changes: bool) -> int:
    db = SessionLocal()
    try:
        try:
            device_uuid = uuid.UUID(str(device_id))
        except Exception:
            print(f"[ERRO] device_id invalido: {device_id}")
            return 2

        device = db.query(Device).filter(Device.id == device_uuid).first()
        if not device:
            print(f"[ERRO] dispositivo nao encontrado: {device_uuid}")
            return 3

        if not _is_zabbix_device(device):
            script_name = str(getattr(getattr(device, "type", None), "script_name", "") or "")
            print(
                "[ERRO] dispositivo nao usa script Zabbix.\n"
                f"       script_name atual: {script_name or '(vazio)'}"
            )
            return 4

        host = str(getattr(device, "ip_address", "") or "").strip()
        username = str(getattr(device, "username", "") or "").strip()
        port = int(getattr(device, "port", 22) or 22)
        ssh_password = decrypt_password(getattr(device, "password_encrypted", None))
        if not host or not username or not ssh_password:
            print("[ERRO] host/usuario/senha SSH ausentes para autodeteccao.")
            return 5

        before = _safe_extra(device)
        print("[INFO] dispositivo:", str(device.id))
        print("[INFO] nome:", str(getattr(device, "name", "") or ""))
        print("[INFO] host:", host, "porta:", port, "usuario:", username)
        print("[INFO] estado atual:", json.dumps(
            {
                "db_type": before.get("db_type"),
                "db_name": before.get("db_name"),
                "db_user": before.get("db_user"),
                "db_password": _mask(str(before.get("db_password") or "")),
                "exclude_tables": before.get("exclude_tables"),
                "db_credentials_mode": before.get(ZABBIX_AUTODISCOVERY_MODE_KEY),
            },
            ensure_ascii=True,
        ))

        discovered = _discover_zabbix_db_params_ssh(
            host=host,
            port=port,
            username=username,
            password=ssh_password,
        )

        found_name = str(discovered.get("DBName", "") or "").strip()
        found_user = str(discovered.get("DBUser", "") or "").strip()
        found_password = str(discovered.get("DBPassword", "") or "").strip()
        if not all([found_name, found_user, found_password]):
            print("[ERRO] autodeteccao incompleta (DBName/DBUser/DBPassword).")
            return 6

        print("[INFO] autodeteccao OK:")
        print("       DBName:", found_name)
        print("       DBUser:", found_user)
        print("       DBPassword:", _mask(found_password))

        if not apply_changes:
            print("[DRY-RUN] nenhuma alteracao gravada.")
            return 0

        after = dict(before)
        after["db_type"] = str(after.get("db_type") or "postgres").strip().lower()
        if after["db_type"] not in {"postgres", "mysql"}:
            after["db_type"] = "postgres"
        after["db_name"] = found_name
        after["db_user"] = found_user
        after["db_password"] = found_password
        after["exclude_tables"] = str(after.get("exclude_tables") or "").strip() or ZABBIX_DEFAULT_EXCLUDE_TABLES
        after[ZABBIX_AUTODISCOVERY_MODE_KEY] = ZABBIX_AUTODISCOVERY_MODE_AUTOMATIC

        device.extra_parameters = after
        db.commit()
        print("[APPLY] alteracoes aplicadas com sucesso.")
        return 0
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        print(f"[ERRO] falha ao processar dispositivo: {exc}")
        return 1
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Autodetecta credenciais DB de 1 Zabbix por device_id.")
    parser.add_argument("--device-id", required=True, help="UUID do dispositivo.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Somente validar/autodetectar, sem salvar.")
    mode.add_argument("--apply", action="store_true", help="Aplicar no extra_parameters.")
    args = parser.parse_args()
    return run(args.device_id, apply_changes=bool(args.apply))


if __name__ == "__main__":
    raise SystemExit(main())
