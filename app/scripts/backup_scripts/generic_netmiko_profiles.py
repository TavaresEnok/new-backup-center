import re
from typing import Dict, List, Tuple

from netmiko import ConnectHandler

from script_helpers import (
    BackupLogger,
    friendly_failure_message,
    friendly_unexpected_error,
    netmiko_send_command_interactive,
    prepare_backup_path,
)

ERROR_MARKERS = (
    "invalid",
    "bad command",
    "incomplete command",
    "error:",
    "unknown command",
    "unrecognized",
    "not supported",
)
NETWORK_ERROR_MARKERS = (
    "timeout",
    "timed out",
    "no route to host",
    "connection refused",
    "tcp connection to device failed",
    "no existing session",
    "timeout opening channel",
    "channelexception",
    "eoferror",
    "connection reset by peer",
)
AUTH_ERROR_MARKERS = (
    "authentication failed",
    "auth failed",
    "permission denied",
    "invalid password",
    "login failed",
)


def _looks_invalid(output: str) -> bool:
    text = (output or "").lower()
    return any(marker in text for marker in ERROR_MARKERS)


def _classify_connection_failure(detail: str) -> str:
    lowered = (detail or "").lower()
    if any(marker in lowered for marker in NETWORK_ERROR_MARKERS):
        return "CONEXAO"
    if any(marker in lowered for marker in AUTH_ERROR_MARKERS):
        return "AUTENTICACAO"
    return "AUTENTICACAO"


def _with_telnet_fallback(candidates: List[str], use_telnet: bool) -> List[str]:
    if not use_telnet:
        return candidates
    telnet_first = []
    for item in candidates:
        if item.endswith("_telnet"):
            telnet_first.append(item)
        elif item in ("cisco_ios", "huawei"):
            telnet_first.append(f"{item}_telnet")
    return list(dict.fromkeys(telnet_first + candidates))


PROFILE_MAP: Dict[str, Dict[str, List[str]]] = {
    "switch_tplink": {
        "candidates": ["tplink_jetstream", "cisco_ios"],
        "paging": ["terminal length 0", "terminal datadump", "no page", "screen-length disable"],
        "backup": ["show running-config", "show startup-config"],
    },
    "switch_juniper": {
        "candidates": ["juniper_junos"],
        "paging": ["set cli screen-length 0", "set cli screen-width 0"],
        "backup": ["show configuration | display set", "show configuration"],
    },
    "switch_ubiquiti": {
        "candidates": ["vyos", "linux", "cisco_ios"],
        "paging": ["set terminal length 0", "terminal length 0"],
        "backup": ["show configuration commands", "cat /config/config.boot", "show running-config"],
    },
    "switch_arista": {
        "candidates": ["arista_eos", "cisco_ios"],
        "paging": ["terminal length 0"],
        "backup": ["show running-config"],
    },
    "switch_intelbras": {
        "candidates": ["cisco_ios", "tplink_jetstream"],
        "paging": ["terminal length 0", "screen-length disable"],
        "backup": ["show running-config", "show startup-config"],
    },
    "switch_nokia": {
        "candidates": ["nokia_sros", "cisco_ios", "juniper_junos"],
        "paging": ["environment more false", "terminal length 0", "set cli screen-length 0"],
        "backup": ["admin display-config", "show configuration", "show running-config"],
    },
    "router_nokia": {
        "candidates": ["nokia_sros", "nokia_srl", "juniper_junos", "cisco_ios"],
        "paging": ["environment more false", "terminal length 0", "set cli screen-length 0"],
        "backup": ["admin display-config", "show configuration", "show running-config"],
    },
    "cgnat_hillstone": {
        "candidates": ["linux", "cisco_ios"],
        "paging": ["terminal length 0", "set cli pagination off"],
        "backup": ["show running-config", "show configuration", "show config"],
    },
    "cgnat_a10": {
        "candidates": ["a10", "linux", "cisco_ios"],
        "paging": ["terminal length 0", "set cli pagination off"],
        "backup": ["show running-config", "show configuration", "show config"],
    },
    "olt_generic": {
        "candidates": ["cisco_ios", "tplink_jetstream", "huawei", "zte_zxros"],
        "paging": ["terminal length 0", "screen-length disable", "no page"],
        "backup": [
            "show running-config",
            "show startup-config",
            "show running",
            "show startup",
            "display current-configuration",
            "show configuration",
        ],
    },
}

def _send_maybe_paged(conn, command: str, read_timeout: int = 300) -> str:
    return netmiko_send_command_interactive(
        conn,
        command,
        read_timeout=read_timeout,
        strip_command=False,
        strip_prompt=False,
    )


def _ensure_privileged_mode(conn, password: str, parametros: dict):
    try:
        prompt = conn.find_prompt().strip()
    except Exception:
        return
    if not prompt.endswith(">"):
        return

    enable_password = (parametros or {}).get("enable_password") or password
    out = conn.send_command_timing(
        "enable",
        read_timeout=20,
        strip_command=False,
        strip_prompt=False,
    )
    if "password" in (out or "").lower():
        conn.send_command_timing(
            enable_password or "",
            read_timeout=20,
            strip_command=False,
            strip_prompt=False,
        )


def run_profile_backup(
    profile: str,
    ip: str,
    usuario: str,
    porta: int,
    nome_provedor: str,
    nome_tipo_equip: str,
    nome_dispositivo: str,
    parametros: dict = None,
    task_id: str = None,
    backup_base_path: str = None,
    **kwargs,
) -> Tuple:
    logger = BackupLogger(nome_dispositivo, task_id)
    logger.emit(f"Iniciando backup para {nome_tipo_equip} ({profile})...")

    config = PROFILE_MAP.get(profile)
    if not config:
        msg = f"Profile desconhecido: {profile}"
        logger.emit(msg, "error")
        return False, msg, None, "CONFIGURACAO"

    parametros = parametros or {}
    password = parametros.get("password")
    if not password:
        msg = "Falha: 'password' e obrigatorio."
        logger.emit(msg, "error")
        return False, msg, None, "CONFIGURACAO"

    use_telnet = bool(parametros.get("use_telnet") or kwargs.get("use_telnet") or kwargs.get("usar_telnet"))
    candidates = _with_telnet_fallback(config["candidates"], use_telnet)

    logger.emit("Etapa 1/4: Testando conexao...")
    selected_type = None
    connection_errors: List[str] = []
    for device_type in candidates:
        try:
            with ConnectHandler(
                device_type=device_type,
                host=ip,
                port=int(porta),
                username=usuario,
                password=password,
                conn_timeout=45,
                banner_timeout=45,
                auth_timeout=60,
                fast_cli=False,
            ):
                selected_type = device_type
                break
        except Exception as exc:
            connection_errors.append(f"{device_type}: {type(exc).__name__}: {exc}")
            continue

    if not selected_type:
        detail = "; ".join(connection_errors[:3]).strip()
        category = _classify_connection_failure(detail)
        msg = friendly_failure_message(category, detail)
        logger.emit(msg, "error")
        return False, msg, None, category

    logger.emit(f"Teste de conexao bem-sucedido usando '{selected_type}'.", "success")

    backup_path = prepare_backup_path(
        backup_base_path,
        nome_provedor,
        nome_tipo_equip,
        nome_dispositivo,
        "cfg",
    )

    try:
        logger.emit("Etapa 2/4: Reconectando para coleta...")
        with ConnectHandler(
            device_type=selected_type,
            host=ip,
            port=int(porta),
            username=usuario,
            password=password,
            conn_timeout=45,
            banner_timeout=45,
            auth_timeout=60,
            fast_cli=False,
        ) as conn:
            logger.emit("Conexao estabelecida.", "success")
            prompt = conn.find_prompt()
            _ensure_privileged_mode(conn, password, parametros)
            prompt = conn.find_prompt()

            logger.emit("Etapa 3/4: Preparando terminal...")
            for cmd in config["paging"]:
                try:
                    out = conn.send_command(
                        cmd,
                        expect_string=re.escape(prompt.strip()),
                        read_timeout=20,
                        strip_command=False,
                        strip_prompt=False,
                    )
                    if not _looks_invalid(out):
                        logger.emit(f"Paginacao ajustada com '{cmd}'.")
                        break
                except Exception:
                    continue

            logger.emit("Etapa 4/4: Coletando configuracao...")
            collected = ""
            used_cmd = None
            for cmd in config["backup"]:
                try:
                    out = _send_maybe_paged(conn, cmd, read_timeout=300)
                    if out and not _looks_invalid(out) and len(out.strip()) > 40:
                        collected = out
                        used_cmd = cmd
                        break
                    if out and len(out.strip()) > len(collected.strip()):
                        collected = out
                        used_cmd = cmd
                except Exception:
                    continue

            if not collected or _looks_invalid(collected) or len(collected.strip()) <= 40:
                raise ValueError("O dispositivo nao retornou configuracao valida.")

        with open(backup_path, "w", encoding="utf-8") as fh:
            fh.write(collected)

        msg = f"Backup concluido com sucesso usando '{used_cmd}'."
        logger.emit(msg, "success")
        return True, msg, backup_path
    except Exception as exc:
        msg = friendly_unexpected_error(exc)
        logger.emit(msg, "error")
        return False, msg, None, "SCRIPT"
