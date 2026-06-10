import re
from typing import Tuple

from netmiko import ConnectHandler

from script_helpers import (
    BackupLogger,
    friendly_failure_message,
    friendly_unexpected_error,
    netmiko_send_command_interactive,
    prepare_backup_path,
)


ERROR_MARKERS = (
    "invalid input",
    "unknown command",
    "unrecognized",
    "incomplete command",
    "error:",
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


def _invalid(output: str) -> bool:
    text = (output or "").lower()
    return any(marker in text for marker in ERROR_MARKERS)


def _classify_connection_failure(detail: str) -> str:
    lowered = (detail or "").lower()
    if any(marker in lowered for marker in NETWORK_ERROR_MARKERS):
        return "CONEXAO"
    if any(marker in lowered for marker in AUTH_ERROR_MARKERS):
        return "AUTENTICACAO"
    return "AUTENTICACAO"


def realizar_backup(
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
    logger.emit("Iniciando backup para Switch Datacom...")

    parametros = parametros or {}
    password = parametros.get("password")
    if not password:
        msg = "Falha: 'password' e um parametro obrigatorio."
        logger.emit(msg, "error")
        return (False, msg, None, "CONFIGURACAO")

    use_telnet = bool(parametros.get("use_telnet") or kwargs.get("use_telnet") or kwargs.get("usar_telnet"))
    device_type = "cisco_ios_telnet" if use_telnet else "cisco_ios"

    device_config = {
        "device_type": device_type,
        "host": ip,
        "port": int(porta),
        "username": usuario,
        "password": password,
        "conn_timeout": 25,
        "banner_timeout": 25,
        "auth_timeout": 25,
        "fast_cli": False,
    }

    logger.emit("Etapa 1/4: Testando conexao...")
    try:
        with ConnectHandler(**device_config):
            logger.emit("Teste de conexao bem-sucedido.", "success")
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        category = _classify_connection_failure(detail)
        msg = friendly_failure_message(category, detail)
        logger.emit(msg, "error")
        return (False, msg, None, category)

    caminho_local = prepare_backup_path(backup_base_path, nome_provedor, nome_tipo_equip, nome_dispositivo, "cfg")

    try:
        logger.emit(f"Etapa 2/4: Reconectando via {'Telnet' if use_telnet else 'SSH'}...")
        with ConnectHandler(**device_config) as net_connect:
            prompt = net_connect.find_prompt()
            logger.emit("Conexao estabelecida.", "success")

            logger.emit("Etapa 3/4: Desativando paginacao...")
            for cmd in ("paginate false", "terminal length 0", "no page"):
                try:
                    out = netmiko_send_command_interactive(
                        net_connect,
                        cmd,
                        read_timeout=20,
                        strip_command=False,
                        strip_prompt=False,
                    )
                    if not _invalid(out):
                        break
                except Exception:
                    continue

            logger.emit("Etapa 4/4: Coletando configuracao...")
            output = ""
            used = None
            for cmd in ("show running-config", "show configuration", "display current-configuration"):
                try:
                    out = netmiko_send_command_interactive(
                        net_connect,
                        cmd,
                        read_timeout=300,
                        strip_command=False,
                        strip_prompt=False,
                    )
                    if out and not _invalid(out) and len(out.strip()) > len(output.strip()):
                        output = out
                        used = cmd
                    if out and not _invalid(out) and len(out.strip()) > 80:
                        break
                except Exception:
                    continue

            if not output or _invalid(output) or len(output.strip()) < 80:
                raise RuntimeError("O dispositivo nao retornou uma configuracao valida ou o comando foi rejeitado.")

        with open(caminho_local, "w", encoding="utf-8") as fp:
            fp.write(output)

        msg = f"Backup do Switch Datacom '{nome_dispositivo}' concluido!"
        if used:
            msg = f"{msg} ({used})"
        logger.emit(msg, "success")
        return (True, msg, caminho_local)
    except Exception as exc:
        error_msg = friendly_unexpected_error(exc)
        logger.emit(error_msg, "error")
        return (False, error_msg, None, "SCRIPT")
