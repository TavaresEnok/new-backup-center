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

    parametros = parametros or {}
    try:
        timeout_value = int(parametros.get("backup_connection_timeout", 60))
    except (ValueError, TypeError):
        timeout_value = 60

    password = parametros.get("password")
    if not password:
        msg = "Falha: 'password' e um parametro obrigatorio."
        logger.emit(msg, "error")
        return (False, msg, None, "CONFIGURACAO")

    use_telnet = bool(parametros.get("use_telnet") or kwargs.get("use_telnet") or kwargs.get("usar_telnet"))
    device_type = "cisco_ios_telnet" if use_telnet else "cisco_ios"
    protocol_label = "TELNET" if use_telnet else "SSH"

    logger.emit(f"Iniciando backup para OLT Datacom via {protocol_label} (timeout: {timeout_value}s)...")

    connect_timeout = max(25, int(timeout_value))
    device_config = {
        "device_type": device_type,
        "host": ip,
        "port": int(porta),
        "username": usuario,
        "password": password,
        "conn_timeout": connect_timeout,
        "banner_timeout": connect_timeout,
        "auth_timeout": connect_timeout,
        "fast_cli": False,
    }

    logger.emit(f"Etapa 1/4: Testando conexao {protocol_label}...")
    try:
        with ConnectHandler(**device_config):
            logger.emit("Teste de conexao bem-sucedido.", "success")
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        category = _classify_connection_failure(detail)
        msg = friendly_failure_message(category, detail)
        logger.emit(msg, "error")
        return (False, msg, None, category)

    caminho_local_completo = prepare_backup_path(
        backup_base_path, nome_provedor, nome_tipo_equip, nome_dispositivo, "cfg"
    )

    try:
        logger.emit(f"Etapa 2/4: Reconectando via {protocol_label} para realizar o backup...")
        with ConnectHandler(**device_config) as net_connect:
            net_connect.find_prompt()  # valida que a sessao responde antes de coletar
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
            used_command = None
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
                        used_command = cmd
                    if out and not _invalid(out) and len(out.strip()) > 80:
                        break
                except Exception:
                    continue

            logger.emit("Coleta da configuracao concluida.")

            if not output or _invalid(output) or len(output.strip()) < 80:
                raise RuntimeError("O dispositivo nao retornou uma configuracao valida ou o comando foi rejeitado.")

        with open(caminho_local_completo, "w", encoding="utf-8") as fp:
            fp.write(output)

        msg = f"Backup da OLT Datacom '{nome_dispositivo}' concluido!"
        if used_command:
            msg = f"{msg} ({used_command})"
        logger.emit(msg, "success")
        return (True, msg, caminho_local_completo)
    except Exception as exc:
        error_msg = friendly_unexpected_error(exc)
        logger.emit(error_msg, "error")
        return (False, error_msg, None, "SCRIPT")
