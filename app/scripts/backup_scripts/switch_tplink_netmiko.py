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
    "invalid",
    "bad command",
    "incomplete command",
    "error:",
    "unknown command",
)


def _looks_invalid(output: str) -> bool:
    text = (output or "").lower()
    return any(marker in text for marker in ERROR_MARKERS)


def _pick_device_types(use_telnet: bool):
    if use_telnet:
        return ["cisco_ios_telnet", "tplink_jetstream", "cisco_ios"]
    return ["tplink_jetstream", "cisco_ios"]


def _build_conn_params(device_type: str, ip: str, porta: int, usuario: str, password: str):
    return {
        "device_type": device_type,
        "host": ip,
        "port": int(porta),
        "username": usuario,
        "password": password,
        "conn_timeout": 30,
        "banner_timeout": 30,
        "auth_timeout": 30,
        "fast_cli": False,
    }


def _disable_paging(conn, logger: BackupLogger):
    for cmd in ("terminal length 0", "terminal datadump", "no page", "screen-length disable"):
        try:
            out = netmiko_send_command_interactive(
                conn,
                cmd,
                read_timeout=20,
                strip_command=False,
                strip_prompt=False,
            )
            if not _looks_invalid(out):
                logger.emit(f"Paginacao ajustada com '{cmd}'.")
                return
        except Exception:
            continue

    logger.emit("Nao foi possivel confirmar comando de paginacao, continuando mesmo assim.", "warning")


def _collect_config(conn):
    commands = (
        "show running-config",
        "show startup-config",
    )
    last_output = ""
    for cmd in commands:
        out = netmiko_send_command_interactive(
            conn,
            cmd,
            read_timeout=300,
            strip_command=False,
            strip_prompt=False,
        )
        last_output = out or ""
        if out and (not _looks_invalid(out)) and len(out.strip()) > 50:
            return out, cmd
    return last_output, commands[-1]


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
    logger.emit("Iniciando backup para Switch TP-Link...")

    parametros = parametros or {}
    password = parametros.get("password")
    if not password:
        msg = "Falha: 'password' e obrigatorio."
        logger.emit(msg, "error")
        return False, msg, None, "CONFIGURACAO"

    use_telnet = bool(parametros.get("use_telnet") or kwargs.get("use_telnet") or kwargs.get("usar_telnet"))
    device_candidates = _pick_device_types(use_telnet)

    logger.emit("Etapa 1/4: Testando conexao...")
    selected_type = None
    last_exc = None
    for device_type in device_candidates:
        test_cfg = _build_conn_params(device_type, ip, porta, usuario, password)
        try:
            with ConnectHandler(**test_cfg):
                selected_type = device_type
                break
        except Exception as exc:
            last_exc = exc
            continue

    if not selected_type:
        detail = f"{type(last_exc).__name__}: {last_exc}" if last_exc else ""
        msg = friendly_failure_message("AUTENTICACAO", detail)
        logger.emit(msg, "error")
        return False, msg, None, "AUTENTICACAO"

    logger.emit(f"Teste de conexao bem-sucedido usando '{selected_type}'.", "success")

    caminho_local_completo = prepare_backup_path(
        backup_base_path, nome_provedor, nome_tipo_equip, nome_dispositivo, "cfg"
    )

    try:
        logger.emit("Etapa 2/4: Reconectando para coleta...")
        conn_cfg = _build_conn_params(selected_type, ip, porta, usuario, password)
        with ConnectHandler(**conn_cfg) as conn:
            logger.emit("Conexao estabelecida.", "success")

            logger.emit("Etapa 3/4: Preparando terminal...")
            _disable_paging(conn, logger)

            logger.emit("Etapa 4/4: Coletando configuracao...")
            output, used_cmd = _collect_config(conn)
            if not output or _looks_invalid(output) or len(output.strip()) <= 50:
                raise ValueError("O dispositivo nao retornou configuracao valida.")
            logger.emit(f"Coleta concluida com '{used_cmd}'.")

        with open(caminho_local_completo, "w", encoding="utf-8") as f:
            f.write(output)

        msg = f"Backup do Switch TP-Link '{nome_dispositivo}' concluido."
        logger.emit(msg, "success")
        return True, msg, caminho_local_completo
    except Exception as e:
        error_msg = friendly_unexpected_error(e)
        logger.emit(error_msg, "error")
        return False, error_msg, None, "SCRIPT"
