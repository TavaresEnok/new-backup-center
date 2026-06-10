import os
import re
import time
import zipfile
from typing import List, Tuple

from netmiko import ConnectHandler

from script_helpers import (
    BackupLogger,
    friendly_failure_message,
    friendly_unexpected_error,
    sanitize_path_component,
)


PAGER_MARKERS = ("--More--", "---- More ----", "[More]", "<--- More --->", "Press any key")
CONFIRM_MARKERS = (
    "continue? [y/n]",
    "continue? [yes/no]",
    "are you sure",
    "[y/n]:",
    "(y/n)",
    "confirm",
)
ERROR_MARKERS = (
    "unrecognized command",
    "unknown command",
    "invalid input",
    "incomplete command",
    "command not found",
    "% error",
)
CONFIG_MARKERS = (
    "sysname ",
    "interface ",
    "vlan ",
    "bgp",
    "ospf",
    "return",
    "ip route-static",
    "acl ",
    "snmp-agent",
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


def _safe_exc_text(exc: Exception) -> str:
    text = str(exc).strip()
    name = getattr(getattr(exc, "__class__", None), "__name__", "Exception")
    return f"{name}: {text}" if text else name


def _classify_connection_failure(detail: str) -> str:
    lowered = (detail or "").lower()
    if any(marker in lowered for marker in NETWORK_ERROR_MARKERS):
        return "CONEXAO"
    if any(marker in lowered for marker in AUTH_ERROR_MARKERS):
        return "AUTENTICACAO"
    return "AUTENTICACAO"


def _looks_invalid(output: str) -> bool:
    for line in (output or "").splitlines()[:120]:
        lowered = line.strip().lower()
        if not lowered:
            continue
        if any(marker in lowered for marker in ERROR_MARKERS):
            return True
    return False


def _looks_like_config(output: str) -> bool:
    text = (output or "").strip()
    if len(text) < 60:
        return False
    lowered = text.lower()
    if "current configuration" in lowered or "configuration file" in lowered:
        return True
    if any(marker in lowered for marker in CONFIG_MARKERS):
        return True
    if len(text) >= 700 and not _looks_invalid(text):
        return True
    if "\n#" in text or text.startswith("#"):
        return True
    return False


def _send_maybe_paged(conn, command: str, read_timeout: int = 300) -> str:
    output = conn.send_command_timing(
        command_string=command,
        read_timeout=read_timeout,
        strip_command=False,
        strip_prompt=False,
    )
    guard = 0
    while guard < 400:
        lowered = (output or "").lower()
        if any(marker in output for marker in PAGER_MARKERS):
            guard += 1
            output += conn.send_command_timing(
                command_string=" ",
                read_timeout=30,
                strip_command=False,
                strip_prompt=False,
            )
            continue
        if any(marker in lowered for marker in CONFIRM_MARKERS):
            guard += 1
            output += conn.send_command_timing(
                command_string="y",
                read_timeout=30,
                strip_command=False,
                strip_prompt=False,
            )
            continue
        break
    return output


def _disable_paging(conn):
    for cmd in ("screen-length 0 temporary", "screen-length 0", "terminal length 0"):
        try:
            out = conn.send_command_timing(
                command_string=cmd,
                read_timeout=20,
                strip_command=False,
                strip_prompt=False,
            )
            if out and ":" in out:
                conn.send_command_timing(
                    command_string="",
                    read_timeout=15,
                    strip_command=False,
                    strip_prompt=False,
                )
            if not _looks_invalid(out):
                break
        except Exception:
            continue


def _collect_configuration(conn) -> Tuple[str, str]:
    collected = ""
    used_cmd = None
    for cmd in (
        "display current-configuration",
        "display current-configuration all",
        "display saved-configuration",
        "show running-config",
    ):
        for attempt in (1, 2):
            try:
                out = _send_maybe_paged(
                    conn,
                    cmd,
                    read_timeout=360 if attempt == 1 else 600,
                )
                if out and len(out.strip()) > len(collected.strip()):
                    collected = out
                    used_cmd = cmd
                if out and not _looks_invalid(out) and _looks_like_config(out):
                    return out, cmd
            except Exception:
                continue
    return collected, used_cmd


def _discover_virtual_systems(conn) -> List[str]:
    try:
        output = _send_maybe_paged(conn, "switch virtual-system ?", read_timeout=120)
    except Exception:
        return []

    # Exemplo esperado:
    #   VS-BGP-NAVEGA     Name of virtual system
    vs_list = re.findall(
        r"^\s*([A-Za-z0-9_.:-]+)\s+Name of virtual system",
        output or "",
        re.MULTILINE,
    )
    # Remove duplicados mantendo ordem
    seen = set()
    ordered = []
    for item in vs_list:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


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
) -> Tuple[bool, str, str]:
    logger = BackupLogger(nome_dispositivo, task_id)
    logger.emit("Iniciando backup para Huawei NE...")

    password = (parametros or {}).get("password")
    if not password:
        msg = "Falha: 'password' e um parametro obrigatorio."
        logger.emit(msg, "error")
        return (False, msg, None, "CONFIGURACAO")

    device_config = {
        "device_type": "huawei",
        "host": ip,
        "port": int(porta),
        "username": usuario,
        "password": password,
        "conn_timeout": 60,
        "banner_timeout": 60,
        "auth_timeout": 60,
        "fast_cli": False,
    }

    logger.emit("Etapa 1/4: Testando conexao inicial...")
    last_conn_exc = None
    for conn_try in (1, 2, 3):
        try:
            with ConnectHandler(**device_config):
                logger.emit("Teste de conexao bem-sucedido.", "success")
                last_conn_exc = None
                break
        except Exception as exc:
            last_conn_exc = exc
            if conn_try < 3:
                logger.emit(
                    f"Falha de conexao inicial (tentativa {conn_try}/3): {_safe_exc_text(exc)}. Retentando...",
                    "warning",
                )
                time.sleep(1.5 * conn_try)
                continue
    if last_conn_exc is not None:
        detail = _safe_exc_text(last_conn_exc)
        category = _classify_connection_failure(detail)
        msg = friendly_failure_message(category, detail)
        logger.emit(msg, "error")
        return (False, msg, None, category)

    caminho_final_backup = os.path.join(
        backup_base_path,
        sanitize_path_component(nome_provedor),
        sanitize_path_component(nome_tipo_equip),
        sanitize_path_component(nome_dispositivo),
    )
    os.makedirs(caminho_final_backup, exist_ok=True)

    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    arquivos_temporarios_cfg: List[str] = []
    vs_ignoradas: List[str] = []
    virtual_systems_encontrados: List[str] = []

    try:
        logger.emit("Etapa 2/4: Conectando para backup do Admin-VS...")
        with ConnectHandler(**device_config) as net_connect:
            _disable_paging(net_connect)

            logger.emit("Fazendo backup do Admin-VS...")
            config_admin_vs, admin_cmd = _collect_configuration(net_connect)
            if not config_admin_vs or _looks_invalid(config_admin_vs) or not _looks_like_config(config_admin_vs):
                raise RuntimeError("Configuracao do Admin-VS invalida ou incompleta.")

            caminho_admin = os.path.join(
                caminho_final_backup,
                f"backup_{timestamp}_Admin-VS.cfg",
            )
            with open(caminho_admin, "w", encoding="utf-8") as f:
                f.write(config_admin_vs)
            arquivos_temporarios_cfg.append(caminho_admin)

            logger.emit("Descobrindo Virtual-Systems...")
            virtual_systems_encontrados = _discover_virtual_systems(net_connect)
            if virtual_systems_encontrados:
                logger.emit(
                    f"VSs descobertos: {', '.join(virtual_systems_encontrados)}",
                    "success",
                )
            if admin_cmd:
                logger.emit(f"Admin-VS coletado com comando '{admin_cmd}'.")
    except Exception as exc:
        msg = friendly_unexpected_error(_safe_exc_text(exc), operation="coleta do Admin-VS")
        logger.emit(msg, "error")
        return (False, msg, None, "SCRIPT")

    logger.emit("Etapa 3/4: Iniciando backup individual de cada VS...")
    for vs_name in virtual_systems_encontrados:
        try:
            with ConnectHandler(**device_config) as net_connect_vs:
                _disable_paging(net_connect_vs)

                logger.emit(f"Entrando na VS '{vs_name}'...")
                net_connect_vs.send_command_timing(
                    command_string=f"switch virtual-system {vs_name}",
                    read_timeout=90,
                    strip_command=False,
                    strip_prompt=False,
                )
                time.sleep(1.5)

                config_vs, used_cmd = _collect_configuration(net_connect_vs)
                if not config_vs or _looks_invalid(config_vs) or not _looks_like_config(config_vs):
                    raise RuntimeError("Configuracao da VS invalida ou incompleta.")

                caminho_vs = os.path.join(
                    caminho_final_backup,
                    f"backup_{timestamp}_{sanitize_path_component(vs_name)}.cfg",
                )
                with open(caminho_vs, "w", encoding="utf-8") as f:
                    f.write(config_vs)
                arquivos_temporarios_cfg.append(caminho_vs)
                if used_cmd:
                    logger.emit(f"Backup da VS '{vs_name}' concluido ({used_cmd}).", "success")
                else:
                    logger.emit(f"Backup da VS '{vs_name}' concluido.", "success")
        except Exception as exc:
            logger.emit(
                f"Erro ao processar a VS '{vs_name}': {_safe_exc_text(exc)}. Pulando.",
                "error",
            )
            vs_ignoradas.append(vs_name)
            continue

    logger.emit("Etapa 4/4: Finalizando e compactando ficheiros...")
    try:
        if not arquivos_temporarios_cfg:
            raise RuntimeError("Nenhum arquivo de backup pode ser gerado.")

        caminho_zip = os.path.join(caminho_final_backup, f"backup_{timestamp}_consolidado.zip")
        with zipfile.ZipFile(caminho_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in arquivos_temporarios_cfg:
                zf.write(file_path, os.path.basename(file_path))

        for file_path in arquivos_temporarios_cfg:
            try:
                os.remove(file_path)
            except Exception:
                pass

        msg = f"Backup de {len(arquivos_temporarios_cfg)} configuracoes criado com sucesso."
        if vs_ignoradas:
            msg += f" | VS ignoradas: {', '.join(vs_ignoradas)}."
        logger.emit(msg, "success")
        return (True, msg, caminho_zip)
    except Exception as exc:
        error_msg = friendly_unexpected_error(_safe_exc_text(exc), operation="finalizacao do backup")
        logger.emit(error_msg, "error")
        return (False, error_msg, None, "SCRIPT")
