from typing import Tuple
import json
import os
import re
import secrets
import time

from olt_cli_backup import (
    OltCliProfile,
    _diagnostic_preview,
    _failure_category,
    _login,
    _looks_invalid,
    _looks_meaningful_config,
    _send_collect,
    _ssh_command,
    _try_enable,
    run_olt_cli_backup,
)
from script_helpers import (
    BackupLogger,
    close_pexpect_session,
    friendly_failure_message,
    friendly_unexpected_error,
    open_pexpect_session,
    prepare_backup_path,
)


VSOL_PROFILE = OltCliProfile(
    vendor_name="OLT EPON/VSOL",
    paging_commands=(
        "terminal length 0",
        "terminal width 512",
        "screen-length 0",
        "screen-length 0 temporary",
        "no page",
        "no paging",
        "terminal datadump",
        "scroll",
    ),
    backup_commands=(
        "show running-config-devel",
        "show running-config",
        "show startup-config",
        "show config",
        "show configuration",
        "show current-config",
        "show running",
        "show run",
        "show system-config",
        "show saved-config",
        "show running config",
        "show startup config",
        "display current-configuration",
        "display saved-configuration",
        "cat /config/running-config",
        "cat /tmp/running-config",
        "more /config/running-config",
    ),
    config_markers=(
        "hostname ",
        "sysname ",
        "interface ",
        "vlan ",
        "epon",
        "gpon",
        "pon ",
        "onu ",
        "ont ",
        "service-port",
        "service port",
        "session ",
        "onu set",
        "bridge-profile",
        "auto-service",
        "meprof ",
        "traffic-profile",
        "dba-profile",
        "line-profile",
        "profile ",
        "snmp",
        "ip route",
        "end",
        "return",
    ),
    min_config_len=300,
    min_lines=6,
    command_timeout_seconds=25,
    max_backup_attempts=12,
    failure_probe_timeout_seconds=8,
)


def _public_upload_base_url() -> str:
    raw = (
        os.getenv("OLT_HTTP_UPLOAD_BASE_URL")
        or os.getenv("APP_PUBLIC_URL")
        or "http://168.194.14.85:5000"
    )
    return str(raw).rstrip("/")


def _register_upload_target(backup_path: str, filename: str) -> tuple[str, str]:
    from app.services.realtime_backup_logs import get_redis_client

    client = get_redis_client()
    if not client:
        raise RuntimeError("Redis indisponivel para registrar endpoint de upload.")

    token = secrets.token_urlsafe(32)
    key = f"backup_center:olt_upload:{token}"
    payload = {
        "path": backup_path,
        "filename": filename,
        "max_bytes": 20 * 1024 * 1024,
        "created_at": int(time.time()),
    }
    client.setex(key, 10 * 60, json.dumps(payload, separators=(",", ":")))
    return token, f"{_public_upload_base_url()}/internal/olt-upload/{token}/{filename}"


def _try_cli_config(child):
    best = ""
    used = None
    rejected = []
    for cmd in VSOL_PROFILE.backup_commands:
        ok, out = _send_collect(child, cmd, timeout_seconds=VSOL_PROFILE.command_timeout_seconds)
        txt = _normalize_vsol_config_output(cmd, out)
        if not txt:
            continue
        invalid = _looks_invalid(txt, VSOL_PROFILE)
        meaningful = _looks_meaningful_config(txt, VSOL_PROFILE)
        if invalid and len(rejected) < 4:
            rejected.append(cmd)
        if not invalid and len(txt) > len(best):
            best = txt
            used = cmd
        if not invalid and meaningful:
            return True, txt, cmd, rejected
    return False, best, used, rejected


def _normalize_vsol_config_output(command: str, output: str) -> str:
    text = (output or "").strip()
    if not text:
        return ""

    # Intelbras/VSOL sometimes leaves rejected setup commands before the real dump.
    marker = "Starting configuration dump"
    marker_idx = text.find(marker)
    if marker_idx >= 0:
        text = text[marker_idx:]

    text = re.sub(r"^.*?" + re.escape(command).replace(r"\ ", r"\s+") + r"\s*", "", text, flags=re.S)
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            lines.append(line)
            continue
        if stripped == command:
            continue
        if stripped.startswith("%% Invalid command"):
            continue
        if re.match(r"^[A-Za-z0-9_.:-]+[>#]\s*", stripped):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def _supports_network_backup(child) -> bool:
    ok, out = _send_collect(child, "backup ?", timeout_seconds=12)
    text = (out or "").lower()
    return bool(ok or text) and "network" in text and "backup" in text


def _poll_http_upload(child, backup_path: str, timeout_seconds: int = 150) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if os.path.exists(backup_path) and os.path.getsize(backup_path) > 80:
            return True
        _send_collect(child, "file upload status", timeout_seconds=10)
        time.sleep(5)
    return os.path.exists(backup_path) and os.path.getsize(backup_path) > 80


def _run_http_export_backup(
    child,
    backup_path: str,
    nome_dispositivo: str,
    logger: BackupLogger,
) -> tuple[bool, str, str | None]:
    filename = f"{int(time.time())}_{''.join(c for c in nome_dispositivo if c.isalnum() or c in ('-', '_')) or 'vsol'}.conf"
    _token, upload_url = _register_upload_target(backup_path, filename)

    logger.emit("CLI exige exportacao por arquivo; iniciando upload HTTP temporario.")
    ok, out = _send_collect(child, f"backup network http {upload_url}", timeout_seconds=35)
    text = (out or "").strip()
    if _looks_invalid(text, VSOL_PROFILE) or "upload started" not in text.lower():
        msg = f"OLT rejeitou exportacao HTTP. Resposta: {_diagnostic_preview(text, 180)}"
        logger.emit(msg, "error")
        return False, msg, None

    if not _poll_http_upload(child, backup_path):
        msg = (
            "Exportacao HTTP iniciada, mas o Backup Center nao recebeu o arquivo. "
            "Verifique firewall/NAT para a URL publica do sistema."
        )
        logger.emit(msg, "error")
        return False, msg, None

    with open(backup_path, "r", encoding="utf-8", errors="ignore") as fp:
        content = fp.read()
    if not _looks_meaningful_config(content, VSOL_PROFILE) and len(content.strip()) < 300:
        msg = "Arquivo recebido da OLT VSOL parece vazio ou incompleto."
        logger.emit(msg, "error")
        return False, msg, None

    msg = f"Backup de '{nome_dispositivo}' concluido! (backup network http)"
    logger.emit(msg, "success")
    return True, msg, backup_path


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
    parametros = parametros or {}
    password = parametros.get("password")
    if not password:
        msg = "Falha: 'password' e um parametro obrigatorio."
        return (False, msg, None, "CONFIGURACAO")

    logger = BackupLogger(nome_dispositivo, task_id)
    logger.emit("Iniciando backup para OLT EPON/VSOL...")

    use_telnet = bool(parametros.get("use_telnet") or kwargs.get("use_telnet") or kwargs.get("usar_telnet"))
    jump_host = kwargs.get("jump_host") or parametros.get("jump_host") or None
    command = f"telnet {ip} {int(porta)}" if use_telnet else _ssh_command(ip, usuario, porta)
    backup_path = prepare_backup_path(backup_base_path, nome_provedor, nome_tipo_equip, nome_dispositivo, "cfg")

    child = None
    try:
        logger.emit(f"Etapa 1/3: Conectando {'TELNET' if use_telnet else 'SSH'}...")
        child = open_pexpect_session(
            command,
            jump_host=jump_host,
            timeout=35,
            encoding="utf-8",
            codec_errors="ignore",
            logger=logger,
        )
        ok_login, login_reason = _login(child, usuario, password, timeout=28)
        if not ok_login:
            category = _failure_category(login_reason)
            msg = friendly_failure_message(category, login_reason)
            logger.emit(msg, "error")
            return (False, msg, None, category)

        logger.emit("Login concluido.", "success")
        logger.emit("Etapa 2/3: Preparando sessao...")
        if _try_enable(child, [parametros.get("enable_password"), password, usuario], timeout=10):
            logger.emit("Modo privilegiado confirmado.", "success")
        else:
            logger.emit("Modo privilegiado nao confirmado; seguindo no modo atual.", "warning")

        logger.emit("Etapa 3/3: Coletando configuracao...")
        ok_cli, config, used_cmd, rejected = _try_cli_config(child)
        if ok_cli:
            with open(backup_path, "w", encoding="utf-8") as fp:
                fp.write(config)
            msg = f"Backup de '{nome_dispositivo}' concluido! ({used_cmd})"
            logger.emit(msg, "success")
            return (True, msg, backup_path)

        if _supports_network_backup(child):
            return _run_http_export_backup(child, backup_path, nome_dispositivo, logger)

        msg = "Configuracao retornada muito curta/vazia."
        if rejected:
            msg = f"{msg} Comandos rejeitados pelo equipamento: {', '.join(rejected)}."
        logger.emit(msg, "error")
        return (False, msg, None, "SCRIPT")

    except Exception as exc:
        category = _failure_category(str(exc))
        msg = friendly_failure_message(category, str(exc)) if category in ("CONEXAO", "AUTENTICACAO") else friendly_unexpected_error(exc)
        logger.emit(msg, "error")
        return (False, msg, None, category)
    finally:
        close_pexpect_session(child)
