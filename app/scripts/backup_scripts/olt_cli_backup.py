from dataclasses import dataclass
from typing import List, Sequence, Tuple
import os
import re
import time

import pexpect

from script_helpers import (
    BackupLogger,
    friendly_failure_message,
    friendly_unexpected_error,
    prepare_backup_path,
    open_pexpect_session,
    close_pexpect_session,
    ssh_host_key_options,
)


PROMPT_HOST_RE = r"[A-Za-z0-9][A-Za-z0-9_.:/_-]*"
PROMPT_PAREN_RE = r"\([A-Za-z0-9_.:/_-]{1,64}\)[>#]?"
PROMPT_ANY_LINE = rf"(?m)^(?:<{PROMPT_HOST_RE}>|{PROMPT_HOST_RE}(?:\([^\r\n)]*\))?[>#]|{PROMPT_PAREN_RE}|\([^\r\n)]*\)#)\s*$"
PAGER_RE = (
    r"--More--|---- More ----|\[More\]|--MORE--|<--- More --->|Press any key"
    r"|\s*-*\s*More\s*\(\s*Press\s+'Q'\s+to\s+(?:break|quit)\s*\)\s*-*"
)
STANDALONE_PROMPT_RE = r"(?mi)^(?:[A-Za-z0-9 _/\-]{1,40}:)\s*$"

BASE_ERROR_MARKERS = (
    "unknown command",
    "invalid command",
    "invalid input",
    "incomplete command",
    "parameter error",
    "unrecognized command",
    "command not found",
    "no such command",
    "bad command",
    "% error",
    "syntax error",
)

BASE_CONFIG_MARKERS = (
    "hostname ",
    "sysname ",
    "interface ",
    "vlan ",
    "ip address",
    "ip route",
    "gpon",
    "epon",
    "xpon",
    "pon ",
    "onu ",
    "ont ",
    "service-port",
    "service port",
    "traffic-profile",
    "dba-profile",
    "line-profile",
    "srvprofile",
    "profile ",
    "snmp-server",
    "snmp-agent",
    "ntp",
    "aaa",
    "qos",
    "end",
    "return",
)

CONNECTION_MARKERS = (
    "timeout",
    "timed out",
    "connection refused",
    "closed by remote host",
    "no route to host",
    "network is unreachable",
    "error reading ssh protocol banner",
    "eof",
    "connection closed",
    "timeout opening channel",
    "jump host",
    "jump_session_closed",
)

AUTH_MARKERS = (
    "authentication failed",
    "auth failed",
    "permission denied",
    "invalid password",
    "login failed",
    "senha",
    "password",
    "credenciais",
)


@dataclass(frozen=True)
class OltCliProfile:
    vendor_name: str
    paging_commands: Sequence[str]
    backup_commands: Sequence[str]
    config_markers: Sequence[str] = BASE_CONFIG_MARKERS
    error_markers: Sequence[str] = BASE_ERROR_MARKERS
    weak_markers: Sequence[str] = ("hostname ", "sysname ")
    min_config_len: int = 500
    min_lines: int = 8
    command_timeout_seconds: int = 600
    max_backup_attempts: int = 0
    verbose_diagnostics: bool = False
    failure_probe_commands: Sequence[str] = ("?", "help", "show ?")
    failure_probe_timeout_seconds: int = 12


DEFAULT_PAGING_COMMANDS = (
    "terminal length 0",
    "terminal datadump",
    "no page",
    "no paging",
    "screen-length 0",
    "screen-length disable",
    "screen-length 0 temporary",
)

DEFAULT_BACKUP_COMMANDS = (
    "show running-config",
    "show startup-config",
    "show running",
    "show startup",
    "show configuration",
    "show config",
    "display current-configuration",
)


def _ssh_command(ip: str, usuario: str, porta: int) -> str:
    return (
        "ssh "
        f"{ssh_host_key_options()} "
        "-o ConnectTimeout=25 "
        "-o HostKeyAlgorithms=+ssh-rsa,ssh-dss "
        "-o KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1 "
        "-o Ciphers=+aes128-cbc,3des-cbc "
        f"{usuario}@{ip} -p {int(porta)}"
    )


def _clean(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"\x1B\[[0-9;?]*[A-Za-z]", "", text)
    text = re.sub(r".\x08", "", text)
    return text.replace("\r", "")


def _coerce_text(value) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _drain_pending(child, max_reads: int = 8) -> None:
    for _ in range(max_reads):
        try:
            pending = child.read_nonblocking(size=65535, timeout=0)
        except (pexpect.TIMEOUT, EOFError, OSError):
            break
        except Exception:
            break
        if not pending:
            break


def _looks_invalid(output: str, profile: OltCliProfile) -> bool:
    low = (output or "").lower()
    return any(marker in low for marker in profile.error_markers)


def _has_pager_marker(output: str) -> bool:
    return bool(re.search(PAGER_RE, output or "", flags=re.I))


def _diagnostic_preview(output: str, limit: int = 180) -> str:
    text = _clean(output or "")
    text = re.sub(r"(?i)(password|passwd|community|secret|key)\s+\S+", r"\1 ***", text)
    text = re.sub(r"\s+", " ", text).strip()
    return (text[:limit].rstrip() + "...") if len(text) > limit else text


def _should_log_diagnostics(parametros: dict, profile: OltCliProfile) -> bool:
    if profile.verbose_diagnostics:
        return True
    if str(os.getenv("BACKUP_SCRIPT_VERBOSE_DIAGNOSTICS", "")).strip().lower() in ("1", "true", "yes", "sim"):
        return True
    return bool((parametros or {}).get("debug") or (parametros or {}).get("verbose_diagnostics"))


def _looks_meaningful_config(output: str, profile: OltCliProfile) -> bool:
    txt = _clean(output or "").strip()
    if not txt:
        return False
    if _has_pager_marker(txt):
        return False
    if _looks_invalid(txt, profile):
        return False

    low = txt.lower()
    strong_markers = [marker for marker in profile.config_markers if marker not in profile.weak_markers]
    strong_count = sum(1 for marker in strong_markers if marker in low)
    weak_count = sum(1 for marker in profile.weak_markers if marker in low)
    lines = [line.strip() for line in txt.splitlines() if line.strip()]

    if strong_count >= 3 and len(txt) >= 120:
        return True
    if strong_count >= 2 and len(txt) >= profile.min_config_len:
        return True
    if re.search(r"(?m)^\s*(end|return)\s*$", low) and strong_count >= 1:
        return True
    if len(txt) >= 2500 and strong_count >= 1 and len(lines) >= profile.min_lines:
        return True
    if len(lines) >= 20 and strong_count >= 1:
        return True

    if weak_count and not strong_count:
        return False
    return False


def _failure_category(reason: str | None) -> str:
    low = str(reason or "").lower()
    if any(marker in low for marker in CONNECTION_MARKERS):
        return "CONEXAO"
    if any(marker in low for marker in AUTH_MARKERS):
        return "AUTENTICACAO"
    return "SCRIPT"


def _login(child, usuario: str, password: str, timeout: int = 25) -> Tuple[bool, str]:
    last_reason = ""
    for _ in range(14):
        idx = child.expect(
            [
                r"(?i)are you sure you want to continue connecting",
                r"(?i)(press\s+enter|pressione\s+enter|any key to continue)",
                r"(?i)(user\s*name|username|login|usuario|usu.rio)[: ]*",
                r"(?i)(password|senha|passwd)[: ]*",
                PROMPT_ANY_LINE,
                r"(?i)(connection refused|closed by remote host|no route to host|network is unreachable)",
                pexpect.TIMEOUT,
                pexpect.EOF,
            ],
            timeout=timeout,
        )
        if idx == 0:
            child.sendline("yes")
        elif idx == 1:
            child.sendline("")
        elif idx == 2:
            child.sendline(usuario)
        elif idx == 3:
            child.sendline(password)
        elif idx == 4:
            return True, ""
        elif idx == 5:
            return False, _clean(_coerce_text(child.before) + _coerce_text(child.after))
        elif idx == 6:
            last_reason = _clean(_coerce_text(child.before) + _coerce_text(child.after))
            child.sendline("")
        elif idx == 7:
            last_reason = _clean(_coerce_text(child.before) + _coerce_text(child.after))
            return False, last_reason or "Conexao encerrada pelo equipamento durante login."
    return False, last_reason or "Nao foi possivel completar autenticacao."


def _try_enable(child, secrets: List[str], timeout: int = 10) -> bool:
    _drain_pending(child)
    child.sendline("enable")
    idx = child.expect([r"(?i)(password|senha|passwd)[: ]*", PROMPT_ANY_LINE, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
    if idx == 1:
        return True
    if idx == 0:
        for secret in secrets:
            sec = (secret or "").strip()
            if not sec:
                continue
            child.sendline(sec)
            j = child.expect([PROMPT_ANY_LINE, r"(?i)(password|senha|passwd)[: ]*", pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
            if j == 0:
                return True
            if j == 1:
                continue
    return False


def _send_collect(child, command: str, timeout_seconds: int = 420):
    _drain_pending(child)
    child.sendline("")
    try:
        child.expect([PROMPT_ANY_LINE, pexpect.TIMEOUT, pexpect.EOF], timeout=2)
    except Exception:
        pass
    _drain_pending(child, max_reads=3)
    child.sendline(command)
    deadline = time.time() + timeout_seconds
    chunks = []

    while True:
        remaining = int(deadline - time.time())
        if remaining <= 0:
            return False, _clean("".join(chunks))

        idx = child.expect(
            [
                PROMPT_ANY_LINE,
                PAGER_RE,
                STANDALONE_PROMPT_RE,
                r"(?i)continue\s*\?\s*\[?[YyNn]\]?",
                pexpect.TIMEOUT,
                pexpect.EOF,
            ],
            timeout=max(5, min(25, remaining)),
        )
        chunks.append(_coerce_text(child.before))

        if idx == 0:
            return True, _clean("".join(chunks))
        if idx == 1:
            pager_text = _coerce_text(child.after)
            if re.search(r"Press\s+'Q'\s+to\s+quit", pager_text, flags=re.I):
                child.sendline("")
            else:
                child.send(" ")
            time.sleep(0.2)
            continue
        if idx in (2, 3):
            child.sendline("")
            continue
        if idx == 4:
            if int(deadline - time.time()) > 0:
                continue
            return False, _clean("".join(chunks))
        if idx == 5:
            chunks.append(_coerce_text(child.after))
            return True, _clean("".join(chunks))


def run_olt_cli_backup(
    profile: OltCliProfile,
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
    logger.emit(f"Iniciando backup para {profile.vendor_name}...")

    parametros = parametros or {}
    password = parametros.get("password")
    if not password:
        msg = "Falha: 'password' e um parametro obrigatorio."
        logger.emit(msg, "error")
        return (False, msg, None, "CONFIGURACAO")

    use_telnet = bool(parametros.get("use_telnet") or kwargs.get("use_telnet") or kwargs.get("usar_telnet"))
    enable_password = parametros.get("enable_password")
    secrets = [enable_password, password, usuario]
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
        try:
            child.maxread = max(int(getattr(child, "maxread", 0) or 0), 65536)
        except Exception:
            pass

        ok_login, login_reason = _login(child, usuario, password, timeout=28)
        if not ok_login:
            category = _failure_category(login_reason)
            msg = friendly_failure_message(category, login_reason)
            logger.emit(msg, "error")
            return (False, msg, None, category)

        logger.emit("Login concluido.", "success")

        logger.emit("Etapa 2/3: Preparando sessao...")
        if _try_enable(child, secrets, timeout=10):
            logger.emit("Modo privilegiado confirmado.", "success")
        else:
            logger.emit("Modo privilegiado nao confirmado; seguindo no modo atual.", "warning")

        paging_disabled = False
        for cmd in profile.paging_commands:
            ok, out = _send_collect(child, cmd, timeout_seconds=20)
            if ok and not _looks_invalid(out, profile):
                paging_disabled = True
                logger.emit(f"Paginacao ajustada com '{cmd}'.")
                break
        if not paging_disabled:
            logger.emit("Nao foi possivel confirmar ajuste de paginacao; continuando mesmo assim.", "warning")

        logger.emit("Etapa 3/3: Coletando configuracao...")
        best = ""
        used = None
        best_valid = False
        verbose_diagnostics = _should_log_diagnostics(parametros, profile)
        failed_summaries = []
        attempted = 0

        for cmd in profile.backup_commands:
            if profile.max_backup_attempts and attempted >= profile.max_backup_attempts:
                break
            attempted += 1
            ok, out = _send_collect(child, cmd, timeout_seconds=profile.command_timeout_seconds)
            txt = (out or "").strip()
            has_pager = _has_pager_marker(txt)
            invalid = _looks_invalid(txt, profile) or has_pager
            complete = bool(ok) and not has_pager
            meaningful = complete and _looks_meaningful_config(txt, profile)
            preview = _diagnostic_preview(txt) if not meaningful and len(txt) <= 300 else ""
            if verbose_diagnostics:
                preview_suffix = f" preview={preview!r}" if preview else ""
                logger.emit(
                    f"Diagnostico comando '{cmd}': ok={ok} len={len(txt)} "
                    f"invalid={invalid} meaningful={meaningful}{preview_suffix}"
                )
            elif invalid and len(failed_summaries) < 4:
                failed_summaries.append(cmd)

            if not txt:
                continue
            if complete and not invalid and len(txt) > len(best):
                best = txt
                used = cmd
                best_valid = meaningful
            if not invalid and meaningful:
                logger.emit(f"Configuracao coletada com '{cmd}'.")
                break

        if not best_valid:
            msg = "Configuracao retornada muito curta/vazia."
            if used:
                msg = f"{msg} Ultimo comando util: {used}."
            elif failed_summaries:
                shown = ", ".join(failed_summaries)
                suffix = "..." if attempted > len(failed_summaries) else ""
                msg = f"{msg} Comandos rejeitados pelo equipamento: {shown}{suffix}."
            if profile.failure_probe_commands:
                probe_notes = []
                for probe_cmd in profile.failure_probe_commands:
                    ok, probe_out = _send_collect(
                        child,
                        probe_cmd,
                        timeout_seconds=profile.failure_probe_timeout_seconds,
                    )
                    probe_txt = (probe_out or "").strip()
                    if probe_txt and not _looks_invalid(probe_txt, profile):
                        probe_notes.append(f"{probe_cmd}: {_diagnostic_preview(probe_txt, 160)}")
                        break
                if probe_notes:
                    msg = f"{msg} Ajuda do CLI: {probe_notes[0]}"
            logger.emit(msg, "error")
            return (False, msg, None, "SCRIPT")

        with open(backup_path, "w", encoding="utf-8") as fp:
            fp.write(best)

        msg = f"Backup de '{nome_dispositivo}' concluido!"
        if used:
            msg = f"{msg} ({used})"
        logger.emit(msg, "success")
        return (True, msg, backup_path)

    except pexpect.TIMEOUT:
        msg = friendly_failure_message("TIMEOUT")
        logger.emit(msg, "error")
        return (False, msg, None, "TIMEOUT")
    except Exception as exc:
        category = _failure_category(str(exc))
        msg = friendly_failure_message(category, str(exc)) if category in ("CONEXAO", "AUTENTICACAO") else friendly_unexpected_error(exc)
        logger.emit(msg, "error")
        return (False, msg, None, category)
    finally:
        close_pexpect_session(child)
