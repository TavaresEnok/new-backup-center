from typing import Tuple, List
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
PROMPT_ANY_LINE = rf"(?m)^(?:{PROMPT_HOST_RE}(?:\([^\r\n)]*\))?[>#]|\([^\r\n)]*\)#)\s*$"
PAGER_RE = r"--More--|---- More ----|\[More\]|--MORE--|<--- More --->|Press any key|\s+More\s*\( Press 'Q' to break \)"
STANDALONE_COLON_PROMPT_RE = r"(?mi)^(?:[A-Za-z0-9 _/\-]{1,40}:)\s*$"

ERROR_MARKERS = (
    "unknown command",
    "invalid command",
    "invalid input",
    "incomplete command",
    "parameter error",
    "unrecognized command",
    "command not found",
    "no such command",
    "% error in",
    "syntax error",
)

CONFIG_MARKERS = (
    "hostname ",
    "system ",
    "interface ",
    "vlan ",
    "ip address",
    "ip route",
    "gpon",
    "epon",
    "ont ",
    "onu ",
    "pon ",
    "service-port",
    "traffic-profile",
    "dba-profile",
    "line-profile",
    "profile ",
    "snmp-server",
    "ntp",
    "logging ",
    "aaa ",
    "qos ",
    "end",
    "return",
)
WEAK_CONFIG_MARKERS = (
    "hostname ",
)
MIN_MEANINGFUL_CONFIG_LEN = 500


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
    text = text.replace("\r", "")
    return text


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


def _looks_invalid(output: str) -> bool:
    low = (output or "").lower()
    return any(marker in low for marker in ERROR_MARKERS)


def _diagnostic_preview(output: str, limit: int = 180) -> str:
    text = _clean(output or "")
    text = re.sub(r"(?i)(password|passwd|community|secret|key)\s+\S+", r"\1 ***", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        return text[:limit].rstrip() + "..."
    return text


def _looks_meaningful_config(output: str) -> bool:
    txt = _clean(output or "").strip()
    if not txt:
        return False
    low = txt.lower()
    if _looks_invalid(low):
        return False

    strong_markers = [marker for marker in CONFIG_MARKERS if marker not in WEAK_CONFIG_MARKERS]
    strong_count = sum(1 for marker in strong_markers if marker in low)
    weak_count = sum(1 for marker in WEAK_CONFIG_MARKERS if marker in low)

    if strong_count >= 3 and len(txt) >= 120:
        return True
    if strong_count >= 2 and len(txt) >= MIN_MEANINGFUL_CONFIG_LEN:
        return True
    if re.search(r"(?m)^\s*(end|return)\s*$", low) and strong_count >= 1:
        return True
    if len(txt) >= 2000 and strong_count >= 1:
        return True

    lines = [line.strip() for line in txt.splitlines() if line.strip()]
    if len(lines) >= 20 and strong_count >= 1:
        return True

    if weak_count and not strong_count:
        return False
    return False


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
            continue
        if idx == 1:
            child.sendline("")
            continue
        if idx == 2:
            child.sendline(usuario)
            continue
        if idx == 3:
            child.sendline(password)
            continue
        if idx == 4:
            return True, ""
        if idx == 5:
            return False, _clean(_coerce_text(child.before) + _coerce_text(child.after))
        if idx == 6:
            last_reason = _clean(_coerce_text(child.before) + _coerce_text(child.after))
            child.sendline("")
            continue
        if idx == 7:
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
    child.sendline(command)
    deadline = time.time() + timeout_seconds
    chunks = []

    while True:
        rem = int(deadline - time.time())
        if rem <= 0:
            return False, _clean("".join(chunks))

        idx = child.expect(
            [
                PROMPT_ANY_LINE,
                PAGER_RE,
                STANDALONE_COLON_PROMPT_RE,
                r"(?i)continue\s*\?\s*\[?[YyNn]\]?",
                pexpect.TIMEOUT,
                pexpect.EOF,
            ],
            timeout=max(5, min(25, rem)),
        )
        chunks.append(_coerce_text(child.before))

        if idx == 0:
            return True, _clean("".join(chunks))
        if idx == 1:
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
    logger.emit("Iniciando backup para OLT Digistar...")

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
            category = "CONEXAO" if any(token in login_reason.lower() for token in ("eof", "conexao encerrada", "connection", "refused")) else "AUTENTICACAO"
            msg = friendly_failure_message(category, login_reason)
            logger.emit(msg, "error")
            return (False, msg, None, category)

        logger.emit("Login concluido.", "success")

        logger.emit("Etapa 2/3: Preparando sessao...")
        if not _try_enable(child, secrets, timeout=10):
            logger.emit("Modo privilegiado nao confirmado; seguindo no modo atual.", "warning")

        paging_disabled = False
        for cmd in ("terminal length 0", "terminal len 0", "no paging", "screen-length 0", "set length 0"):
            ok, out = _send_collect(child, cmd, timeout_seconds=20)
            if ok and not _looks_invalid(out):
                paging_disabled = True
                logger.emit(f"Paginacao ajustada com '{cmd}'.")
                break
        if not paging_disabled:
            logger.emit("Nao foi possivel confirmar ajuste de paginacao; continuando mesmo assim.", "warning")

        logger.emit("Etapa 3/3: Coletando configuracao...")
        commands = [
            "show running config",
            "show startup config",
            "show configuration",
            "show config",
            "show current config",
            "show running-config",
            "show startup-config",
            "display current-configuration",
            "show running",
        ]

        best = ""
        used = None
        best_valid = False
        for cmd in commands:
            ok, out = _send_collect(child, cmd, timeout_seconds=600)
            txt = (out or "").strip()
            txt = re.sub(r"^.*?" + re.escape(cmd).replace("\\ ", r"\\s+") + r"\s*", "", txt, flags=re.S).strip()

            invalid = _looks_invalid(txt)
            meaningful = _looks_meaningful_config(txt)
            preview = _diagnostic_preview(txt) if not meaningful and len(txt) <= 300 else ""
            preview_suffix = f" preview={preview!r}" if preview else ""
            logger.emit(
                f"Diagnostico comando '{cmd}': ok={ok} len={len(txt)} "
                f"invalid={invalid} meaningful={meaningful}{preview_suffix}"
            )

            if not txt:
                continue

            if not invalid and len(txt) > len(best):
                best = txt
                used = cmd
                best_valid = meaningful
            if not invalid and meaningful:
                break

        if not best_valid:
            msg = "Configuracao retornada muito curta/vazia."
            if used:
                msg = f"{msg} Ultimo comando util: {used}."
            logger.emit(msg, "error")
            return (False, msg, None, "SCRIPT")

        with open(backup_path, "w", encoding="utf-8") as fp:
            fp.write(best)

        msg = f"Backup da OLT Digistar '{nome_dispositivo}' concluido!"
        if used:
            msg = f"{msg} ({used})"
        logger.emit(msg, "success")
        return (True, msg, backup_path)
    except pexpect.TIMEOUT:
        msg = friendly_failure_message("TIMEOUT")
        logger.emit(msg, "error")
        return (False, msg, None, "TIMEOUT")
    except Exception as exc:
        msg = friendly_unexpected_error(exc)
        logger.emit(msg, "error")
        return (False, msg, None, "SCRIPT")
    finally:
        close_pexpect_session(child)
