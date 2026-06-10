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

PROMPT_HOST_RE = r"[A-Za-z0-9][A-Za-z0-9_.:/-]*"
PROMPT_ANY_LINE = rf"(?m)^(?:<{PROMPT_HOST_RE}>|{PROMPT_HOST_RE}(?:\([^\r\n)]*\))?[>#])\s*$"
PAGER_RE = r"--More--|---- More ----|\[More\]|<--- More --->|Press any key|\s+More\s*\( Press 'Q' to break \)"
STANDALONE_COLON_PROMPT_RE = r"(?mi)^(?:[A-Za-z0-9 _/\-]{1,40}:)\s*$"

ERROR_MARKERS = (
    "unknown command",
    "invalid command",
    "invalid input",
    "incomplete command",
    "parameter error",
    "unrecognized",
    "error 20200",
)

CONFIG_MARKERS = (
    "interface ",
    "pon-onu-mng",
    "pon-onu",
    "gpon-olt",
    "epon-olt",
    "vlan ",
    "service-port",
    "hostname ",
    "username ",
    "ip route",
    "interface vport",
    "config-version",
    "timestamp_write:",
    "operator-mode",
    "tacacs-server",
    "alarm enable",
    "crtv disable",
    "load-balance enable",
    "\nend",
)
WEAK_CONFIG_MARKERS = (
    "hostname ",
    "login authentication",
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
    """Remove prompt/eco atrasado antes de enviar o próximo comando."""
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


# Padrão de linhas de erro inline que OLTs ZTE intercalam na saída do show startup-config.
# Ex: "%Error 20201\n%Error 20203\n" no meio da configuração válida.
_ZTE_ERROR_LINE_RE = re.compile(r"(?m)^[ \t]*%[Ee]rror\s+\d+[^\r\n]*$")


def _strip_zte_error_lines(output: str) -> str:
    """Remove linhas '%Error NNNNN' intercaladas na saída da ZTE, preservando o restante."""
    return _ZTE_ERROR_LINE_RE.sub("", output or "")


def _looks_meaningful_after_strip(output: str) -> bool:
    """Verifica se a saída é válida após remover linhas de erro inline ZTE."""
    stripped = _strip_zte_error_lines(output)
    return _looks_meaningful_config(stripped)


def _diagnostic_preview(output: str, limit: int = 180) -> str:
    text = _clean(output or "")
    text = re.sub(r"(?i)(password|passwd|community|secret)\s+\S+", r"\1 ***", text)
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

    if strong_count >= 3 and len(txt) >= 80:
        return True
    if strong_count >= 2 and len(txt) >= MIN_MEANINGFUL_CONFIG_LEN:
        return True
    if re.search(r"(?m)^\s*end\s*$", low) and strong_count >= 1:
        return True
    if len(txt) >= 2000 and strong_count >= 1:
        return True

    lines = [line.strip() for line in txt.splitlines() if line.strip()]
    if len(lines) >= 20 and strong_count >= 1:
        return True

    # Hostname/login isolados aparecem em retorno parcial do "show config" em alguns ZTE.
    if weak_count and not strong_count:
        return False
    return False


def _login(child, usuario: str, password: str, timeout: int = 25) -> bool:
    for _ in range(14):
        idx = child.expect(
            [
                r"(?i)are you sure you want to continue connecting",
                r"(?i)(press\s+enter|pressione\s+enter|any key to continue)",
                r"(?i)(user\s*name|username|login)[: ]",
                r"(?i)password[: ]",
                PROMPT_ANY_LINE,
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
            return True
        if idx in (5, 6):
            child.sendline("")
            continue
    return False


def _try_enable(child, secrets: List[str], timeout: int = 10) -> bool:
    child.sendline("enable")
    idx = child.expect([r"(?i)password[: ]", PROMPT_ANY_LINE, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
    if idx == 1:
        return True
    if idx == 0:
        for secret in secrets:
            sec = (secret or "").strip()
            if not sec:
                continue
            child.sendline(sec)
            j = child.expect([PROMPT_ANY_LINE, r"(?i)password[: ]", pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
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
            continue
        if idx == 2:
            child.sendline("")
            continue
        if idx == 3:
            if int(deadline - time.time()) > 0:
                continue
            return False, _clean("".join(chunks))
        if idx == 4:
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
    logger.emit("Iniciando backup para OLT ZTE...")

    parametros = parametros or {}
    password = parametros.get("password")
    if not password:
        msg = "Falha: 'password' e um parametro obrigatorio."
        logger.emit(msg, "error")
        return (False, msg, None, "CONFIGURACAO")

    use_telnet = bool(parametros.get("use_telnet") or kwargs.get("use_telnet") or kwargs.get("usar_telnet"))
    # OLTs ZTE com SSH transferem configs grandes 50x mais devagar que Telnet devido ao
    # overhead de criptografia por pacote. Se a porta padrão (23) sugere Telnet e o
    # dispositivo não tem use_telnet=True explícito, ativamos automaticamente para
    # evitar coletas de 600s quando Telnet coleta em 12s.
    if not use_telnet and int(porta) == 23:
        use_telnet = True
        logger.emit("Porta 23 detectada: usando Telnet para maior performance na coleta.", "info")

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
        # Buffer grande reduz syscalls de I/O para configs volumosas (ex: 17MB Mood Telecom)
        try:
            child.maxread = 131072  # 128KB (padrão pexpect é 2000)
        except Exception:
            pass

        if not _login(child, usuario, password, timeout=28):
            msg = friendly_failure_message("AUTENTICACAO")
            logger.emit(msg, "error")
            return (False, msg, None, "AUTENTICACAO")

        logger.emit("Login concluido.", "success")

        logger.emit("Etapa 2/3: Preparando sessao...")
        if not _try_enable(child, secrets, timeout=10):
            logger.emit("Modo privilegiado nao confirmado; seguindo no modo atual.", "warning")

        # Melhora compatibilidade em firmwares ZTE diferentes
        for cmd in ("terminal length 0", "screen-length 0 temporary", "no page"):
            ok, out = _send_collect(child, cmd, timeout_seconds=20)
            if ok and not _looks_invalid(out):
                break

        logger.emit("Etapa 3/3: Coletando configuracao...")
        # Ordem otimizada: show startup-config primeiro porque em todas as OLTs ZTE testadas
        # o show running-config retorna apenas o echo do terminal (17 chars, meaningless).
        # A config real sempre está em show startup-config. Isso elimina ~1-2s de espera
        # desnecessária por dispositivo.
        commands = [
            "show startup-config",
            "show running-config",
            "show running-config all",
            "show configuration",
            "display current-configuration",
            "show config",
        ]

        best = ""
        used = None
        best_valid = False
        for cmd in commands:
            ok, out = _send_collect(child, cmd, timeout_seconds=600)
            txt = (out or "").strip()
            txt = re.sub(r"^.*?" + re.escape(cmd).replace("\\ ", r"\\s+") + r"\s*", "", txt, flags=re.S).strip()

            invalid = _looks_invalid(txt)
            # Tenta validar após remover linhas de erro inline (%Error NNNNN) da ZTE
            txt_clean = _strip_zte_error_lines(txt) if invalid else txt
            meaningful = _looks_meaningful_config(txt_clean)
            was_cleaned = invalid and meaningful  # tinha erros inline mas config é válida após remoção
            if was_cleaned:
                invalid = False  # conteúdo válido após limpeza
                txt = txt_clean  # usa versão limpa para salvar
            preview = _diagnostic_preview(txt) if not meaningful and len(txt) <= 300 else ""
            preview_suffix = f" preview={preview!r}" if preview else ""
            logger.emit(
                f"Diagnostico comando '{cmd}': ok={ok} len={len(txt)} "
                f"invalid={invalid} meaningful={meaningful}"
                + (" [linhas %Error removidas]" if was_cleaned else "")
                + preview_suffix
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

        msg = f"Backup da OLT ZTE '{nome_dispositivo}' concluido!"
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
