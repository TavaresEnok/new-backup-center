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
CONFIG_TAG_NAMES_RE = (
    r"(?:pre|global|device|public|vlan|emu|bbs|sysmode|config|aaa|mcu|meth|null|loopback|"
    r"post-system|prevlanif|preloopback|vlanif|gpon)(?:-[^>\r\n]+)?"
)
# Exige no mínimo 2 caracteres dentro de < > para evitar falsos positivos com tokens de menu
# interativo da Huawei como <K>, <cr>, <E> que aparecem na linha de parâmetros opcionais.
PROMPT_ANGLE_LINE = rf"<(?!/?{CONFIG_TAG_NAMES_RE}>)[^>\r\n]{{2,}}>"
PROMPT_ANY_LINE = rf"(?m)^(?:{PROMPT_ANGLE_LINE}|{PROMPT_HOST_RE}(?:\(config[^\r\n)]*\))?[>#]|\(config[^\r\n)]*\)#)\s*$"
PROMPT_PRIV_LINE = rf"(?m)^(?:{PROMPT_HOST_RE}(?:\(config[^\r\n)]*\))?#|\(config[^\r\n)]*\)#)\s*$"
PROMPT_CONFIG_LINE = rf"(?m)^(?:{PROMPT_HOST_RE})?\(config[^\r\n)]*\)#\s*$"
PROMPT_COMMAND_LINE = rf"(?m)^(?:{PROMPT_ANGLE_LINE}|{PROMPT_HOST_RE}(?:\(config[^\r\n)]*\))?[>#])\s*$"
PAGER_RE = r"--More--|---- More ----|\[More\]|<--- More --->|Press any key|\s+More\s*\( Press 'Q' to break \)"
INTERACTIVE_CONFIRM_RE = r"(?m)^\s*\{[^\r\n}]*(?:<cr>|<K>)[^\r\n}]*\}\s*:?\s*$"

ERROR_MARKERS = (
    "unknown command",
    "invalid input",
    "incomplete command",
    "parameter error",
    "unrecognized",
    "error locates at '^'",
)

CONFIG_MARKERS = (
    "sysname",
    "interface",
    "vlan",
    "service-port",
    "ont-lineprofile",
    "ont-srvprofile",
    "gpon",
    "return",
)

MIN_FULL_CONFIG_LEN = 800
FULL_CONFIG_TIMEOUT_SECONDS = 1200

CONNECTION_MARKERS = (
    "timeout",
    "timed out",
    "connection refused",
    "unable to connect",
    "no route to host",
    "network is unreachable",
    "error reading ssh protocol banner",
    "eof",
    "connection closed",
    "timeout opening channel",
    "sessao com jump host encerrada",
    "sessão com jump host encerrada",
    "jump host",
    "jump_session_closed",
)

AUTH_MARKERS = (
    "authentication failed",
    "netmikoauthenticationexception",
    "senha",
    "password",
    "credenciais",
    "usuario",
    "usuário",
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


def _clean_terminal_text(text: str) -> str:
    if not text:
        return ""
    # remove ANSI e corrige backspaces comuns dessas OLTs
    text = re.sub(r"\x1B\[[0-9;?]*[A-Za-z]", "", text)
    text = re.sub(r".\x08", "", text)
    text = text.replace("\r", "")
    return text


def _looks_invalid(output: str) -> bool:
    low = (output or "").lower()
    return any(marker in low for marker in ERROR_MARKERS)


def _looks_like_config(output: str) -> bool:
    low = (output or "").lower()
    if _looks_invalid(low):
        return False

    # OLTs MA5800/MA5600 com firmware de seções XML usam o formato [pre-config]/<pre-config>
    # sem o campo 'sysname' em nível raiz. A guarda abaixo protegia contra blocos pre-config
    # parciais, mas rejeita configs completas no formato de seções. Permitimos se houver
    # markers suficientes que confirmem tratar-se de configuração completa.
    marker_count = sum(1 for marker in CONFIG_MARKERS if marker in low)
    if "<pre-config>" in low and "sysname" not in low and marker_count < 3:
        return False

    if len(low) >= MIN_FULL_CONFIG_LEN and marker_count >= 1:
        return True
    if "sysname" in low and any(marker in low for marker in ("interface", "vlan", "service-port", "gpon", "return")):
        return True
    if "service-port" in low and any(marker in low for marker in ("gpon", "vlan", "ont-lineprofile", "ont-srvprofile")):
        return True
    if any(marker in low for marker in ("ont-lineprofile", "ont-srvprofile")) and "gpon" in low:
        return True
    return False


def _has_config_terminator(output: str) -> bool:
    return bool(re.search(r"(?im)^\s*return\s*$", output or ""))


def _is_complete_config_output(command_ok: bool, output: str) -> bool:
    return bool(output and (command_ok or _has_config_terminator(output)))


def _strip_command_noise(output: str, command: str) -> str:
    text = _clean_terminal_text(output or "").strip()
    if command and text.startswith(command):
        text = text[len(command) :].lstrip()
    if command:
        text = re.sub(rf"(?is)^Command:\s*\n\s*{re.escape(command)}\s*\n", "", text, count=1).lstrip()
    text = re.sub(PROMPT_COMMAND_LINE, "", text).strip()
    return text


def _coerce_pexpect_text(value) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _failure_category_from_reason(reason: str | None) -> str:
    text = str(reason or "").strip().lower()
    if not text:
        return "SCRIPT"
    if any(marker in text for marker in CONNECTION_MARKERS):
        return "CONEXAO"
    if any(marker in text for marker in AUTH_MARKERS):
        return "AUTENTICACAO"
    return "SCRIPT"


def _login_failure_text(child, fallback: str) -> str:
    text = _clean_terminal_text(_coerce_pexpect_text(getattr(child, "before", "")))
    text = re.sub(r"\s+", " ", text).strip()
    if text:
        return text
    return fallback


def _login(
    child,
    usuario: str,
    password: str,
    timeout: int = 25,
    max_total_seconds: int = 80,
):
    user_prompt = r"(?i)(?:user\s*name|username)\s*[:>]|(?:^|\n)\s*login\s*[:>]\s*$"
    pass_prompt = r"(?i)password\s*[:>]"
    refused_prompt = r"(?i)(connection refused|closed by remote host|refused by remote host|no route to host|network is unreachable)"
    last_reason = ""
    deadline = time.monotonic() + max(10, int(max_total_seconds or 80))
    attempts = 0
    while attempts < 14:
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            break
        attempts += 1
        idx = child.expect(
            [
                r"(?i)are you sure you want to continue connecting",
                user_prompt,
                pass_prompt,
                refused_prompt,
                r"(?i)(press\s+enter|pressione\s+enter|any key to continue)",
                PROMPT_ANY_LINE,
                r"(?m)^%\s*$",
                pexpect.TIMEOUT,
                pexpect.EOF,
            ],
            timeout=max(1, min(timeout, remaining)),
        )
        if idx == 0:
            child.sendline("yes")
            continue
        if idx == 1:
            child.sendline(usuario)
            continue
        if idx == 2:
            child.sendline(password)
            continue
        if idx == 3:
            last_reason = _clean_terminal_text(_coerce_pexpect_text(child.after) + _coerce_pexpect_text(child.before))
            try:
                child.sendline("")
                continue
            except Exception:
                pass
            return False, last_reason or "Conexao recusada pelo destino."
        if idx == 4:
            child.sendline("")
            continue
        if idx == 5:
            return True, ""
        if idx == 6:
            child.sendline("")
            continue
        if idx == 7:
            last_reason = _login_failure_text(child, "Timeout aguardando banner/login do equipamento.")
            child.sendline("")
            continue
        if idx == 8:
            last_reason = _login_failure_text(child, "Conexao encerrada antes do equipamento apresentar login/banner.")
            return False, last_reason
    return False, (last_reason or "Nao foi possivel completar autenticacao dentro do tempo limite.")


def _is_pre_login_close(reason: str) -> bool:
    low = (reason or "").lower()
    return (
        "conexao encerrada antes" in low
        or "connection closed" in low
        or "closed by remote host" in low
        or "eof" in low
        or "error reading ssh protocol banner" in low
    )


def _try_enable(child, secrets: List[str], timeout: int = 12) -> bool:
    child.sendline("enable")
    idx = child.expect([r"(?i)password[: ]", PROMPT_PRIV_LINE, PROMPT_ANY_LINE, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)

    if idx == 1:
        return True
    if idx == 0:
        for secret in secrets:
            sec = (secret or "").strip()
            if not sec:
                continue
            child.sendline(sec)
            j = child.expect([PROMPT_PRIV_LINE, r"(?i)password[: ]", PROMPT_ANY_LINE, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
            if j == 0:
                return True
            if j == 1:
                continue
        return False

    return False


def _send_and_collect(child, command: str, timeout_seconds: int = 420):
    child.sendline(command)
    deadline = time.time() + timeout_seconds
    chunks = []

    while True:
        remaining = int(deadline - time.time())
        if remaining <= 0:
            return False, _clean_terminal_text("".join(chunks))

        # IMPORTANTE: INTERACTIVE_CONFIRM_RE deve vir ANTES de PROMPT_COMMAND_LINE.
        # Tokens de menu como <K> e <cr> podem casar com PROMPT_COMMAND_LINE (via PROMPT_ANGLE_LINE)
        # antes do padrão de menu completo ser reconhecido. Priorizando INTERACTIVE_CONFIRM_RE
        # garantimos que o menu interativo seja respondido corretamente e não confundido com prompt.
        idx = child.expect(
            [
                INTERACTIVE_CONFIRM_RE,  # 0 — menu interativo → envia CR (default)
                PROMPT_COMMAND_LINE,     # 1 — prompt real → coleta concluída
                PAGER_RE,               # 2 — paginação → envia espaço
                pexpect.TIMEOUT,        # 3 — continua aguardando
                pexpect.EOF,            # 4 — fim
            ],
            timeout=max(10, min(45, remaining)),
        )
        chunks.append(_coerce_pexpect_text(child.before))

        if idx == 0:
            child.sendline("")
            continue
        if idx == 1:
            return True, _clean_terminal_text("".join(chunks))
        if idx == 2:
            child.send(" ")
            time.sleep(0.05)
            continue
        if idx == 3:
            continue
        if idx == 4:
            return True, _clean_terminal_text("".join(chunks))


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
    logger.emit(f"Iniciando backup para Huawei OLT: {nome_dispositivo}...")

    parametros = parametros or {}
    password = parametros.get("password")
    if not password:
        msg = "Senha nao fornecida."
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
        logger.emit("Etapa 1/3: Conectando e autenticando...")
        if jump_host and jump_host.get("host"):
            logger.emit("Sessao interativa via Jump Host habilitada para OLT Huawei.")
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
        if not ok_login and use_telnet and _is_pre_login_close(login_reason):
            close_pexpect_session(child)
            child = None
            logger.emit(
                "TELNET abriu mas encerrou antes do login; tentando SSH na mesma porta.",
                "warning",
            )
            child = open_pexpect_session(
                _ssh_command(ip, usuario, porta),
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
            ok_login, ssh_reason = _login(child, usuario, password, timeout=28)
            if not ok_login:
                login_reason = f"TELNET: {login_reason}; SSH mesma porta: {ssh_reason}"
        if not ok_login:
            category = _failure_category_from_reason(login_reason)
            msg = friendly_failure_message(category, login_reason)
            logger.emit(msg, "error")
            return (False, msg, None, category)

        logger.emit("Login concluido.", "success")

        logger.emit("Etapa 2/3: Preparando sessao...")
        enabled = _try_enable(child, secrets, timeout=10)
        if enabled:
            logger.emit("Modo privilegiado confirmado.", "success")
        else:
            logger.emit("Enable nao confirmado; seguindo no modo atual.", "warning")

        # Alguns firmwares Huawei entregam a configuracao completa e sem formatacao quebrada no modo config.
        child.sendline("config")
        idx = child.expect([PROMPT_CONFIG_LINE, PROMPT_PRIV_LINE, PROMPT_ANY_LINE, pexpect.TIMEOUT, pexpect.EOF], timeout=12)
        if idx == 0:
            logger.emit("Modo config confirmado.")

        # desativa paginacao sem travar se comando nao existir
        for cmd in ("screen-length 0 temporary", "terminal length 0", "scroll", "scroll 0"):
            ok, out = _send_and_collect(child, cmd, timeout_seconds=25)
            if ok and not _looks_invalid(out):
                logger.emit(f"Paginacao preparada com: {cmd}")
                break

        # Usado nos scripts antigos para preservar a saida original em alguns MA56xx/MA58xx.
        ok_mmi, out_mmi = _send_and_collect(child, "mmi-mode original-output", timeout_seconds=25)
        if ok_mmi and not _looks_invalid(out_mmi):
            logger.emit("Modo de saida original habilitado para esta sessao.")

        logger.emit("Etapa 3/3: Coletando configuracao...")
        commands = [
            "display current-configuration",
            "display saved-configuration",
            "display current-configuration simple",
            "display startup",
            "display current-configuration all",
            "show running-config",
            "show startup-config",
        ]

        best_usable = ""
        used_usable = None
        best_any = ""
        used_any = None
        incomplete_candidates = []
        for cmd in commands:
            ok, out = _send_and_collect(child, cmd, timeout_seconds=FULL_CONFIG_TIMEOUT_SECONDS)
            txt = _strip_command_noise(out, cmd)
            if not txt:
                continue

            invalid = _looks_invalid(txt)
            complete = _is_complete_config_output(ok, txt)
            has_return = _has_config_terminator(txt)
            logger.emit(
                f"Diagnostico comando '{cmd}': ok={ok} len={len(txt)} "
                f"invalid={invalid} complete={complete} return={has_return}"
            )

            if len(txt) > len(best_any):
                best_any = txt
                used_any = cmd

            if not invalid and _looks_like_config(txt) and not complete:
                incomplete_candidates.append((cmd, len(txt)))
                logger.emit(
                    f"Ignorando retorno incompleto de '{cmd}' ({len(txt)} caracteres).",
                    "warning",
                )
                continue

            if complete and not invalid and _looks_like_config(txt) and len(txt) > len(best_usable):
                best_usable = txt
                used_usable = cmd

            if complete and not invalid and _looks_like_config(txt):
                break

        selected = best_usable
        used = used_usable
        # fallback 1: firmwares que misturam mensagens de erro e config no mesmo bloco
        if len(selected) < 80 and len(best_any) >= 300 and _looks_like_config(best_any) and _has_config_terminator(best_any):
            selected = best_any
            used = used_any
            logger.emit("Usando fallback do maior retorno bruto por firmware legado.", "warning")

        # fallback 2: config coletada é grande e válida mas não tem terminador "return"
        # (firmwares Huawei OLT que não emitem "return" ao final do display current-configuration).
        # Se o comando retornou >= 5 000 chars de config válida, aceita mesmo sem terminador.
        MIN_INCOMPLETE_FALLBACK_LEN = 5_000
        if not _looks_like_config(selected) and incomplete_candidates:
            best_incomplete_cmd, best_incomplete_len = max(incomplete_candidates, key=lambda x: x[1])
            if best_incomplete_len >= MIN_INCOMPLETE_FALLBACK_LEN and _looks_like_config(best_any):
                selected = best_any
                used = best_incomplete_cmd
                logger.emit(
                    f"Usando retorno incompleto de '{best_incomplete_cmd}' ({best_incomplete_len} chars) "
                    "como backup valido (sem terminador 'return', mas conteudo valido).",
                    "warning",
                )

        if not _looks_like_config(selected):
            msg = "Falha durante a coleta do backup: configuracao retornada muito curta/vazia."
            if incomplete_candidates:
                detail = ", ".join(f"{cmd}={size}" for cmd, size in incomplete_candidates[-3:])
                msg = f"{msg} Retornos incompletos ignorados: {detail}."
            logger.emit(msg, "error")
            return (False, msg, None, "SCRIPT")

        with open(backup_path, "w", encoding="utf-8") as fp:
            fp.write(selected)

        msg = f"Backup de '{nome_dispositivo}' concluido!"
        if used:
            msg = f"{msg} ({used})"
        logger.emit(msg, "success")
        return (True, msg, backup_path)
    except pexpect.TIMEOUT:
        msg = "Timeout: O equipamento nao respondeu a tempo durante o backup."
        logger.emit(msg, "error")
        return (False, msg, None, "TIMEOUT")
    except Exception as exc:
        category = _failure_category_from_reason(str(exc))
        if category == "CONEXAO":
            msg = friendly_failure_message(category, str(exc))
        else:
            msg = friendly_unexpected_error(exc)
        logger.emit(msg, "error")
        return (False, msg, None, category)
    finally:
        close_pexpect_session(child)
