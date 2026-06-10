from typing import List, Tuple
import re
import time

from netmiko import ConnectHandler
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
    "aaa",
    "snmp-agent",
    "user-interface",
    "acl ",
    "return",
    "hostname ",
    "line vty",
    "end",
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

SSH_ALGORITHM_ERROR_MARKERS = (
    "incompatible ssh peer",
    "no acceptable kex algorithm",
    "no matching key exchange",
    "kex algorithm",
    "no matching cipher",
    "no acceptable ciphers",
)

PROMPT_LINE_RE = r"(?m)^(?:<[^>\r\n]+>|\[[^\]\r\n]+\]|[A-Za-z0-9][A-Za-z0-9_.:/-]*(?:\([^\r\n)]*\))?[>#])\s*$"
PAGER_RE = r"--More--|---- More ----|\[More\]|<--- More --->|Press any key|\s+More\s*\( Press 'Q' to break \)"


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


def _is_ssh_algorithm_error(detail: str) -> bool:
    lowered = (detail or "").lower()
    return any(marker in lowered for marker in SSH_ALGORITHM_ERROR_MARKERS)


def _ssh_legacy_command(ip: str, usuario: str, porta: int) -> str:
    return (
        "ssh "
        f"{ssh_host_key_options()} "
        "-o ConnectTimeout=25 "
        "-o PreferredAuthentications=password,keyboard-interactive "
        "-o PubkeyAuthentication=no "
        "-o HostKeyAlgorithms=+ssh-rsa,ssh-dss "
        "-o PubkeyAcceptedAlgorithms=+ssh-rsa,ssh-dss "
        "-o KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1 "
        "-o Ciphers=+aes128-cbc,3des-cbc,aes256-cbc "
        "-o MACs=+hmac-sha1,hmac-md5 "
        f"{usuario}@{ip} -p {int(porta)}"
    )


def _clean_terminal_text(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"\x1B\[[0-9;?]*[A-Za-z]", "", text)
    text = re.sub(r".\x08", "", text)
    return text.replace("\r", "")


def _coerce_pexpect_text(value) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _login_legacy_ssh(child, usuario: str, password: str, timeout: int = 25) -> Tuple[bool, str]:
    deadline = time.monotonic() + 80
    last_reason = ""
    while time.monotonic() < deadline:
        idx = child.expect(
            [
                r"(?i)are you sure you want to continue connecting",
                r"(?i)(?:user\s*name|username|login)\s*[:>]\s*$",
                r"(?i)password\s*[:>]\s*$",
                r"(?i)(permission denied|authentication failed|login failed|bad username|bad password)",
                r"(?i)(connection refused|closed by remote host|no route to host|network is unreachable|connection reset)",
                PROMPT_LINE_RE,
                pexpect.TIMEOUT,
                pexpect.EOF,
            ],
            timeout=max(1, min(timeout, int(deadline - time.monotonic()))),
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
            reason = _clean_terminal_text(_coerce_pexpect_text(child.before) + _coerce_pexpect_text(child.after))
            return False, reason or "Credenciais recusadas pelo equipamento."
        if idx == 4:
            reason = _clean_terminal_text(_coerce_pexpect_text(child.before) + _coerce_pexpect_text(child.after))
            return False, reason or "Conexao recusada ou encerrada pelo equipamento."
        if idx == 5:
            return True, ""
        if idx == 6:
            last_reason = _clean_terminal_text(_coerce_pexpect_text(child.before))
            child.sendline("")
            continue
        reason = _clean_terminal_text(_coerce_pexpect_text(child.before) + _coerce_pexpect_text(child.after))
        return False, reason or "Conexao encerrada antes do login/banner."
    return False, last_reason or "Tempo esgotado aguardando login/banner do equipamento."


def _send_and_collect_legacy(child, command: str, timeout_seconds: int = 480) -> Tuple[bool, str]:
    child.sendline(command)
    chunks = []
    deadline = time.time() + timeout_seconds

    while True:
        remaining = int(deadline - time.time())
        if remaining <= 0:
            return False, _clean_terminal_text("".join(chunks))

        idx = child.expect(
            [
                PROMPT_LINE_RE,
                PAGER_RE,
                r"(?mi)^\s*\{[^\r\n}]*(?:<cr>|<K>)[^\r\n}]*\}\s*:?\s*$",
                pexpect.TIMEOUT,
                pexpect.EOF,
            ],
            timeout=max(5, min(30, remaining)),
        )
        chunks.append(_coerce_pexpect_text(child.before))

        if idx == 0:
            return True, _clean_terminal_text("".join(chunks))
        if idx == 1:
            child.send(" ")
            continue
        if idx == 2:
            child.sendline("")
            continue
        if idx == 3:
            if int(deadline - time.time()) > 0:
                continue
            return False, _clean_terminal_text("".join(chunks))
        chunks.append(_coerce_pexpect_text(child.after))
        return True, _clean_terminal_text("".join(chunks))


def _strip_legacy_output(output: str, command: str) -> str:
    text = _clean_terminal_text(output or "").strip()
    if command and text.startswith(command):
        text = text[len(command):].lstrip()
    text = re.sub(PROMPT_LINE_RE, "", text).strip()
    return text


def _legacy_ssh_backup(
    ip: str,
    usuario: str,
    porta: int,
    password: str,
    backup_path: str,
    jump_host: dict | None,
    logger: BackupLogger,
) -> Tuple:
    child = None
    try:
        logger.emit("Etapa 1.1: Conectando com modo SSH legado...")
        child = open_pexpect_session(
            _ssh_legacy_command(ip, usuario, porta),
            jump_host=jump_host,
            timeout=35,
            encoding="utf-8",
            codec_errors="ignore",
            logger=logger,
        )

        ok_login, login_reason = _login_legacy_ssh(child, usuario, password)
        if not ok_login:
            category = _classify_connection_failure(login_reason)
            msg = friendly_failure_message(category, login_reason)
            logger.emit(msg, "error")
            return (False, msg, None, category)

        logger.emit("Conexao estabelecida via SSH legado.", "success")
        logger.emit("Etapa 2/4: Ajustando paginacao...")
        for prep_cmd in ("screen-length 0 temporary", "terminal length 0"):
            ok, out = _send_and_collect_legacy(child, prep_cmd, timeout_seconds=25)
            if ok and not _looks_invalid(out):
                break

        logger.emit("Etapa 3/4: Coletando configuracao...")
        best_output = ""
        used_cmd = None
        for cmd in ("display current-configuration", "display saved-configuration"):
            ok, out = _send_and_collect_legacy(child, cmd, timeout_seconds=600)
            cleaned = _strip_legacy_output(out, cmd)
            if cleaned and len(cleaned.strip()) > len(best_output.strip()):
                best_output = cleaned
                used_cmd = cmd
            if ok and not _looks_invalid(cleaned) and _looks_like_config(cleaned):
                break

        if not best_output or _looks_invalid(best_output) or not _looks_like_config(best_output):
            msg = "O dispositivo conectou via SSH legado, mas nao retornou uma configuracao valida."
            logger.emit(msg, "error")
            return (False, msg, None, "SCRIPT")

        with open(backup_path, "w", encoding="utf-8") as fp:
            fp.write(best_output)

        msg = f"Backup do Switch Huawei concluido com sucesso ({used_cmd}, SSH legado)."
        logger.emit(msg, "success")
        return (True, msg, backup_path)
    finally:
        close_pexpect_session(child)


def _looks_invalid(output: str) -> bool:
    lines = (output or "").splitlines()
    for line in lines[:80]:
        lowered = line.strip().lower()
        if not lowered:
            continue
        if any(marker in lowered for marker in ERROR_MARKERS):
            return True
    return False


def _looks_like_config(output: str) -> bool:
    text = (output or "").strip()
    if len(text) < 40:
        return False
    lowered = text.lower()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if "current configuration" in lowered or "configuration file" in lowered:
        return True
    if any(marker in lowered for marker in CONFIG_MARKERS):
        return True
    # Alguns firmwares retornam config "enxuta" sem cabeçalhos esperados;
    # aceita quando ha volume/estrutura suficiente e sem indício de erro.
    if len(lines) >= 6 and len(text) >= 120 and not _looks_invalid(text):
        return True
    # Configuracoes longas em Huawei podem nao conter os marcadores acima
    # em alguns modelos/firmwares; evita falso negativo.
    if len(text) >= 600 and not _looks_invalid(text):
        return True
    # Heuristica adicional para equipamentos com config curta
    if "\n#" in text or text.startswith("#"):
        return True
    return False


def _device_candidates(use_telnet: bool) -> List[str]:
    base = ["huawei", "cisco_ios", "tplink_jetstream"]
    if not use_telnet:
        return base

    telnet_first = []
    for item in base:
        if item.endswith("_telnet"):
            telnet_first.append(item)
        elif item in ("huawei", "cisco_ios"):
            telnet_first.append(f"{item}_telnet")
    return list(dict.fromkeys(telnet_first + base))


def _send_maybe_paged(conn, command: str, read_timeout: int = 300) -> str:
    output = conn.send_command_timing(
        command,
        read_timeout=read_timeout,
        strip_command=False,
        strip_prompt=False,
    )
    safety = 0
    while safety < 300:
        lowered = (output or "").lower()
        if any(marker in output for marker in PAGER_MARKERS):
            safety += 1
            output += conn.send_command_timing(
                " ",
                read_timeout=30,
                strip_command=False,
                strip_prompt=False,
            )
            continue
        if any(marker in lowered for marker in CONFIRM_MARKERS):
            safety += 1
            output += conn.send_command_timing(
                "y",
                read_timeout=30,
                strip_command=False,
                strip_prompt=False,
            )
            continue
        break
    return output


def _collect_configuration(conn) -> Tuple[str, str]:
    collected = ""
    used_cmd = None

    for cmd in (
        "display current-configuration",
        "display current-configuration all",
        "show running-config",
        "show configuration",
    ):
        for attempt in range(1, 3):
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
    logger.emit("Iniciando backup para Switch Huawei...")

    parametros = parametros or {}
    password = parametros.get("password")
    if not password:
        msg = "Falha: 'password' e um parametro obrigatorio."
        logger.emit(msg, "error")
        return (False, msg, None, "CONFIGURACAO")

    use_telnet = bool(parametros.get("use_telnet") or kwargs.get("use_telnet") or kwargs.get("usar_telnet"))
    jump_host = kwargs.get("jump_host") or parametros.get("jump_host") or None
    candidates = _device_candidates(use_telnet)

    logger.emit(f"Etapa 1/4: Testando conexao {'TELNET' if use_telnet else 'SSH'}...")
    selected_type = None
    conn_errors: List[str] = []
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
            conn_errors.append(f"{device_type}: {_safe_exc_text(exc)}")
            continue

    if not selected_type:
        detail = "; ".join(conn_errors[:3]).strip()
        if not use_telnet and _is_ssh_algorithm_error(detail):
            logger.emit("SSH padrao incompativel com o equipamento; tentando modo SSH legado...", "warning")
            caminho_local = prepare_backup_path(
                backup_base_path,
                nome_provedor,
                nome_tipo_equip,
                nome_dispositivo,
                "cfg",
            )
            return _legacy_ssh_backup(
                ip=ip,
                usuario=usuario,
                porta=porta,
                password=password,
                backup_path=caminho_local,
                jump_host=jump_host,
                logger=logger,
            )

        category = _classify_connection_failure(detail)
        msg = friendly_failure_message(category, detail)
        logger.emit(msg, "error")
        return (False, msg, None, category)

    logger.emit(f"Teste de conexao bem-sucedido com '{selected_type}'.", "success")

    caminho_local = prepare_backup_path(
        backup_base_path,
        nome_provedor,
        nome_tipo_equip,
        nome_dispositivo,
        "cfg",
    )

    try:
        collected = ""
        used_cmd = None
        for conn_attempt in (1, 2):
            logger.emit(f"Etapa 2/4: Reconectando com '{selected_type}'...")
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
            ) as net_connect:
                logger.emit("Conexao estabelecida.", "success")

                logger.emit("Etapa 3/4: Ajustando paginacao...")
                for cmd in ("screen-length 0 temporary", "terminal length 0", "screen-length disable", "scroll"):
                    try:
                        out = net_connect.send_command_timing(
                            cmd,
                            read_timeout=20,
                            strip_command=False,
                            strip_prompt=False,
                        )
                        if out and ":" in out:
                            net_connect.send_command_timing(
                                "",
                                read_timeout=15,
                                strip_command=False,
                                strip_prompt=False,
                            )
                        if not _looks_invalid(out):
                            break
                    except Exception:
                        continue

                logger.emit("Etapa 4/4: Coletando configuracao...")
                current_output, current_cmd = _collect_configuration(net_connect)
                if current_output and len(current_output.strip()) > len(collected.strip()):
                    collected = current_output
                    used_cmd = current_cmd

            if collected and not _looks_invalid(collected) and _looks_like_config(collected):
                break
            if conn_attempt < 2:
                logger.warning(
                    "Configuracao retornada nao passou na validacao (tentativa %s/2). Reconectando para nova coleta...",
                    conn_attempt,
                )

        if not collected or _looks_invalid(collected) or not _looks_like_config(collected):
            raise ValueError("O dispositivo nao retornou uma configuracao valida.")

        with open(caminho_local, "w", encoding="utf-8") as fp:
            fp.write(collected)

        msg = f"Backup do Switch Huawei '{nome_dispositivo}' concluido com sucesso ({used_cmd})."
        logger.emit(msg, "success")
        return (True, msg, caminho_local)
    except Exception as exc:
        error_msg = friendly_unexpected_error(_safe_exc_text(exc))
        logger.emit(error_msg, "error")
        return (False, error_msg, None, "SCRIPT")
