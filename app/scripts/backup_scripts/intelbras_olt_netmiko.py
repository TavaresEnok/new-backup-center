import re
import time
from typing import Tuple

import pexpect
from netmiko import ConnectHandler

from script_helpers import (
    BackupLogger,
    close_pexpect_session,
    friendly_failure_message,
    friendly_unexpected_error,
    open_pexpect_session,
    prepare_backup_path,
    ssh_host_key_options,
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
PROMPT_REGEX = r"\S+[>#]\s*$|<[^>]+>"
PAGER_REGEX = r"--More--|---- More ----|\[More\]|<--- More --->|Press any key|\s+More\s*\( Press 'Q' to break \)"


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


def _clean_output(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"\x1B\[[0-9;?]*[A-Za-z]", "", text)
    text = re.sub(r".\x08", "", text)
    return text.replace("\r", "")


def _open_and_login(child, usuario: str, password: str, timeout: int = 25):
    for _ in range(14):
        idx = child.expect(
            [
                r"(?i)are you sure you want to continue connecting",
                r"(?i)(press\s+enter|pressione\s+enter|any key to continue)",
                r"(?i)(user\s*name|username|login)[: ]",
                r"(?i)password[: ]",
                PROMPT_REGEX,
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
            return child.after or ""
        if idx in (5, 6):
            child.sendline("")
            continue
    raise RuntimeError("Nao foi possivel concluir a autenticacao/interacao com a OLT Intelbras.")


def _enter_enable(child, enable_passwords: list[str], timeout: int = 12) -> None:
    child.sendline("enable")
    idx = child.expect([r"(?i)password[: ]", PROMPT_REGEX, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
    if idx == 1:
        return
    if idx != 0:
        return
    for secret in enable_passwords:
        if not secret:
            continue
        child.sendline(secret)
        sub = child.expect([PROMPT_REGEX, r"(?i)password[: ]", pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
        if sub == 0:
            return


def _disable_pagination(child) -> None:
    for cmd in ("terminal length 0", "screen-length 0 temporary", "paginate false", "no page", "scroll"):
        child.sendline(cmd)
        try:
            idx = child.expect([PROMPT_REGEX, PAGER_REGEX, r":", pexpect.TIMEOUT, pexpect.EOF], timeout=12)
        except Exception:
            continue
        if idx == 1:
            child.send(" ")
        elif idx == 2:
            child.sendline("")
        elif idx == 0:
            return


def _send_collect(child, command: str, timeout_seconds: int = 420) -> tuple[bool, str]:
    child.sendline(command)
    deadline = time.time() + timeout_seconds
    chunks = []
    while True:
        remaining = int(deadline - time.time())
        if remaining <= 0:
            return False, _clean_output("".join(chunks))

        idx = child.expect(
            [
                PROMPT_REGEX,
                PAGER_REGEX,
                r":",
                pexpect.TIMEOUT,
                pexpect.EOF,
            ],
            timeout=max(5, min(25, remaining)),
        )
        chunks.append(child.before or "")

        if idx == 0:
            return True, _clean_output("".join(chunks))
        if idx == 1:
            child.send(" ")
            continue
        if idx == 2:
            child.sendline("")
            continue
        if idx == 3:
            return False, _clean_output("".join(chunks))
        if idx == 4:
            return True, _clean_output("".join(chunks))


def _normalize_config_output(command: str, output: str) -> str:
    text = (output or "").strip()
    if not text:
        return ""
    pattern = r"^.*?" + re.escape(command).replace("\\ ", r"\\s+") + r"\s*"
    text = re.sub(pattern, "", text, flags=re.S).strip()
    text = re.sub(PAGER_REGEX, "", text, flags=re.I)
    return text.strip()


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
    protocol_label = "TELNET" if use_telnet else "SSH"
    enable_password = parametros.get("enable_password") or password
    enable_secrets = []
    for secret in (enable_password, password, usuario):
        value = str(secret or "").strip()
        if value and value not in enable_secrets:
            enable_secrets.append(value)

    logger.emit(f"Iniciando backup para {nome_dispositivo} ({nome_tipo_equip}) via {protocol_label}...")

    if use_telnet:
        command = f"telnet {ip} {int(porta)}"
        jump_host = kwargs.get("jump_host") or parametros.get("jump_host") or None
        caminho_local = prepare_backup_path(backup_base_path, nome_provedor, nome_tipo_equip, nome_dispositivo, "cfg")
        child_test = None
        try:
            logger.emit("Etapa 1/4: Testando conexao TELNET...")
            child_test = open_pexpect_session(
                command,
                jump_host=jump_host,
                timeout=max(25, int(timeout_value)),
                encoding="utf-8",
                codec_errors="ignore",
                logger=logger,
            )
            prompt = _open_and_login(child_test, usuario, password, timeout=28)
            if re.search(r">\s*$", prompt or ""):
                _enter_enable(child_test, enable_secrets, timeout=12)
            logger.emit("Teste de conexao bem-sucedido.", "success")
        except Exception as exc:
            detail = f"{type(exc).__name__}: {exc}"
            category = _classify_connection_failure(detail)
            msg = friendly_failure_message(category, detail)
            logger.emit(msg, "error")
            return (False, msg, None, category)
        finally:
            close_pexpect_session(child_test)

        child = None
        try:
            logger.emit("Etapa 2/4: Reconectando via TELNET...")
            child = open_pexpect_session(
                command,
                jump_host=jump_host,
                timeout=max(35, int(timeout_value)),
                encoding="utf-8",
                codec_errors="ignore",
                logger=logger,
            )
            prompt = _open_and_login(child, usuario, password, timeout=30)
            if re.search(r">\s*$", prompt or ""):
                _enter_enable(child, enable_secrets, timeout=12)
            logger.emit("Conexao estabelecida.", "success")

            logger.emit("Etapa 3/4: Desativando paginacao...")
            _disable_pagination(child)

            logger.emit("Etapa 4/4: Coletando configuracao...")
            output = ""
            used_command = None
            last_rejected = ""
            commands = (
                "show running-config-devel",
                "show running-config",
                "show startup-config",
                "show configuration",
                "display current-configuration",
                "show config",
                "write terminal",
                "display config",
            )
            for cmd in commands:
                try:
                    ok, out = _send_collect(child, cmd, timeout_seconds=420)
                except Exception:
                    continue
                cleaned = _normalize_config_output(cmd, out)
                if cleaned and _invalid(cleaned):
                    last_rejected = cleaned[:200]
                    continue
                if cleaned and len(cleaned) > len(output):
                    output = cleaned
                    used_command = cmd
                if ok and cleaned and len(cleaned) >= 80:
                    break

            logger.emit("Coleta da configuracao concluida.")

            if not output or _invalid(output) or len(output.strip()) < 80:
                detail = "O dispositivo nao retornou uma configuracao valida ou o comando foi rejeitado."
                if used_command:
                    detail = f"{detail} Ultimo comando util: {used_command}."
                if last_rejected:
                    detail = f"{detail} Resposta: {last_rejected}"
                raise RuntimeError(detail)

            with open(caminho_local, "w", encoding="utf-8") as fp:
                fp.write(output)

            msg = "Backup concluido com sucesso!"
            if used_command:
                msg = f"{msg} ({used_command})"
            logger.emit(msg, "success")
            return (True, msg, caminho_local)
        except Exception as exc:
            msg = friendly_unexpected_error(exc)
            logger.emit(msg, "error")
            return (False, msg, None, "SCRIPT")
        finally:
            close_pexpect_session(child)

    device_type = "cisco_ios"
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
        "global_delay_factor": 2,
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

    caminho_local = prepare_backup_path(backup_base_path, nome_provedor, nome_tipo_equip, nome_dispositivo, "cfg")

    try:
        logger.emit(f"Etapa 2/4: Reconectando via {protocol_label}...")
        with ConnectHandler(**device_config) as net_connect:
            prompt = net_connect.find_prompt()
            logger.emit("Conexao estabelecida.", "success")

            logger.emit("Etapa 3/4: Desativando paginacao...")
            for cmd in ("terminal length 0", "screen-length 0 temporary", "paginate false", "no page"):
                try:
                    out = net_connect.send_command(
                        cmd,
                        expect_string=re.escape(prompt.strip()),
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
            for cmd in (
                "show running-config-devel",
                "show running-config",
                "show startup-config",
                "show configuration",
                "display current-configuration",
                "show config",
                "write terminal",
                "display config",
            ):
                try:
                    out = net_connect.send_command_timing(
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

        with open(caminho_local, "w", encoding="utf-8") as fp:
            fp.write(output)

        msg = f"Backup concluido com sucesso!"
        if used_command:
            msg = f"{msg} ({used_command})"
        logger.emit(msg, "success")
        return (True, msg, caminho_local)
    except Exception as exc:
        msg = friendly_unexpected_error(exc)
        logger.emit(msg, "error")
        return (False, msg, None, "SCRIPT")
