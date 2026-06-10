from typing import List, Tuple
import re

import pexpect
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
    "% invalid",
    "% incomplete",
    "% ambiguous",
)
PAGER_MARKERS = ("--More--", "Press any key", "---- More ----", "[More]")
CONFIG_MARKERS = (
    "version ",
    "hostname ",
    "interface ",
    "vlan ",
    "ip address",
    "ip route",
    "spanning-tree",
    "router ",
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


def _invalid(output: str) -> bool:
    text = (output or "").lower()
    return any(marker in text for marker in ERROR_MARKERS)


def _looks_like_config(output: str) -> bool:
    text = (output or "").strip()
    if len(text) < 80:
        return False
    if _invalid(text):
        return False
    lowered = text.lower()
    marker_count = sum(1 for marker in CONFIG_MARKERS if marker in lowered)
    if marker_count >= 2:
        return True
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) >= 20 and marker_count >= 1:
        return True
    if len(text) >= 2500 and any(marker in lowered for marker in ("interface ", "vlan ", "hostname ")):
        return True
    return False


def _diagnostic_preview(output: str, limit: int = 160) -> str:
    text = re.sub(r"(?i)(password|secret|community)\s+\S+", r"\1 ***", output or "")
    text = re.sub(r"\s+", " ", text).strip()
    return (text[:limit].rstrip() + "...") if len(text) > limit else text


def _classify_connection_failure(detail: str) -> str:
    lowered = (detail or "").lower()
    if any(marker in lowered for marker in NETWORK_ERROR_MARKERS):
        return "CONEXAO"
    if any(marker in lowered for marker in AUTH_ERROR_MARKERS):
        return "AUTENTICACAO"
    return "AUTENTICACAO"


def _device_candidates(use_telnet: bool) -> List[str]:
    base = ["cisco_ios", "huawei"]
    if not use_telnet:
        return base
    return ["cisco_ios_telnet", "huawei_telnet"] + base


def _send_maybe_paged(conn, command: str, read_timeout: int = 300) -> str:
    output = netmiko_send_command_interactive(
        conn,
        command,
        read_timeout=read_timeout,
        strip_command=False,
        strip_prompt=False,
    )
    return output


def _collect_telnet_pexpect(ip: str, porta: int, usuario: str, password: str, logger: BackupLogger, enable_password: str = None) -> str:
    session = pexpect.spawn(f"telnet {ip} {int(porta)}", timeout=35, encoding="utf-8", codec_errors="ignore")
    prompt_host = r"[A-Za-z0-9][A-Za-z0-9_.:/_-]*"
    prompt = rf"(?m)^(?:<{prompt_host}>|{prompt_host}(?:\([^\r\n)]*\))?[>#])\s*$"
    try:
        for _ in range(12):
            idx = session.expect([
                r"(?i)(user\s*name|username|login)[: ]",
                r"(?i)password[: ]",
                prompt,
                r"(?i)change now|please choose",
                pexpect.TIMEOUT,
                pexpect.EOF,
            ], timeout=35)
            if idx == 0:
                session.sendline(usuario or "")
                continue
            if idx == 1:
                session.sendline(password or "")
                continue
            if idx == 2:
                break
            if idx == 3:
                # Alguns equipamentos pedem troca de senha ao conectar.
                session.sendline("N")
                continue
            if idx in (4, 5):
                session.sendline("")
                continue
        else:
            raise RuntimeError("Falha no fluxo de login Telnet.")

        session.sendline("enable")
        idx = session.expect([r"(?i)password[: ]", prompt, pexpect.TIMEOUT, pexpect.EOF], timeout=10)
        if idx == 0:
            for secret in (enable_password, password, usuario):
                if not secret:
                    continue
                session.sendline(secret)
                j = session.expect([prompt, r"(?i)password[: ]", pexpect.TIMEOUT, pexpect.EOF], timeout=10)
                if j == 0:
                    break
                if j == 1:
                    continue
                break

        for cmd in ("terminal length 0", "terminal width 511", "no page", "screen-length 0 temporary", "paginate false"):
            session.sendline(cmd)
            session.expect([prompt, r":", pexpect.TIMEOUT], timeout=12)
            if session.after == ":":
                session.sendline("")
                session.expect(prompt, timeout=12)

        best = ""
        best_cmd = None
        for cmd in ("show running-config", "show startup-config", "show run", "show configuration", "display current-configuration"):
            session.sendline(cmd)
            chunks = []
            safety = 0
            while True:
                idx = session.expect([
                    prompt,
                    r"--More--|---- More ----|\[More\]|Press any key",
                    r":",
                    pexpect.TIMEOUT,
                    pexpect.EOF,
                ], timeout=25)
                chunks.append(session.before or "")
                if idx == 0:
                    break
                if idx == 1:
                    safety += 1
                    if safety > 250:
                        break
                    session.send(" ")
                    continue
                if idx == 2:
                    session.sendline("")
                    continue
                if idx in (3, 4):
                    break
            text = "".join(chunks)
            logger.emit(
                f"Diagnostico Telnet comando '{cmd}': len={len(text.strip())} "
                f"invalid={_invalid(text)} meaningful={_looks_like_config(text)}"
            )
            if text and not _invalid(text) and len(text.strip()) > len(best.strip()):
                best = text
                best_cmd = cmd
            if text and _looks_like_config(text):
                break

        if not _looks_like_config(best):
            preview = _diagnostic_preview(best)
            detail = f" Preview: {preview}" if preview else ""
            raise RuntimeError(f"O dispositivo nao retornou configuracao valida via Telnet fallback.{detail}")

        logger.emit(f"Coleta realizada via fallback Telnet (pexpect) com '{best_cmd}'.", "warning")
        return best
    finally:
        if session.isalive():
            session.close(force=True)


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
    logger.emit(f"Iniciando backup para {nome_dispositivo} ({nome_tipo_equip})...")

    parametros = parametros or {}
    password = parametros.get("password")
    if not password:
        msg = "Falha: 'password' e um parametro obrigatorio."
        logger.emit(msg, "error")
        return (False, msg, None, "CONFIGURACAO")

    use_telnet = bool(parametros.get("use_telnet") or kwargs.get("use_telnet") or kwargs.get("usar_telnet"))
    enable_password = parametros.get("enable_password")
    candidates = _device_candidates(use_telnet)

    logger.emit("Etapa 1/3: Testando conexao e autenticacao...")
    selected_type = None
    errors = []
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
            errors.append(f"{device_type}: {type(exc).__name__}: {exc}")

    caminho_local = prepare_backup_path(backup_base_path, nome_provedor, nome_tipo_equip, nome_dispositivo, "cfg")

    # Fallback direto para Telnet pexpect quando Netmiko nao autentica no equipamento.
    if not selected_type and use_telnet:
        try:
            output = _collect_telnet_pexpect(ip, int(porta), usuario, password, logger, enable_password=enable_password)
            with open(caminho_local, "w", encoding="utf-8") as fp:
                fp.write(output)
            msg = "Backup concluido com sucesso via fallback Telnet."
            logger.emit(msg, "success")
            return (True, msg, caminho_local)
        except Exception as exc:
            errors.append(f"telnet_fallback: {type(exc).__name__}: {exc}")

    if not selected_type:
        detail = "; ".join(errors[:3])
        category = _classify_connection_failure(detail)
        msg = friendly_failure_message(category, detail)
        logger.emit(msg, "error")
        return (False, msg, None, category)

    try:
        logger.emit(f"Etapa 2/3: Coletando configuracao com '{selected_type}'...")
        with ConnectHandler(
            device_type=selected_type,
            host=ip,
            port=int(porta),
            username=usuario,
            password=password,
            conn_timeout=25,
            banner_timeout=25,
            auth_timeout=25,
            fast_cli=False,
        ) as net_connect:
            try:
                prompt = net_connect.find_prompt().strip()
                if prompt.endswith(">"):
                    out = net_connect.send_command_timing("enable", read_timeout=20, strip_command=False, strip_prompt=False)
                    if "password" in (out or "").lower():
                        net_connect.send_command_timing(enable_password or password or "", read_timeout=20, strip_command=False, strip_prompt=False)
            except Exception:
                pass

            for cmd in ("terminal length 0", "terminal width 511", "no page", "screen-length 0 temporary", "paginate false"):
                try:
                    out = net_connect.send_command_timing(cmd, read_timeout=20)
                    if not _invalid(out):
                        break
                except Exception:
                    continue

            output = ""
            used_cmd = None
            best_valid = False
            for cmd in ("show running-config", "show startup-config", "show run", "show configuration", "display current-configuration"):
                try:
                    out = _send_maybe_paged(net_connect, cmd, read_timeout=300)
                    meaningful = _looks_like_config(out)
                    logger.emit(
                        f"Diagnostico comando '{cmd}': len={len((out or '').strip())} "
                        f"invalid={_invalid(out)} meaningful={meaningful}"
                    )
                    if out and not _invalid(out) and len(out.strip()) > len(output.strip()):
                        output = out
                        used_cmd = cmd
                        best_valid = meaningful
                    if out and meaningful:
                        break
                except Exception:
                    continue

            if not best_valid:
                preview = _diagnostic_preview(output)
                detail = f" Preview: {preview}" if preview else ""
                raise RuntimeError(f"O dispositivo nao retornou uma configuracao valida.{detail}")

        logger.emit("Etapa 3/3: Salvando arquivo de backup...")
        with open(caminho_local, "w", encoding="utf-8") as fp:
            fp.write(output)

        msg = "Backup concluido com sucesso!"
        if used_cmd:
            msg = f"{msg} ({used_cmd})"
        logger.emit(msg, "success")
        return (True, msg, caminho_local)
    except Exception as exc:
        # Ultima tentativa em Telnet bruto se o fluxo Netmiko quebrar no meio.
        if use_telnet:
            try:
                output = _collect_telnet_pexpect(ip, int(porta), usuario, password, logger, enable_password=enable_password)
                with open(caminho_local, "w", encoding="utf-8") as fp:
                    fp.write(output)
                msg = "Backup concluido com sucesso via fallback Telnet."
                logger.emit(msg, "success")
                return (True, msg, caminho_local)
            except Exception:
                pass

        msg = friendly_unexpected_error(exc)
        logger.emit(msg, "error")
        return (False, msg, None, "SCRIPT")
