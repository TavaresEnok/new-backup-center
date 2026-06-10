import socket
from typing import Optional, Tuple

from netmiko import ConnectHandler

from script_helpers import (
    BackupLogger,
    friendly_failure_message,
    friendly_unexpected_error,
    netmiko_send_command_interactive,
    prepare_backup_path,
)


ERROR_MARKERS = (
    "bad command",
    "syntax error",
    "expected end of command",
    "failure:",
    "input does not match any value of",
    "unknown command",
)

CONFIG_MARKERS = (
    "/interface",
    "/ip ",
    "/routing",
    "/system ",
    "/tool ",
    "/user ",
    "#",
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


def _classify_connection_failure(detail: str) -> str:
    lowered = (detail or "").lower()
    if any(marker in lowered for marker in NETWORK_ERROR_MARKERS):
        return "CONEXAO"
    if any(marker in lowered for marker in AUTH_ERROR_MARKERS):
        return "AUTENTICACAO"
    return "AUTENTICACAO"


def _looks_like_export(output: str) -> bool:
    text = (output or "").strip()
    if len(text) < 40:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in CONFIG_MARKERS)


def _probe_ssh_banner(host: str, port: int, timeout: float = 3.0) -> Tuple[bool, Optional[bool], str]:
    """
    Retorna:
      - tcp_ok: conseguiu abrir TCP
      - ssh_banner_ok: True/False/None (None = inconclusivo)
      - detalhe textual para log
    """
    sock = None
    try:
        sock = socket.create_connection((str(host), int(port)), timeout=timeout)
        sock.settimeout(timeout)
        try:
            sock.sendall(b"SSH-2.0-backup-center-probe\r\n")
        except Exception:
            pass
        try:
            banner = sock.recv(256)
        except socket.timeout:
            return True, None, "banner timeout"
        except Exception as exc:
            return True, None, f"banner unreadable: {type(exc).__name__}"
        raw = (banner or b"").decode("utf-8", errors="ignore").strip()
        if not raw:
            return True, None, "empty banner"
        if raw.startswith("SSH-"):
            return True, True, raw[:120]
        return True, False, raw[:120]
    except Exception as exc:
        return False, None, f"{type(exc).__name__}: {exc}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _collect_export(net_connect) -> Tuple[str, Optional[str]]:
    output = ""
    used_cmd = None
    commands = ["/export terse", "/export", "export terse", "export"]

    for cmd in commands:
        for attempt in range(1, 3):
            try:
                out = netmiko_send_command_interactive(
                    net_connect,
                    cmd,
                    read_timeout=600 if attempt == 1 else 900,
                    strip_command=False,
                    strip_prompt=False,
                )
                if out and not _invalid(out) and len(out.strip()) > len(output.strip()):
                    output = out
                    used_cmd = cmd
                if out and not _invalid(out) and _looks_like_export(out):
                    return out, cmd
            except Exception:
                continue

    return output, used_cmd


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
    logger.emit(f"Iniciando backup para MikroTik: {nome_dispositivo}")

    password = (parametros or {}).get("password")
    if not password:
        msg = "Falha: 'password' e um parametro obrigatorio."
        logger.emit(msg, "error")
        return (False, msg, None, "CONFIGURACAO")

    base_device_config = {
        "device_type": "mikrotik_routeros",
        "host": ip,
        "username": usuario,
        "password": password,
        "conn_timeout": 45,
        "banner_timeout": 90,
        "auth_timeout": 60,
        "fast_cli": False,
        "global_delay_factor": 2,
    }

    caminho_local = prepare_backup_path(backup_base_path, nome_provedor, nome_tipo_equip, nome_dispositivo, "rsc")

    logger.emit("Etapa 1/2: Conectando e realizando o backup...")
    try:
        output = ""
        used_cmd = None
        connected = False
        original_port = int(porta)
        device_config = dict(base_device_config)
        device_config["port"] = original_port

        tcp_ok, ssh_ok, detail = _probe_ssh_banner(ip, original_port, timeout=2.5)
        if not tcp_ok:
            logger.warning(
                "Porta cadastrada %s sem conectividade TCP no probe inicial (%s). Tentando somente essa porta...",
                original_port,
                detail,
            )
        elif ssh_ok is False:
            raise RuntimeError(
                f"Porta cadastrada {original_port} respondeu sem banner SSH valido ({detail})."
            )

        with ConnectHandler(**device_config) as net_connect:
            logger.emit("Conexao estabelecida.", "success")
            output, used_cmd = _collect_export(net_connect)

            if not output or _invalid(output) or not _looks_like_export(output):
                raise RuntimeError("O dispositivo nao retornou configuracao valida.")
            connected = True

        if not connected:
            raise RuntimeError("Nao foi possivel estabelecer conexao valida com o dispositivo.")

    except RuntimeError:
        raise
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        category = _classify_connection_failure(detail)
        msg = friendly_failure_message(category, detail)
        logger.emit(msg, "error")
        return (False, msg, None, category)

    logger.emit("Etapa 2/2: Salvando arquivo de backup...")
    try:
        with open(caminho_local, "w", encoding="utf-8") as fp:
            fp.write(output)

        msg = f"Backup do MikroTik '{nome_dispositivo}' concluido!"
        if used_cmd:
            msg = f"{msg} ({used_cmd})"
        logger.emit(msg, "success")
        return (True, msg, caminho_local)
    except Exception as exc:
        msg = friendly_unexpected_error(exc)
        logger.emit(msg, "error")
        return (False, msg, None, "SCRIPT")
