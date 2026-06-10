
import os
import time
import logging
import base64
import tempfile
import re
from datetime import datetime
from io import StringIO

try:
    import pexpect
    from pexpect.fdpexpect import fdspawn
    PEXPECT_AVAILABLE = True
except ImportError:
    pexpect = None
    fdspawn = None
    PEXPECT_AVAILABLE = False

# Try to import paramiko for SSH
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

try:
    from cryptography.hazmat.primitives import serialization
except ImportError:
    serialization = None

try:
    from netmiko import ConnectHandler
    NETMIKO_AVAILABLE = True
except ImportError:
    ConnectHandler = None
    NETMIKO_AVAILABLE = False


class BackupLogger:
    def __init__(self, device_name, task_id=None, **kwargs):
        self.device_name = device_name
        self.task_id = task_id

    @staticmethod
    def _normalize_message(message, args, kwargs):
        text = str(message)
        if args:
            try:
                text = text % args
            except Exception:
                text = " ".join([text, *[str(arg) for arg in args]])
        if kwargs:
            try:
                text = text % kwargs
            except Exception:
                pairs = " ".join(f"{k}={v}" for k, v in kwargs.items())
                text = f"{text} {pairs}".strip()
        try:
            from app.utils.log_sanitizer import sanitize_operational_message

            return sanitize_operational_message(text)
        except Exception:
            return text

    def emit(self, message, level='info', *args, **kwargs):
        message = self._normalize_message(message, args, kwargs)
        timestamp = datetime.now().strftime('%H:%M:%S')
        logger = logging.getLogger(__name__)
        level_map = {
            'info': logging.INFO,
            'success': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
        }
        logger.log(level_map.get(level, logging.INFO), "[%s] [%s] [%s] %s", timestamp, level.upper(), self.device_name, message)
        if self.task_id:
            try:
                from app.services.realtime_backup_logs import append_task_log
                append_task_log(str(self.task_id), self.device_name, message, level)
            except Exception:
                logger.exception("Falha ao emitir log realtime da task %s", self.task_id)

    def info(self, message, *args, **kwargs):
        self.emit(message, "info", *args, **kwargs)

    def success(self, message, *args, **kwargs):
        self.emit(message, "success", *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        self.emit(message, "warning", *args, **kwargs)

    def error(self, message, *args, **kwargs):
        self.emit(message, "error", *args, **kwargs)


def sanitize_path_component(name: str) -> str:
    if not name: return "UNNAMED"
    s = "".join(c for c in name if c.isalnum() or c in (" ", "_", "-")).strip()
    return s.replace(" ", "_") or "UNNAMED"


def prepare_backup_path(base_dir, prov_name, type_name, dev_name, extension):
    if not base_dir:
        base_dir = os.path.join(os.getcwd(), 'storage', 'backups')
    
    prov_safe = sanitize_path_component(prov_name)
    type_safe = sanitize_path_component(type_name)
    dev_safe = sanitize_path_component(dev_name)
    
    final_path = os.path.join(base_dir, prov_safe, type_safe, dev_safe)
    os.makedirs(final_path, exist_ok=True)
    
    filename = f"backup_{time.strftime('%Y-%m-%d_%H-%M-%S')}.{extension}"
    return os.path.join(final_path, filename)


def ssh_strict_host_key_checking_enabled() -> bool:
    value = os.getenv("BACKUP_SSH_STRICT_HOST_KEY_CHECKING", "0").strip().lower()
    return value in {"1", "true", "yes", "on", "strict"}


def ssh_host_key_options() -> str:
    if ssh_strict_host_key_checking_enabled():
        return "-o StrictHostKeyChecking=yes"
    return "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"


def ssh_host_key_option_list() -> list[str]:
    if ssh_strict_host_key_checking_enabled():
        return ["-o", "StrictHostKeyChecking=yes"]
    return ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]


def configure_paramiko_host_key_policy(client):
    if not PARAMIKO_AVAILABLE:
        return client
    if ssh_strict_host_key_checking_enabled():
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return client


def friendly_failure_message(category: str, detail: str = None, *, operation: str = "backup") -> str:
    """Build operator-friendly failure text without leaking Python/Netmiko internals."""
    cat = str(category or "").strip().upper()
    clean_detail = str(detail or "").strip()
    detail_low = clean_detail.lower()
    if (
        "jump host respondeu" in detail_low
        and "dispositivo destino" in detail_low
        and ("nao abriu" in detail_low or "não abriu" in detail_low)
    ):
        cat = "CONEXAO"
    try:
        from app.utils.log_sanitizer import sanitize_operational_message

        clean_detail = sanitize_operational_message(clean_detail)
    except Exception:
        pass

    if cat == "CONEXAO":
        base = "Falha de conectividade com o dispositivo."
    elif cat == "AUTENTICACAO":
        base = "Comunicacao com o dispositivo estabelecida, mas as credenciais foram recusadas."
    elif cat == "TIMEOUT":
        base = "Tempo esgotado aguardando resposta do equipamento."
    elif cat == "CONFIGURACAO":
        base = "Configuracao do cadastro incompleta ou invalida para executar o backup."
    else:
        base = f"Falha durante a {operation}."

    if clean_detail:
        return f"{base} Detalhe: {clean_detail}"
    return base


def friendly_unexpected_error(exc, *, operation: str = "coleta do backup") -> str:
    detail = str(exc or "").strip()
    try:
        from app.utils.log_sanitizer import sanitize_operational_message

        detail = sanitize_operational_message(detail)
    except Exception:
        pass
    if detail:
        return f"Falha durante a {operation}. Detalhe: {detail}"
    return f"Falha durante a {operation}."


def _wrap_pem(header: str, body: str) -> str:
    body = "".join((body or "").split())
    chunks = [body[i : i + 64] for i in range(0, len(body), 64)]
    return f"-----BEGIN {header}-----\n" + "\n".join(chunks) + f"\n-----END {header}-----\n"


def normalize_private_key_text(raw_key: str) -> str:
    if not raw_key:
        return raw_key

    raw_key = str(raw_key).strip()
    if "BEGIN " in raw_key:
        return raw_key

    compact = "".join(raw_key.split())
    if not compact:
        return raw_key

    padding = "=" * ((4 - len(compact) % 4) % 4)
    try:
        decoded = base64.b64decode(compact + padding, validate=True)
    except Exception:
        return raw_key

    if serialization is not None:
        try:
            private_key = serialization.load_der_private_key(decoded, password=None)
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode()
        except Exception:
            pass

    return _wrap_pem("PRIVATE KEY", compact)


def load_private_key(raw_key: str, logger=None):
    if not raw_key or not PARAMIKO_AVAILABLE:
        return None

    raw_key = str(raw_key).strip()
    candidates = [raw_key]
    normalized = normalize_private_key_text(raw_key)
    if normalized and normalized != raw_key:
        candidates.insert(0, normalized)
        if logger:
            logger.emit("Chave do Jump Host convertida de formato bruto/base64 para PEM.", "info")

    for candidate in candidates:
        for cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey):
            try:
                return cls.from_private_key(StringIO(candidate))
            except Exception:
                continue
    return None


def _drain_spawn_buffer(session, max_reads: int = 8):
    if not session:
        return
    for _ in range(max_reads):
        try:
            chunk = session.read_nonblocking(size=4096, timeout=0.2)
            if not chunk:
                break
        except Exception:
            break


def _build_jump_spawn_command(jump_host: dict, timeout: int = 30, logger=None):
    if not jump_host or not jump_host.get("host") or not jump_host.get("username"):
        raise ValueError("Jump Host invalido para sessao interativa.")

    key_path = None
    key_text = normalize_private_key_text(jump_host.get("key")) if jump_host.get("key") else None
    if key_text:
        fd, key_path = tempfile.mkstemp(prefix="jump_host_", suffix=".pem")
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            fp.write(key_text)
        os.chmod(key_path, 0o600)
        if logger and key_text != str(jump_host.get("key") or "").strip():
            logger.emit("Chave do Jump Host convertida de formato bruto/base64 para PEM.", "info")

    cmd = (
        "ssh -tt "
        f"{ssh_host_key_options()} "
        "-o LogLevel=ERROR "
        "-o ConnectionAttempts=1 "
        "-o PreferredAuthentications=publickey,password,keyboard-interactive "
        "-o PubkeyAuthentication=yes "
        "-o PasswordAuthentication=yes "
        "-o ServerAliveInterval=30 "
        "-o ServerAliveCountMax=2 "
        f"-o ConnectTimeout={int(timeout)} "
    )
    if key_path:
        cmd += f"-i {key_path} "
    cmd += f"-p {int(jump_host.get('port') or 22)} {jump_host.get('username')}@{jump_host.get('host')}"
    return cmd, key_path


def open_pexpect_session(
    command: str,
    jump_host: dict = None,
    timeout: int = 30,
    encoding: str = "utf-8",
    codec_errors: str = "ignore",
    logger=None,
):
    """
    Opens an interactive pexpect session, optionally through a Jump Host shell.
    """
    if not jump_host or not jump_host.get("host"):
        if not PEXPECT_AVAILABLE:
            raise ImportError("pexpect is not installed.")
        return pexpect.spawn(command, timeout=timeout, encoding=encoding, codec_errors=codec_errors)

    shell_retries = max(1, int(os.getenv("JUMP_HOST_SHELL_RETRIES", "7") or 7))
    shell_probe_timeout = max(4, int(os.getenv("JUMP_HOST_SHELL_PROBE_TIMEOUT_SECONDS", "14") or 14))
    last_error = None
    for attempt in range(1, shell_retries + 1):
        jump_command, key_path = _build_jump_spawn_command(jump_host, timeout=timeout, logger=logger)
        session = pexpect.spawn(jump_command, timeout=timeout, encoding=encoding, codec_errors=codec_errors)
        session.delaybeforesend = 0.05
        session._jump_key_path = key_path
        try:
            shell_prompt = r"(?m)^[^\r\n]*[#$>] ?$"
            for _ in range(16):
                idx = session.expect(
                    [
                        r"(?i)are you sure you want to continue connecting",
                        r"(?i)password\s*:",
                        r"(?i)(permission denied|too many authentication failures|kex_exchange_identification|administratively prohibited|channel open failed|no route to host|network is unreachable)",
                        shell_prompt,
                        pexpect.TIMEOUT,
                        pexpect.EOF,
                    ],
                    timeout=timeout,
                )
                if idx == 0:
                    session.sendline("yes")
                    continue
                if idx == 1:
                    jump_password = str(jump_host.get("password") or "")
                    if not jump_password:
                        raise RuntimeError("Jump Host solicitou senha, mas nenhuma senha foi configurada.")
                    session.sendline(jump_password)
                    continue
                if idx == 2:
                    detail = ""
                    try:
                        detail = ((session.before or "") + " " + (session.after or "")).strip()
                    except Exception:
                        detail = ""
                    detail = " ".join(str(detail).split())[:240]
                    if detail:
                        raise RuntimeError(f"Falha ao autenticar/estabelecer sessao no Jump Host: {detail}")
                    raise RuntimeError("Falha ao autenticar/estabelecer sessao no Jump Host.")
                if idx == 3:
                    break
                if idx == 4:
                    session.sendline("")
                    continue
                detail = ""
                try:
                    detail = ((session.before or "") + " " + (session.after or "")).strip()
                except Exception:
                    detail = ""
                detail = " ".join(str(detail).split())[:220]
                if detail:
                    raise RuntimeError(
                        "Sessao com Jump Host encerrada antes do shell ficar disponivel. "
                        f"Detalhe: {detail}"
                    )
                raise RuntimeError("Sessao com Jump Host encerrada antes do shell ficar disponivel.")
            else:
                raise RuntimeError("Nao foi possivel abrir shell interativo no Jump Host.")

            try:
                _drain_spawn_buffer(session)
            except Exception:
                pass

            # Confirma que o shell interativo realmente responde antes de iniciar o comando alvo.
            probe_token = f"__BC_JH_READY_{int(time.time() * 1000)}__"
            session.sendline(f"echo {probe_token}")
            probe_idx = session.expect(
                [
                    re.escape(probe_token),
                    shell_prompt,
                    pexpect.TIMEOUT,
                    pexpect.EOF,
                ],
                timeout=shell_probe_timeout,
            )
            if probe_idx == 3:
                raise RuntimeError(
                    "Sessao com Jump Host encerrada antes do shell ficar disponivel. "
                    "Detalhe: encerrada durante validacao do shell interativo."
                )
            if probe_idx == 2:
                session.sendline("")
                probe_idx_2 = session.expect([shell_prompt, pexpect.TIMEOUT, pexpect.EOF], timeout=shell_probe_timeout)
                if probe_idx_2 != 0:
                    raise RuntimeError(
                        "Sessao com Jump Host encerrada antes do shell ficar disponivel. "
                        "Detalhe: shell nao respondeu ao probe de prontidao."
                    )

            session.sendline(command)
            # Valida que o comando de conexão (telnet/ssh) realmente saiu do shell do jump host
            # e iniciou uma sessão com o dispositivo destino. Se apenas o prompt do jump host
            # reaparecer dentro do timeout de handshake, o dispositivo está inacessível.
            _is_telnet_or_ssh = any(
                command.lstrip().startswith(p) for p in ("telnet", "ssh", "nc ")
            )
            if _is_telnet_or_ssh:
                _device_probe_timeout = max(8, int(os.getenv("JUMP_TARGET_PROBE_TIMEOUT_SECONDS", "15") or 15))
                _jump_shell_prompt = r"(?m)^[^\r\n]*[#$>] ?$"
                # Qualquer saída diferente do prompt do jump host indica progresso real
                # (banner do dispositivo, pedido de login, mensagem de erro do telnet, etc.)
                _device_response_patterns = [
                    r"(?i)(login|username|password|user\s*name|usuario)",  # prompt de login do dispositivo
                    r"(?i)(connected to|escape character|trying \d)",       # mensagem do telnet
                    r"(?i)(ssh:|openssh|protocol|banner|welcome|warning)",  # banner SSH
                    r"(?i)(connection refused|no route|failed|error|unable)", # erro de rede explícito
                    _jump_shell_prompt,  # jump host prompt (sem progresso)
                    pexpect.TIMEOUT,
                    pexpect.EOF,
                ]
                try:
                    _probe_idx = session.expect(_device_response_patterns, timeout=_device_probe_timeout)
                    # idx 4 = prompt do jump host reapareceu → dispositivo não respondeu
                    # idx 5 = timeout → dispositivo não respondeu
                    # idx 6 = EOF → sessão encerrada
                    if _probe_idx in (4, 5, 6):
                        _buf = ""
                        try:
                            _buf = ((session.before or "") + " " + (session.after or "")).strip()
                            _buf = " ".join(str(_buf).split())[:200]
                        except Exception:
                            pass
                        raise RuntimeError(
                            f"Falha de conectividade com o dispositivo. "
                            f"Detalhe: Jump Host respondeu mas o dispositivo destino não abriu conexao. {_buf}".strip()
                        )
                    # idx 3 = erro de rede do telnet/ssh → conectividade falhou
                    if _probe_idx == 3:
                        _buf = ""
                        try:
                            _buf = ((session.before or "") + " " + str(session.after or "")).strip()
                            _buf = " ".join(str(_buf).split())[:200]
                        except Exception:
                            pass
                        raise RuntimeError(
                            f"Falha de conectividade com o dispositivo. Detalhe: {_buf}"
                        )
                    # idx 0-2 = progresso real detectado; continua normalmente
                except (RuntimeError, pexpect.EOF, pexpect.TIMEOUT) as _pe:
                    raise RuntimeError(str(_pe)) from _pe
            else:
                time.sleep(0.2)
            return session
        except Exception as exc:
            last_error = exc
            try:
                close_pexpect_session(session)
            except Exception:
                pass
            if logger and attempt < shell_retries:
                logger.emit(
                    f"Falha ao abrir shell no Jump Host (tentativa {attempt}/{shell_retries}). Retentando...",
                    "warning",
                )
            if attempt < shell_retries:
                backoff_seconds = min(12.0, 1.5 * (2 ** (attempt - 1)))
                time.sleep(backoff_seconds)
                continue
            raise
    if last_error:
        raise RuntimeError(str(last_error))
    raise RuntimeError("Nao foi possivel abrir shell interativo no Jump Host.")


def close_pexpect_session(session):
    if not session:
        return
    try:
        key_path = getattr(session, "_jump_key_path", None)
        if key_path and os.path.exists(key_path):
            os.remove(key_path)
    except Exception:
        pass


NETMIKO_PAGER_MARKERS = (
    "--more--",
    "---- more ----",
    "[more]",
    "<--- more --->",
    "press any key",
    "(q to quit)",
    "more ( press 'q' to break )",
)
NETMIKO_CONFIRM_YES_MARKERS = (
    "continue? [y/n]",
    "continue? [yes/no]",
    "are you sure",
    "[y/n]:",
    "(y/n)",
    "confirm",
)
NETMIKO_ENTER_MARKERS = (
    "press enter to continue",
    "pressione enter",
    "any key to continue",
    "<cr>",
    "<k>",
)


def _netmiko_tail_text(chunk: str, output: str, limit: int = 320) -> str:
    source = chunk if chunk else output[-limit:]
    return str(source or "")[-limit:]


def netmiko_send_command_interactive(
    conn,
    command: str,
    *,
    read_timeout: int = 300,
    continuation_timeout: int = 30,
    strip_command: bool = False,
    strip_prompt: bool = False,
    max_rounds: int = 300,
):
    """
    Executa comando via Netmiko tratando paginação e prompts interativos simples.
    """
    output = conn.send_command_timing(
        command_string=command,
        read_timeout=read_timeout,
        strip_command=strip_command,
        strip_prompt=strip_prompt,
    )
    last_chunk = output
    safety = 0
    while safety < max_rounds:
        probe_text = _netmiko_tail_text(last_chunk, output).lower()
        reply = None
        if any(marker in probe_text for marker in NETMIKO_PAGER_MARKERS):
            reply = " "
        elif any(marker in probe_text for marker in NETMIKO_CONFIRM_YES_MARKERS):
            reply = "y"
        elif any(marker in probe_text for marker in NETMIKO_ENTER_MARKERS):
            reply = ""
        if reply is None:
            break
        safety += 1
        last_chunk = conn.send_command_timing(
            command_string=reply,
            read_timeout=continuation_timeout,
            strip_command=strip_command,
            strip_prompt=strip_prompt,
        )
        output += last_chunk
    return output


def run_basic_netmiko_backup(
    *,
    ip: str,
    usuario: str,
    porta: int,
    nome_provedor: str,
    nome_tipo_equip: str,
    nome_dispositivo: str,
    parametros: dict = None,
    task_id: str = None,
    backup_base_path: str = None,
    device_type: str,
    collect_command: str,
    file_extension: str = "txt",
    read_timeout: int = 120,
    global_delay_factor: int = 2,
):
    logger = BackupLogger(nome_dispositivo, task_id)
    logger.emit(f"Iniciando backup para {nome_dispositivo} ({nome_tipo_equip})...")

    if not NETMIKO_AVAILABLE or ConnectHandler is None:
        msg = "Falha: Netmiko nao esta disponivel no ambiente."
        logger.emit(msg, "error")
        return (False, msg, None, "CONFIGURACAO")

    parametros = parametros or {}
    password = parametros.get("password")
    if not password:
        msg = "Falha: 'password' e um parametro obrigatorio."
        logger.emit(msg, "error")
        return (False, msg, None, "CONFIGURACAO")

    device_config = {
        "device_type": device_type,
        "host": ip,
        "port": int(porta),
        "username": usuario,
        "password": password,
        "global_delay_factor": global_delay_factor,
    }

    logger.emit("Etapa 1/3: Testando conexao e autenticando...")
    try:
        with ConnectHandler(**device_config):
            logger.emit("Teste de conexao bem-sucedido.", "success")
            logger.emit(f"Etapa 2/3: Executando comando de coleta '{collect_command}'...")
            with ConnectHandler(**device_config) as net_connect:
                output = netmiko_send_command_interactive(
                    net_connect,
                    collect_command,
                    read_timeout=read_timeout,
                    strip_command=False,
                    strip_prompt=False,
                )
            logger.emit("Coleta da configuracao concluida.")

            if not output or len(output.strip()) < 10:
                raise ValueError("O dispositivo nao retornou uma configuracao valida.")

            logger.emit("Etapa 3/3: Salvando arquivo de backup...")
            caminho_local = prepare_backup_path(
                backup_base_path,
                nome_provedor,
                nome_tipo_equip,
                nome_dispositivo,
                file_extension,
            )

            with open(caminho_local, "w", encoding="utf-8") as f:
                f.write(output)

            msg = "Backup concluido com sucesso!"
            logger.emit(msg, "success")
            return (True, msg, caminho_local)
    except Exception as e:
        msg = friendly_unexpected_error(e)
        logger.emit(msg, "error")
        return (False, msg, None, "AUTENTICACAO" if "auth" in str(e).lower() else "SCRIPT")
    try:
        if hasattr(session, "isalive") and session.isalive():
            session.close(force=True)
    except Exception:
        pass


# =============================================================================
# SSH CONNECTION HELPERS WITH JUMP HOST SUPPORT
# =============================================================================

def create_ssh_client(
    host: str,
    port: int = 22,
    username: str = None,
    password: str = None,
    key: str = None,
    jump_host: dict = None,
    timeout: int = 30
):
    """
    Creates an SSH client, optionally via a Jump Host (Bastion).
    
    Args:
        host: Target device IP/hostname
        port: Target device SSH port
        username: Target device username
        password: Target device password
        key: Target device SSH private key (PEM string)
        jump_host: Dict with jump host config: {'host', 'port', 'username', 'password', 'key'}
        timeout: Connection timeout in seconds
    
    Returns:
        paramiko.SSHClient connected to the target
    """
    if not PARAMIKO_AVAILABLE:
        raise ImportError("paramiko is not installed. Run: pip install paramiko")
    
    client = configure_paramiko_host_key_policy(paramiko.SSHClient())
    
    # Prepare key if provided
    pkey = None
    if key:
        pkey = load_private_key(key)
    
    if jump_host and jump_host.get('host'):
        # Connect via Jump Host
        jump_client = configure_paramiko_host_key_policy(paramiko.SSHClient())
        
        # Prepare jump key
        jump_pkey = None
        if jump_host.get('key'):
            jump_pkey = load_private_key(jump_host['key'])
        
        # Connect to Jump Host
        jump_client.connect(
            hostname=jump_host['host'],
            port=jump_host.get('port', 22),
            username=jump_host.get('username'),
            password=jump_host.get('password'),
            pkey=jump_pkey,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False
        )
        
        # Create channel to target through Jump Host
        jump_transport = jump_client.get_transport()
        dest_addr = (host, port)
        local_addr = ('127.0.0.1', 0)
        
        channel = jump_transport.open_channel(
            'direct-tcpip',
            dest_addr,
            local_addr,
            timeout=timeout
        )
        
        # Connect to target via the channel
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            sock=channel,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False
        )
        
        # Store jump_client reference to prevent garbage collection
        client._jump_client = jump_client
    else:
        # Direct connection
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False
        )
    
    return client


def ssh_execute(client, command: str, timeout: int = 60) -> tuple:
    """
    Execute a command on SSH client.
    
    Returns:
        Tuple[str, str, int]: (stdout, stderr, exit_code)
    """
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    return stdout.read().decode('utf-8', errors='ignore'), stderr.read().decode('utf-8', errors='ignore'), exit_code


def close_ssh_client(client):
    """Safely close SSH client and any jump connection."""
    try:
        if hasattr(client, '_jump_client'):
            client._jump_client.close()
    except:
        pass
    try:
        client.close()
    except:
        pass
