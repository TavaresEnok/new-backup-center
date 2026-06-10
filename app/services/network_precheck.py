import base64
import re
import shlex
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from io import StringIO
from typing import Dict, Optional

from app.scripts.backup_scripts.script_helpers import configure_paramiko_host_key_policy

try:
    import paramiko
except Exception:  # pragma: no cover
    paramiko = None

try:
    from cryptography.hazmat.primitives import serialization
except Exception:  # pragma: no cover
    serialization = None


@dataclass
class NetworkPrecheckResult:
    ping_ok: bool
    tcp_ok: bool
    tcp_port: int
    duration_ms: int
    ping_rtt_ms: Optional[float]
    ping_method: str
    tcp_method: str
    message: str


def _wrap_pem(header: str, body: str) -> str:
    compact = "".join((body or "").split())
    chunks = [compact[i : i + 64] for i in range(0, len(compact), 64)]
    return f"-----BEGIN {header}-----\n" + "\n".join(chunks) + f"\n-----END {header}-----\n"


def _normalize_private_key(raw_key: Optional[str]) -> Optional[str]:
    if not raw_key:
        return None
    raw_key = str(raw_key).strip()
    if not raw_key:
        return None
    if "BEGIN " in raw_key:
        return raw_key

    compact = "".join(raw_key.split())
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


def _load_private_key(raw_key: Optional[str]):
    if paramiko is None:
        return None
    normalized = _normalize_private_key(raw_key)
    if not normalized:
        return None
    for cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey):
        try:
            return cls.from_private_key(StringIO(normalized))
        except Exception:
            continue
    return None


def _probe_ping(host: str, timeout_seconds: int) -> tuple[bool, Optional[float], str]:
    timeout_ms = max(100, int(timeout_seconds * 1000))
    fping_bin = shutil.which("fping")
    if fping_bin:
        # Exemplo esperado: "<host> : 12.3"
        cmd = [fping_bin, "-c", "1", "-t", str(timeout_ms), host]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1, timeout_seconds + 1))
        output = f"{proc.stdout}\n{proc.stderr}".strip()
        if proc.returncode == 0:
            match = re.search(r":\s*([0-9]+(?:\.[0-9]+)?)", output)
            rtt = float(match.group(1)) if match else None
            return True, rtt, "fping"
        return False, None, "fping"

    ping_bin = shutil.which("ping")
    if ping_bin:
        cmd = [ping_bin, "-c", "1", "-W", str(max(1, timeout_seconds)), host]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1, timeout_seconds + 1))
        output = f"{proc.stdout}\n{proc.stderr}".strip()
        if proc.returncode == 0:
            match = re.search(r"time=([0-9]+(?:\.[0-9]+)?)", output)
            rtt = float(match.group(1)) if match else None
            return True, rtt, "ping"
        return False, None, "ping"

    return False, None, "none"


def _probe_tcp_direct(host: str, port: int, timeout_seconds: int) -> tuple[bool, str]:
    tcpping_bin = shutil.which("tcpping")
    if tcpping_bin:
        proc = subprocess.run(
            [tcpping_bin, "-c", "1", "-x", str(max(1, timeout_seconds * 1000)), host, str(port)],
            capture_output=True,
            text=True,
            timeout=max(1, timeout_seconds + 1),
        )
        return proc.returncode == 0, "tcpping"

    nc_bin = shutil.which("nc")
    if nc_bin:
        proc = subprocess.run(
            [nc_bin, "-z", "-w", str(max(1, timeout_seconds)), host, str(port)],
            capture_output=True,
            text=True,
            timeout=max(1, timeout_seconds + 1),
        )
        return proc.returncode == 0, "nc"

    try:
        sock = socket.create_connection((host, int(port)), timeout=max(1, timeout_seconds))
        sock.close()
        return True, "socket"
    except Exception:
        return False, "socket"


def _is_safe_shell_host(host: str) -> bool:
    value = str(host or "").strip()
    if not value:
        return False
    return bool(re.match(r"^[A-Za-z0-9._:-]+$", value))


def _exec_jump_probe_command(client, command: str, timeout_seconds: int) -> bool:
    """
    Runs a command on jump host with hard timeout on channel wait.
    Avoids blocking forever in recv_exit_status when remote probe hangs.
    """
    try:
        _, stdout, _ = client.exec_command(command, timeout=max(2, int(timeout_seconds)))
        channel = stdout.channel
    except Exception:
        return False

    deadline = time.monotonic() + max(2, int(timeout_seconds))
    try:
        while time.monotonic() < deadline:
            if channel.exit_status_ready():
                return int(channel.recv_exit_status()) == 0
            time.sleep(0.1)
        return False
    except Exception:
        return False
    finally:
        try:
            channel.close()
        except Exception:
            pass


def _probe_tcp_via_jump_exec(client, host: str, port: int, timeout_seconds: int) -> tuple[bool, str]:
    """
    Fallback when SSH direct-tcpip is blocked by jump host policy (AllowTcpForwarding=no).
    Executes a cheap TCP probe from the jump host shell itself.
    """
    host_text = str(host or "").strip()
    if not host_text:
        return False, "jump_exec"
    try:
        port_int = int(port)
    except Exception:
        return False, "jump_exec"
    timeout_value = max(1, int(timeout_seconds))
    exec_timeout = max(2, timeout_value + 2)
    host_quoted = shlex.quote(host_text)

    probes: list[tuple[str, str]] = [
        (
            "jump_exec:nc",
            f"sh -lc \"command -v nc >/dev/null 2>&1 && nc -z -w {timeout_value} {host_quoted} {port_int} >/dev/null 2>&1\"",
        ),
    ]

    # /dev/tcp works only with safe host token and bash available
    if _is_safe_shell_host(host_text):
        probes.append(
            (
                "jump_exec:bash_tcp",
                (
                    "sh -lc "
                    f"\"command -v bash >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1 "
                    f"&& timeout {timeout_value} bash -lc '</dev/tcp/{host_text}/{port_int}' >/dev/null 2>&1\""
                ),
            )
        )
        probes.append(
            (
                "jump_exec:telnet",
                (
                    "sh -lc "
                    f"\"command -v telnet >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1 "
                    f"&& timeout {timeout_value} sh -lc 'echo quit | telnet {host_text} {port_int} >/dev/null 2>&1'\""
                ),
            )
        )

    for method, command in probes:
        if _exec_jump_probe_command(client, command, exec_timeout):
            return True, method
    return False, "jump_exec"


def _open_jump_client(jump_host: Dict[str, str], timeout_seconds: int):
    if paramiko is None:
        raise RuntimeError("paramiko indisponivel para precheck via jump host")
    pkey = _load_private_key(jump_host.get("key"))
    client = configure_paramiko_host_key_policy(paramiko.SSHClient())
    client.connect(
        hostname=str(jump_host.get("host") or ""),
        port=int(jump_host.get("port") or 22),
        username=str(jump_host.get("username") or ""),
        password=jump_host.get("password"),
        pkey=pkey,
        timeout=max(1, timeout_seconds),
        auth_timeout=max(1, timeout_seconds),
        banner_timeout=max(1, timeout_seconds),
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def _probe_tcp_via_jump(host: str, port: int, timeout_seconds: int, jump_host: Dict[str, str]) -> tuple[bool, str]:
    client = _open_jump_client(jump_host, timeout_seconds)
    channel = None
    try:
        transport = client.get_transport()
        if not transport or not transport.is_active():
            return False, "jump_channel"
        channel = transport.open_channel(
            "direct-tcpip",
            (host, int(port)),
            ("127.0.0.1", 0),
            timeout=float(max(1, timeout_seconds)),
        )
        return True, "jump_channel"
    except Exception:
        # Common in hardened bastions: SSH shell works, but direct-tcpip is denied.
        ok_exec, method_exec = _probe_tcp_via_jump_exec(client, host, int(port), timeout_seconds)
        if ok_exec:
            return True, method_exec
        return False, "jump_channel"
    finally:
        try:
            if channel is not None:
                channel.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass


def run_network_precheck(
    host: str,
    port: int,
    timeout_seconds: int = 3,
    jump_host: Optional[Dict[str, str]] = None,
) -> NetworkPrecheckResult:
    started = time.monotonic()
    host = str(host or "").strip()
    tcp_port = int(port or 22)
    timeout_seconds = max(1, int(timeout_seconds or 3))

    jump_host_cfg = jump_host if isinstance(jump_host, dict) and jump_host.get("host") else None
    if jump_host_cfg:
        # Em cenarios com Jump Host, o ping direto do worker para o alvo costuma ser
        # irrelevante (alvo privado/atrás de VPN) e adiciona latencia desnecessaria.
        # O sinal decisivo para fail-fast e o teste TCP via jump.
        ping_ok, ping_rtt, ping_method = False, None, "skipped_jump"
        tcp_ok, tcp_method = _probe_tcp_via_jump(host, tcp_port, timeout_seconds, jump_host_cfg)
    else:
        ping_ok, ping_rtt, ping_method = _probe_ping(host, timeout_seconds)
        tcp_ok, tcp_method = _probe_tcp_direct(host, tcp_port, timeout_seconds)

    duration_ms = int((time.monotonic() - started) * 1000)
    if ping_ok and tcp_ok:
        msg = "ping e tcp ok"
    elif tcp_ok:
        msg = "ping sem resposta, tcp ok"
    elif ping_ok:
        msg = "ping ok, tcp falhou"
    else:
        msg = "ping e tcp falharam"

    return NetworkPrecheckResult(
        ping_ok=bool(ping_ok),
        tcp_ok=bool(tcp_ok),
        tcp_port=tcp_port,
        duration_ms=duration_ms,
        ping_rtt_ms=ping_rtt,
        ping_method=ping_method,
        tcp_method=tcp_method,
        message=msg,
    )
