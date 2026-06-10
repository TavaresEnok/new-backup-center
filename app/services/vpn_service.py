import fcntl
import os
import shutil
import subprocess
import time
from contextlib import contextmanager
from typing import Optional

from app.core.security import decrypt_password


class VpnError(RuntimeError):
    pass


def _truthy_env(name: str, default: str = "0") -> bool:
    return str(os.getenv(name, default) or "").strip().lower() in {"1", "true", "on", "yes"}


def _nm_escape(value: str) -> str:
    """Escapa valores para a sintaxe 'key=value,key=value' do nmcli (vpn.data/vpn.secrets).

    Senhas/credenciais VPN com virgula (',') ou barra invertida ('\\') quebravam o parsing
    do nmcli — o valor era truncado na virgula e a autenticacao VPN falhava de forma
    intermitente e dificil de diagnosticar. O nmcli usa '\\' como caractere de escape.

    NO-OP para valores sem ',' ou '\\' (a grande maioria das senhas) — portanto nao altera
    o comportamento de conexoes VPN que ja funcionam hoje.
    """
    text = str(value or "")
    return text.replace("\\", "\\\\").replace(",", "\\,")


class VpnService:
    LOCK_FILE = os.getenv("VPN_LOCK_FILE", "/app/storage/vpn_global.lock")
    GROUP_LOCK_DIR = os.getenv("VPN_GROUP_LOCK_DIR", "/app/storage/vpn_group_locks")
    SETTLE_SECONDS = int(os.getenv("VPN_SETTLE_SECONDS", "8"))
    LOCK_TIMEOUT_SECONDS = max(60, int(os.getenv("VPN_GLOBAL_LOCK_TIMEOUT_SECONDS", "3600") or 3600))
    GROUP_LOCK_TIMEOUT_SECONDS = max(60, int(os.getenv("VPN_GROUP_LOCK_TIMEOUT_SECONDS", os.getenv("VPN_GLOBAL_LOCK_TIMEOUT_SECONDS", "3600")) or 3600))
    NMCLI_BACKEND_RECHECK_SECONDS = max(10, int(os.getenv("VPN_NMCLI_BACKEND_RECHECK_SECONDS", "60") or 60))
    CONNECT_RETRIES = max(1, int(os.getenv("VPN_CONNECT_RETRIES", "3") or 3))
    CONNECT_RETRY_BACKOFF_SECONDS = max(1, int(os.getenv("VPN_CONNECT_RETRY_BACKOFF_SECONDS", "8") or 8))
    RESET_BACKEND_ON_CONNECT_FAILURE = _truthy_env("VPN_RESET_BACKEND_ON_CONNECT_FAILURE", "1")
    RESTART_NETWORKMANAGER_ON_CONNECT_FAILURE = _truthy_env("VPN_RESTART_NETWORKMANAGER_ON_CONNECT_FAILURE", "0")
    RECYCLE_WORKER_AFTER_CONNECT_FAILURE = _truthy_env("VPN_RECYCLE_WORKER_AFTER_CONNECT_FAILURE", "0")
    WORKER_RECYCLE_DELAY_SECONDS = max(3, int(os.getenv("VPN_WORKER_RECYCLE_DELAY_SECONDS", "10") or 10))

    _nmcli_unavailable_until = 0.0
    _nmcli_unavailable_reason = ""

    def _log(self, logger, level: str, message: str):
        if logger and hasattr(logger, level):
            getattr(logger, level)(message)

    def _run_nmcli(self, args, timeout: int = 60, check: bool = True):
        result = subprocess.run(
            ["nmcli", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if check and result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            details = stderr or stdout or f"code={result.returncode}"
            raise VpnError(f"nmcli {' '.join(args)} falhou: {details}")
        return result

    def _connection_name(self, group_id) -> str:
        key = str(group_id).replace("-", "")[:12]
        return f"group_vpn_{key}"

    @staticmethod
    def _is_source_connection_error(message: str) -> bool:
        normalized = str(message or "").strip().lower()
        return "could not find source connection" in normalized

    @classmethod
    def _should_retry_activation_with_eth0(cls, message: str) -> bool:
        normalized = str(message or "").strip().lower()
        if cls._is_source_connection_error(normalized):
            return True
        if "connection activation failed" not in normalized:
            return False
        return (
            "unknown reason" in normalized
            or "nm_device=eth0" in normalized
            or "device=eth0" in normalized
        )

    @classmethod
    def _should_retry_vpn_connect_error(cls, message: str) -> bool:
        normalized = str(message or "").strip().lower()
        if not normalized:
            return False
        hard_markers = (
            "no valid secrets",
            "faltam dados",
            "missing vpn",
            "invalid password",
            "authentication failed",
        )
        if any(marker in normalized for marker in hard_markers):
            return False
        return (
            cls._is_source_connection_error(normalized)
            or "connection activation failed" in normalized
            or "vpn service stopped unexpectedly" in normalized
            or "unknown reason" in normalized
            or "timeout expired" in normalized
            or "nm_device=eth0" in normalized
            or "device=eth0" in normalized
        )

    def _retry_connection_up_on_eth0(self, conn_name: str, logger=None):
        self._log(
            logger,
            "warning",
            (
                "Falha ao subir VPN pela origem escolhida pelo NetworkManager; "
                "reativando 'container-eth0' e tentando novamente com ifname=eth0."
            ),
        )
        self._run_nmcli(["connection", "up", "container-eth0"], check=False)
        self._run_nmcli(["connection", "up", conn_name, "ifname", "eth0"], timeout=90)

    def _group_has_vpn_credentials(self, group) -> bool:
        if not group:
            return False
        vpn_server = str(getattr(group, "vpn_server", "") or "").strip()
        vpn_username = str(getattr(group, "vpn_username", "") or "").strip()
        return bool(vpn_server and vpn_username and getattr(group, "vpn_password_encrypted", None))

    def _ensure_nmcli(self):
        if shutil.which("nmcli") is None:
            raise VpnError("nmcli não encontrado. VPN por L2TP/IPsec indisponível neste worker.")
        now = time.time()
        if now < float(self._nmcli_unavailable_until or 0.0):
            reason = self._nmcli_unavailable_reason or "backend do NetworkManager indisponível."
            raise VpnError(reason)
        try:
            result = self._run_nmcli(
                ["--terse", "--fields", "RUNNING", "general", "status"],
                timeout=10,
                check=False,
            )
            output = ((result.stdout or "") + " " + (result.stderr or "")).strip().lower()
            if result.returncode != 0 or "running" not in output:
                details = output or f"code={result.returncode}"
                reason = (
                    "NetworkManager indisponível neste worker para VPN L2TP/IPsec "
                    f"(nmcli general status: {details})."
                )
                self._nmcli_unavailable_reason = reason
                self._nmcli_unavailable_until = now + float(self.NMCLI_BACKEND_RECHECK_SECONDS)
                raise VpnError(reason)
            self._nmcli_unavailable_until = 0.0
            self._nmcli_unavailable_reason = ""
        except VpnError:
            raise
        except Exception as exc:
            reason = f"Falha ao validar backend de VPN no worker: {exc}"
            self._nmcli_unavailable_reason = reason
            self._nmcli_unavailable_until = now + float(self.NMCLI_BACKEND_RECHECK_SECONDS)
            raise VpnError(reason)

    def ensure_worker_ready(self):
        """Falha rapido quando uma task VPN cai em worker sem backend VPN funcional."""
        self._ensure_nmcli()

    def _cleanup_active_vpns(self, keep_connection_name: str, logger=None):
        result = self._run_nmcli(["--terse", "--fields", "NAME,TYPE,STATE", "con", "show", "--active"], check=False)
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.rsplit(":", 2)
            if len(parts) != 3:
                continue
            name, conn_type, state = parts
            if conn_type == "vpn" and state == "activated" and name != keep_connection_name:
                self._log(logger, "warning", f"Desconectando VPN ativa anterior: {name}")
                self._run_nmcli(["connection", "down", name], check=False)
                self._run_nmcli(["connection", "delete", name], check=False)

    def _cleanup_vpn_profiles(self, keep_connection_name: Optional[str] = None, logger=None):
        # Limpa VPNs ativas primeiro.
        self._cleanup_active_vpns(keep_connection_name or "", logger=logger)

        # Limpa perfis VPN residuais (mesmo inativos) para evitar estado pendente entre provedores.
        result = self._run_nmcli(["--terse", "--fields", "NAME,TYPE", "con", "show"], check=False)
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.rsplit(":", 1)
            if len(parts) != 2:
                continue
            name, conn_type = parts
            if conn_type != "vpn":
                continue
            if keep_connection_name and name == keep_connection_name:
                continue
            self._run_nmcli(["connection", "down", name], check=False)
            self._run_nmcli(["connection", "delete", name], check=False)

    def _wait_for_vpn_quiescent(self, timeout_seconds: int = 20):
        started = time.time()
        while time.time() - started < timeout_seconds:
            result = self._run_nmcli(
                ["--terse", "--fields", "NAME,TYPE,STATE", "con", "show", "--active"],
                check=False,
            )
            active_vpns = 0
            for line in (result.stdout or "").splitlines():
                parts = line.rsplit(":", 2)
                if len(parts) != 3:
                    continue
                _name, conn_type, state = parts
                if conn_type == "vpn" and state == "activated":
                    active_vpns += 1
            if active_vpns == 0:
                return
            time.sleep(1)

    def _detect_eth0_network(self) -> tuple[str, str]:
        addr_result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", "eth0"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        eth0_addr = ""
        if addr_result.returncode == 0 and addr_result.stdout.strip():
            parts = addr_result.stdout.split()
            if len(parts) >= 4:
                eth0_addr = parts[3]

        route_result = subprocess.run(
            ["ip", "route", "show", "default", "0.0.0.0/0", "dev", "eth0"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        route_text = (route_result.stdout or "").strip()
        if not route_text:
            route_result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            route_text = (route_result.stdout or "").strip()
        route_parts = route_text.split()
        eth0_gateway = ""
        if "via" in route_parts:
            via_index = route_parts.index("via")
            if via_index + 1 < len(route_parts):
                eth0_gateway = route_parts[via_index + 1]

        if not eth0_addr or not eth0_gateway:
            raise VpnError("Nao foi possivel detectar IP/gateway da eth0 no worker VPN.")
        return eth0_addr, eth0_gateway

    def _restore_container_eth0_connection(self, logger=None):
        eth0_addr, eth0_gateway = self._detect_eth0_network()
        self._run_nmcli(["device", "set", "eth0", "managed", "yes"], timeout=10, check=False)
        for name in ("container-eth0", "eth0", "Wired connection 1"):
            self._run_nmcli(["connection", "down", name], timeout=10, check=False)
            self._run_nmcli(["connection", "delete", name], timeout=10, check=False)
        self._run_nmcli(
            [
                "connection",
                "add",
                "type",
                "ethernet",
                "con-name",
                "container-eth0",
                "ifname",
                "eth0",
                "ipv4.method",
                "manual",
                "ipv4.addresses",
                eth0_addr,
                "ipv4.gateway",
                eth0_gateway,
                "ipv4.dns",
                "127.0.0.11",
                "ipv4.never-default",
                "no",
                "ipv6.method",
                "ignore",
            ],
            timeout=20,
            check=False,
        )
        self._run_nmcli(["connection", "up", "container-eth0"], timeout=30, check=False)
        self._log(logger, "info", "Conexao container-eth0 restaurada no worker VPN.")

    def _restart_network_manager(self, logger=None):
        if not self.RESTART_NETWORKMANAGER_ON_CONNECT_FAILURE or not shutil.which("NetworkManager"):
            return
        self._log(logger, "warning", "Reiniciando NetworkManager do worker VPN isolado.")
        subprocess.run(["pkill", "-TERM", "-x", "NetworkManager"], capture_output=True, text=True, timeout=5, check=False)
        time.sleep(2)
        subprocess.run(["pkill", "-KILL", "-x", "NetworkManager"], capture_output=True, text=True, timeout=5, check=False)
        try:
            os.remove("/run/NetworkManager/NetworkManager.pid")
        except FileNotFoundError:
            pass
        except Exception:
            pass
        subprocess.Popen(
            ["NetworkManager", "--no-daemon"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.time() + 30
        while time.time() < deadline:
            result = self._run_nmcli(["--terse", "--fields", "RUNNING", "general", "status"], timeout=5, check=False)
            if result.returncode == 0 and "running" in (result.stdout or "").lower():
                self._restore_container_eth0_connection(logger=logger)
                return
            time.sleep(1)
        raise VpnError("NetworkManager nao voltou a ficar pronto apos reset do worker VPN.")

    def _reset_vpn_backend_after_failure(self, logger=None):
        if not self.RESET_BACKEND_ON_CONNECT_FAILURE:
            return
        self._log(
            logger,
            "warning",
            "Resetando backend VPN do worker apos falha de ativacao (L2TP/IPsec/PPP).",
        )
        try:
            self._cleanup_vpn_profiles(None, logger=logger)
        except Exception:
            pass
        for pattern in ("nm-l2tp-service", "xl2tpd", "pppd", "charon", "starter"):
            try:
                subprocess.run(
                    ["pkill", "-f", pattern],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
            except Exception:
                pass
        time.sleep(2)
        try:
            if self.RESTART_NETWORKMANAGER_ON_CONNECT_FAILURE and _truthy_env("VPN_ISOLATED_WORKER", "0"):
                self._restart_network_manager(logger=logger)
            else:
                self._run_nmcli(["connection", "up", "container-eth0"], timeout=20, check=False)
                self._run_nmcli(["device", "reapply", "eth0"], timeout=10, check=False)
        except Exception:
            pass
        try:
            self._wait_for_vpn_quiescent(timeout_seconds=20)
        except Exception:
            pass

    def _recycle_worker_after_failure(self, logger=None, reason: str = ""):
        if not (
            self.RECYCLE_WORKER_AFTER_CONNECT_FAILURE
            and _truthy_env("VPN_ISOLATED_WORKER", "0")
        ):
            return
        parent_pid = os.getppid()
        if parent_pid <= 0:
            return
        delay = int(self.WORKER_RECYCLE_DELAY_SECONDS)
        self._log(
            logger,
            "warning",
            (
                "Reciclando container do worker VPN apos falha de ativacao "
                f"(pid alvo {parent_pid}, delay {delay}s). Motivo: {reason}"
            ),
        )
        try:
            subprocess.Popen(
                ["sh", "-c", f"sleep {delay}; kill -TERM {parent_pid} >/dev/null 2>&1 || true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except Exception:
            pass

    def connect_group_vpn(self, group, logger=None):
        self._ensure_nmcli()
        if not group:
            return None
        if not bool(getattr(group, "uses_vpn", False)) and not self._group_has_vpn_credentials(group):
            return None

        vpn_server = (group.vpn_server or "").strip()
        vpn_user = (group.vpn_username or "").strip()
        vpn_pass = decrypt_password(group.vpn_password_encrypted) if group.vpn_password_encrypted else ""
        vpn_ipsec = decrypt_password(group.vpn_ipsec_secret_encrypted) if group.vpn_ipsec_secret_encrypted else ""

        if not vpn_server or not vpn_user or not vpn_pass:
            raise VpnError(
                f"Grupo '{group.name}' está com VPN ativa, mas faltam dados (server/user/password)."
            )

        conn_name = self._connection_name(group.id)
        self._log(logger, "info", f"Conectando VPN do grupo '{group.name}' ({conn_name})...")

        # Limpa outras VPNs e perfis residuais para evitar conflito de rotas/estado.
        self._cleanup_vpn_profiles(conn_name, logger=logger)
        self._wait_for_vpn_quiescent(timeout_seconds=20)
        time.sleep(2)

        # Remove conexão residual com o mesmo nome
        self._run_nmcli(["connection", "down", conn_name], check=False)
        self._run_nmcli(["connection", "delete", conn_name], check=False)

        # Escapa virgula/barra para nao quebrar o parsing key=value,key=value do nmcli.
        vpn_data = f"gateway={_nm_escape(vpn_server)},user={_nm_escape(vpn_user)}"
        secrets = f"password-flags=0,password={_nm_escape(vpn_pass)}"
        if vpn_ipsec:
            vpn_data += ",ipsec-enabled=yes"
            secrets += f",ipsec-psk-flags=0,ipsec-psk={_nm_escape(vpn_ipsec)}"
        def _emit_nm_diagnostics():
            try:
                dev_status = self._run_nmcli(["device", "status"], check=False)
                self._log(
                    logger,
                    "warning",
                    "Diagnostico NM (device status): "
                    + ((dev_status.stdout or dev_status.stderr or "").strip() or "sem saida"),
                )
            except Exception:
                pass
            try:
                active_conns = self._run_nmcli(
                    ["--terse", "--fields", "NAME,TYPE,DEVICE,STATE", "con", "show", "--active"],
                    check=False,
                )
                self._log(
                    logger,
                    "warning",
                    "Diagnostico NM (active conns): "
                    + ((active_conns.stdout or active_conns.stderr or "").strip() or "sem saida"),
                )
            except Exception:
                pass

        last_exc = None
        try:
            for attempt_vpn_data in [vpn_data]:
                self._run_nmcli(["connection", "down", conn_name], check=False)
                self._run_nmcli(["connection", "delete", conn_name], check=False)
                self._run_nmcli(
                    [
                        "connection",
                        "add",
                        "type",
                        "vpn",
                        "con-name",
                        conn_name,
                        "vpn-type",
                        "l2tp",
                        "vpn.data",
                        attempt_vpn_data,
                        "vpn.secrets",
                        secrets,
                    ]
                )
                try:
                    self._run_nmcli(["connection", "up", conn_name], timeout=90)
                    last_exc = None
                    break
                except VpnError as first_exc:
                    if self._should_retry_activation_with_eth0(str(first_exc)):
                        _emit_nm_diagnostics()
                        self._retry_connection_up_on_eth0(conn_name, logger=logger)
                        last_exc = None
                        break
                    last_exc = first_exc
            if last_exc:
                raise last_exc
        except Exception:
            # Em falhas de conexão, forçamos limpeza para evitar contaminar o próximo grupo.
            _emit_nm_diagnostics()
            self._cleanup_vpn_profiles(None, logger=logger)
            self._wait_for_vpn_quiescent(timeout_seconds=20)
            raise
        self._log(logger, "success", f"VPN conectada para o grupo '{group.name}'.")
        return conn_name

    def disconnect_group_vpn(self, group, logger=None):
        if not group:
            return
        if not bool(getattr(group, "uses_vpn", False)) and not self._group_has_vpn_credentials(group):
            return
        conn_name = self._connection_name(group.id)
        self._log(logger, "info", f"Desconectando VPN do grupo '{group.name}' ({conn_name})...")
        self._run_nmcli(["connection", "down", conn_name], check=False)
        self._run_nmcli(["connection", "delete", conn_name], check=False)
        self._cleanup_vpn_profiles(None, logger=logger)
        self._wait_for_vpn_quiescent(timeout_seconds=20)
        if self.SETTLE_SECONDS > 0:
            self._log(logger, "info", f"Aguardando estabilização de VPN ({self.SETTLE_SECONDS}s)...")
            time.sleep(self.SETTLE_SECONDS)

    def acquire_lock(self, timeout_seconds: int | None = None):
        timeout_seconds = max(60, int(timeout_seconds or self.LOCK_TIMEOUT_SECONDS))
        os.makedirs(os.path.dirname(self.LOCK_FILE), exist_ok=True)
        lock_handle = open(self.LOCK_FILE, "w", encoding="utf-8")
        return self._acquire_file_lock(lock_handle, timeout_seconds, "global de VPN")

    def acquire_group_lock(self, group, timeout_seconds: int | None = None):
        group_id = str(getattr(group, "id", "") or "").strip()
        if not group_id:
            raise VpnError("Grupo VPN sem identificador para lock.")
        safe_group_id = "".join(ch for ch in group_id if ch.isalnum() or ch in {"-", "_"})
        timeout_seconds = max(60, int(timeout_seconds or self.GROUP_LOCK_TIMEOUT_SECONDS))
        os.makedirs(self.GROUP_LOCK_DIR, exist_ok=True)
        lock_path = os.path.join(self.GROUP_LOCK_DIR, f"{safe_group_id}.lock")
        lock_handle = open(lock_path, "w", encoding="utf-8")
        return self._acquire_file_lock(lock_handle, timeout_seconds, f"do grupo VPN {group_id}")

    def _acquire_file_lock(self, lock_handle, timeout_seconds: int, label: str):
        start = time.time()
        while True:
            try:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                lock_handle.write(str(os.getpid()))
                lock_handle.flush()
                return lock_handle
            except BlockingIOError:
                if (time.time() - start) >= timeout_seconds:
                    lock_handle.close()
                    raise VpnError(f"Timeout aguardando lock {label}.")
                time.sleep(1)

    @staticmethod
    def release_lock(lock_handle):
        if not lock_handle:
            return
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        finally:
            lock_handle.close()

    @contextmanager
    def vpn_session(self, group, logger=None, timeout_seconds: int | None = None):
        lock_handle = None
        group_lock_handle = None
        connected = False
        try:
            group_lock_handle = self.acquire_group_lock(group, timeout_seconds=timeout_seconds)
            if not _truthy_env("VPN_ISOLATED_WORKER", "0"):
                lock_handle = self.acquire_lock(timeout_seconds=timeout_seconds)
            last_exc = None
            for attempt in range(1, self.CONNECT_RETRIES + 1):
                try:
                    self.connect_group_vpn(group, logger=logger)
                    connected = True
                    last_exc = None
                    break
                except VpnError as exc:
                    last_exc = exc
                    if attempt >= self.CONNECT_RETRIES or not self._should_retry_vpn_connect_error(str(exc)):
                        self._reset_vpn_backend_after_failure(logger=logger)
                        self._recycle_worker_after_failure(logger=logger, reason=str(exc)[:240])
                        raise
                    wait_seconds = self.CONNECT_RETRY_BACKOFF_SECONDS * attempt
                    self._log(
                        logger,
                        "warning",
                        (
                            f"Falha transitoria ao conectar VPN (tentativa {attempt}/{self.CONNECT_RETRIES}): {exc}. "
                            f"Limpando estado e retentando em {wait_seconds}s."
                        ),
                    )
                    try:
                        self._reset_vpn_backend_after_failure(logger=logger)
                    except Exception:
                        pass
                    time.sleep(wait_seconds)
            if last_exc:
                raise last_exc
            yield
        finally:
            try:
                if connected:
                    self.disconnect_group_vpn(group, logger=logger)
                else:
                    try:
                        self._cleanup_vpn_profiles(None, logger=logger)
                    except Exception:
                        pass
            finally:
                self.release_lock(lock_handle)
                self.release_lock(group_lock_handle)


vpn_service = VpnService()
