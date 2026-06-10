import base64
import socket
import time
from dataclasses import dataclass
from io import StringIO
from typing import Any, Dict, Optional, List, Tuple

import paramiko
import pexpect
import requests

from app.core.security import decrypt_password
from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.services.backup_executor import BackupLogger
from app.services.connection_mode import uses_jump_host, uses_vpn_tunnel
from app.services.vpn_service import VpnError, vpn_service
from app.scripts.backup_scripts.script_helpers import (
    configure_paramiko_host_key_policy,
    ssh_strict_host_key_checking_enabled,
)

try:
    from netmiko import ConnectHandler
except Exception:  # pragma: no cover
    ConnectHandler = None

try:
    from cryptography.hazmat.primitives import serialization
except Exception:  # pragma: no cover
    serialization = None


@dataclass
class ConnectionTestResult:
    success: bool
    message: str
    protocol: str
    elapsed_ms: int
    tcp_ok: bool = False


class ConnectionTestService:
    DEFAULT_TIMEOUT = 8

    def _message_has_auth_failure(self, message: str) -> bool:
        text = str(message or "").strip().lower()
        return any(token in text for token in [
            "auth",
            "authentication",
            "permission denied",
            "access denied",
            "invalid credentials",
            "login failed",
            "senha",
            "password",
            "credencia",
        ])

    def _message_has_timeout(self, message: str) -> bool:
        text = str(message or "").strip().lower()
        return any(token in text for token in ["timeout", "timed out", "banner", "timeoutexception"])

    def _message_has_route_failure(self, message: str) -> bool:
        text = str(message or "").strip().lower()
        return any(token in text for token in [
            "no route to host",
            "network is unreachable",
            "host unreachable",
            "connection refused",
            "unable to connect",
            "tcp",
            "port",
            "refused",
            "unreachable",
        ])

    def _append_step(self, steps: List[Dict[str, Any]], key: str, title: str, status: str, message: str) -> None:
        steps.append(
            {
                "key": key,
                "title": title,
                "status": status,
                "message": str(message or "").strip(),
            }
        )

    def _script_name(self, device: Device) -> str:
        return str(getattr(getattr(device, "type", None), "script_name", "") or "").strip().lower()

    def _recommended_timeout(self, device: Device, group: Optional[DeviceGroup] = None) -> int:
        script_name = self._script_name(device)

        if script_name == "huawei_ne_router_netmiko.py":
            base = 60
        elif script_name == "Zabbix_backup.py".lower():
            base = 35
        elif script_name == "mikrotik_ros_netmiko.py":
            base = 25
        elif script_name == "grafana_backup.py":
            base = 20
        elif "switch_huawei" in script_name:
            base = 15
        else:
            base = self.DEFAULT_TIMEOUT

        if group and uses_jump_host(group, device=device):
            base = max(base, 15)
        if device.use_telnet:
            base = max(base, 12)
        return int(base)

    def _test_grafana_api(self, device: Device, timeout: int) -> Tuple[bool, str]:
        params = dict(getattr(device, "extra_parameters", None) or {})
        grafana_url = str(params.get("grafana_url") or "").strip().rstrip("/")
        api_key = str(params.get("api_key") or "").strip()
        if not grafana_url or not api_key:
            return False, "Parametros do Grafana ausentes (grafana_url/api_key)."

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        response = requests.get(f"{grafana_url}/api/org", headers=headers, timeout=max(timeout, 20))
        response.raise_for_status()
        org_name = ""
        try:
            org_name = str((response.json() or {}).get("name") or "").strip()
        except Exception:
            org_name = ""
        if org_name:
            return True, f"Conexao validada com sucesso (Grafana API: {org_name})."
        return True, "Conexao validada com sucesso (Grafana API)."

    @staticmethod
    def _wrap_pem(header: str, body: str) -> str:
        body = "".join((body or "").split())
        chunks = [body[i : i + 64] for i in range(0, len(body), 64)]
        return f"-----BEGIN {header}-----\n" + "\n".join(chunks) + f"\n-----END {header}-----\n"

    def _normalize_private_key(self, raw_key: Optional[str]) -> Optional[str]:
        if not raw_key:
            return None

        raw_key = str(raw_key).strip()
        if "BEGIN " in raw_key:
            return raw_key

        compact = "".join(raw_key.split())
        if not compact:
            return None

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

        return self._wrap_pem("PRIVATE KEY", compact)

    def _load_private_key(self, raw_key: Optional[str]):
        normalized = self._normalize_private_key(raw_key)
        if not normalized:
            return None
        for cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey):
            try:
                return cls.from_private_key(StringIO(normalized))
            except Exception:
                continue
        return None

    def _build_jump_host_config(self, group: Optional[DeviceGroup], device: Optional[Device] = None) -> Optional[dict]:
        if not group or not uses_jump_host(group, device=device) or not getattr(group, "jump_host", None):
            return None
        if not getattr(group, "jump_username", None):
            return None

        jump_password = None
        jump_key = None
        if getattr(group, "jump_password_encrypted", None):
            jump_password = decrypt_password(group.jump_password_encrypted)
        if getattr(group, "jump_key_encrypted", None):
            jump_key = decrypt_password(group.jump_key_encrypted)
        if not jump_password and not jump_key:
            return None

        return {
            "host": str(group.jump_host or "").strip(),
            "port": int(group.jump_port or 22),
            "username": str(group.jump_username or "").strip(),
            "password": jump_password,
            "key": jump_key,
        }

    def _should_bypass_jump_host(self, device: Device, jump_host: Optional[dict]) -> bool:
        if not jump_host:
            return False
        target_host = str(getattr(device, "ip_address", "") or "").strip().lower()
        jump_host_name = str(jump_host.get("host") or "").strip().lower()
        return bool(target_host and jump_host_name and target_host == jump_host_name)

    def _open_jump_client(self, jump_host: dict, timeout: int) -> paramiko.SSHClient:
        jump_pkey = self._load_private_key(jump_host.get("key"))
        client = configure_paramiko_host_key_policy(paramiko.SSHClient())
        client.connect(
            hostname=jump_host["host"],
            port=int(jump_host.get("port") or 22),
            username=jump_host.get("username"),
            password=jump_host.get("password"),
            pkey=jump_pkey,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        return client

    def _open_jump_channel(self, jump_client: paramiko.SSHClient, host: str, port: int, timeout: int):
        transport = jump_client.get_transport()
        if not transport or not transport.is_active():
            raise RuntimeError("Transporte SSH do Jump Host indisponivel.")

        return transport.open_channel(
            "direct-tcpip",
            (host, int(port)),
            ("127.0.0.1", 0),
            timeout=float(timeout),
        )

    def _test_tcp_port(self, host: str, port: int, timeout: int, jump_host: Optional[dict] = None) -> None:
        # Normaliza host (strip) — espacos acidentais no cadastro davam falso "no_ping"/"down".
        host = str(host or "").strip()
        if jump_host:
            jump_client = self._open_jump_client(jump_host, timeout)
            channel = None
            try:
                channel = self._open_jump_channel(jump_client, host, port, timeout)
            finally:
                try:
                    if channel is not None:
                        channel.close()
                finally:
                    jump_client.close()
            return

        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()

    def _candidate_device_types(self, device: Device) -> List[str]:
        script_name = (getattr(getattr(device, "type", None), "script_name", "") or "").lower()
        type_name = (getattr(getattr(device, "type", None), "name", "") or "").lower()
        token = f"{script_name} {type_name}"

        candidates: List[str] = []

        def add(*items: str):
            for item in items:
                if item and item not in candidates:
                    candidates.append(item)

        if "tplink" in token or "tp-link" in token or "jetstream" in token:
            add("tplink_jetstream", "cisco_ios")
        if "huawei" in token:
            add("huawei", "cisco_ios")
        if "mikrotik" in token:
            add("mikrotik_routeros", "cisco_ios")
        if "cisco" in token:
            add("cisco_ios", "cisco_xe")
        if "juniper" in token:
            add("juniper_junos")
        if "ubiquiti" in token:
            add("vyos", "linux", "cisco_ios")
        if "nokia" in token:
            add("nokia_sros", "nokia_srl", "juniper_junos", "cisco_ios")
        if "arista" in token:
            add("arista_eos", "cisco_ios")
        if "a10" in token:
            add("a10", "linux", "cisco_ios")
        if "hillstone" in token:
            add("linux", "cisco_ios")
        if "olt" in token:
            add("huawei", "zte_zxros", "tplink_jetstream", "cisco_ios")

        if not candidates:
            add("cisco_ios", "huawei", "tplink_jetstream", "linux")

        if device.use_telnet:
            telnet_first: List[str] = []
            for item in candidates:
                if item.endswith("_telnet"):
                    telnet_first.append(item)
                elif item in ("cisco_ios", "huawei"):
                    telnet_first.append(f"{item}_telnet")
            candidates = list(dict.fromkeys(telnet_first + candidates))

        return candidates

    def _test_netmiko(
        self,
        device: Device,
        password: str,
        timeout: int,
        jump_host: Optional[dict] = None,
    ) -> Tuple[bool, str]:
        if ConnectHandler is None:
            return False, "Netmiko indisponivel no ambiente."

        # Normaliza host/usuario (strip) — cobre dispositivos legados com espacos no cadastro.
        device_host = str(device.ip_address or "").strip()
        device_user = str(device.username or "").strip()
        last_error = None
        candidates = self._candidate_device_types(device)
        jump_client = None
        try:
            if jump_host:
                jump_client = self._open_jump_client(jump_host, max(timeout, 8))

            for driver in candidates:
                channel = None
                try:
                    kwargs = {
                        "device_type": driver,
                        "host": device_host,
                        "port": int(device.port or (23 if device.use_telnet else 22)),
                        "username": device_user,
                        "password": password,
                        "conn_timeout": max(timeout, 8),
                        "banner_timeout": max(timeout, 8),
                        "auth_timeout": max(timeout, 8),
                        "fast_cli": False,
                    }
                    if ssh_strict_host_key_checking_enabled() and not driver.endswith("_telnet"):
                        kwargs["ssh_strict"] = True
                        kwargs["system_host_keys"] = True
                    if jump_client:
                        channel = self._open_jump_channel(
                            jump_client,
                            device_host,
                            int(device.port or (23 if device.use_telnet else 22)),
                            max(timeout, 8),
                        )
                        kwargs["sock"] = channel
                    with ConnectHandler(**kwargs):
                        return True, driver
                except Exception as exc:
                    last_error = exc
                finally:
                    try:
                        if channel is not None:
                            channel.close()
                    except Exception:
                        pass
        finally:
            if jump_client:
                jump_client.close()

        return False, str(last_error) if last_error else "Falha de autenticacao via Netmiko."

    def _test_ssh(
        self,
        device: Device,
        password: str,
        timeout: int,
        jump_host: Optional[dict] = None,
    ) -> None:
        # Normaliza host/usuario (strip) — cobre dispositivos legados com espacos no cadastro.
        device_host = str(device.ip_address or "").strip()
        device_user = str(device.username or "").strip()
        client = configure_paramiko_host_key_policy(paramiko.SSHClient())
        jump_client = None
        channel = None
        try:
            if jump_host:
                jump_client = self._open_jump_client(jump_host, timeout)
                channel = self._open_jump_channel(
                    jump_client,
                    device_host,
                    int(device.port or 22),
                    timeout,
                )
            client.connect(
                hostname=device_host,
                port=device.port or 22,
                username=device_user,
                password=password,
                sock=channel,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        finally:
            client.close()
            try:
                if channel is not None:
                    channel.close()
            finally:
                if jump_client is not None:
                    jump_client.close()

    def _test_telnet(self, device: Device, password: str, timeout: int) -> None:
        # Normaliza host/usuario (strip) — espacos acidentais quebravam o comando telnet.
        device_host = str(device.ip_address or "").strip()
        device_user = str(device.username or "").strip()
        command = f"telnet {device_host} {device.port or 23}"
        session = pexpect.spawn(command, timeout=timeout, encoding="utf-8")
        try:
            prompt_login = r"[Ll]ogin[: ]|[Uu]ser(\s*[Nn]ame)?[: ]"
            prompt_pass = r"[Pp]ass(word)?[: ]"
            prompt_shell = r"[>#\]\$]\s*$|<[^>]+>"
            prompt_fail = r"[Ii]ncorrect|[Ff]ailed|[Dd]enied|[Ii]nvalid|authentication failed"

            first = session.expect([prompt_login, prompt_pass, prompt_shell, prompt_fail, pexpect.TIMEOUT, pexpect.EOF])
            if first == 0:
                session.sendline(device_user)
                second = session.expect([prompt_pass, prompt_shell, prompt_fail, pexpect.TIMEOUT, pexpect.EOF])
                if second == 0:
                    session.sendline(password or "")
                    final = session.expect([prompt_shell, prompt_fail, pexpect.TIMEOUT, pexpect.EOF])
                    if final != 0:
                        raise RuntimeError("Autenticacao Telnet falhou.")
                elif second != 1:
                    raise RuntimeError("Falha no fluxo de autenticacao Telnet.")
            elif first == 1:
                session.sendline(password or "")
                final = session.expect([prompt_shell, prompt_fail, pexpect.TIMEOUT, pexpect.EOF])
                if final != 0:
                    raise RuntimeError("Autenticacao Telnet falhou.")
            elif first == 2:
                return
            else:
                raise RuntimeError("Nao foi possivel completar autenticacao Telnet.")
        finally:
            if session.isalive():
                session.close(force=True)

    def diagnose_access_chain(
        self,
        device: Device,
        group: Optional[DeviceGroup] = None,
        manage_vpn: bool = True,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        timeout = int(timeout or self._recommended_timeout(device, group))
        logger = BackupLogger(device.name, verbose=False)
        password = decrypt_password(device.password_encrypted)
        protocol = "telnet" if device.use_telnet else "ssh"
        started = time.monotonic()
        steps: List[Dict[str, Any]] = []
        tcp_ok = False
        jump_host_ok = False
        route_ok = False
        jump_host = self._build_jump_host_config(group, device=device)
        if self._should_bypass_jump_host(device, jump_host):
            jump_host = None

        def _result(ok: bool, category: str, message: str) -> Dict[str, Any]:
            return {
                "ok": bool(ok),
                "category": category,
                "message": str(message or "").strip(),
                "protocol": protocol,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "tcp_ok": bool(tcp_ok),
                "jump_host_ok": bool(jump_host_ok),
                "route_ok": bool(route_ok),
                "steps": steps,
            }

        def _run() -> Dict[str, Any]:
            nonlocal tcp_ok, jump_host_ok, route_ok
            jump_client = None
            try:
                if jump_host:
                    try:
                        sock = socket.create_connection(
                            (jump_host["host"], int(jump_host.get("port") or 22)),
                            timeout=timeout,
                        )
                        sock.close()
                        self._append_step(
                            steps,
                            "jump_reachability",
                            "Jump Host alcançável",
                            "success",
                            f"TCP {jump_host['host']}:{int(jump_host.get('port') or 22)} respondeu.",
                        )
                    except Exception as exc:
                        self._append_step(
                            steps,
                            "jump_reachability",
                            "Jump Host alcançável",
                            "error",
                            str(exc),
                        )
                        category = "timeout" if self._message_has_timeout(str(exc)) else "jump_host_access_failed"
                        return _result(False, category, f"Falha de acesso ao Jump Host: {exc}")

                    try:
                        jump_client = self._open_jump_client(jump_host, timeout)
                        jump_host_ok = True
                        self._append_step(
                            steps,
                            "jump_login",
                            "Login no Jump Host",
                            "success",
                            f"SSH autenticado com {jump_host.get('username')}@{jump_host.get('host')}.",
                        )
                    except Exception as exc:
                        self._append_step(
                            steps,
                            "jump_login",
                            "Login no Jump Host",
                            "error",
                            str(exc),
                        )
                        category = "timeout" if self._message_has_timeout(str(exc)) else "jump_host_access_failed"
                        return _result(False, category, f"Falha de acesso ao Jump Host: {exc}")

                    try:
                        channel = self._open_jump_channel(
                            jump_client,
                            device.ip_address,
                            int(device.port or (23 if device.use_telnet else 22)),
                            timeout,
                        )
                        channel.close()
                        route_ok = True
                        tcp_ok = True
                        self._append_step(
                            steps,
                            "route_to_device",
                            "Rota até dispositivo",
                            "success",
                            f"Jump Host abriu canal para {device.ip_address}:{int(device.port or (23 if device.use_telnet else 22))}.",
                        )
                    except Exception as exc:
                        self._append_step(
                            steps,
                            "route_to_device",
                            "Rota até dispositivo",
                            "error",
                            str(exc),
                        )
                        category = "timeout" if self._message_has_timeout(str(exc)) else "jump_host_no_route"
                        return _result(False, category, f"Jump Host online, mas sem rota para o dispositivo: {exc}")
                else:
                    try:
                        self._test_tcp_port(
                            device.ip_address,
                            int(device.port or (23 if device.use_telnet else 22)),
                            timeout,
                            jump_host=None,
                        )
                        route_ok = True
                        tcp_ok = True
                        self._append_step(
                            steps,
                            "direct_tcp",
                            "Porta do dispositivo",
                            "success",
                            f"TCP {device.ip_address}:{int(device.port or (23 if device.use_telnet else 22))} respondeu.",
                        )
                    except Exception as exc:
                        self._append_step(
                            steps,
                            "direct_tcp",
                            "Porta do dispositivo",
                            "error",
                            str(exc),
                        )
                        category = "timeout" if self._message_has_timeout(str(exc)) else "connectivity_failed"
                        return _result(False, category, f"Falha de conectividade com o dispositivo: {exc}")

                ok, netmiko_info = self._test_netmiko(device, password, timeout, jump_host=jump_host)
                if ok:
                    self._append_step(
                        steps,
                        "device_auth",
                        "Autenticação no dispositivo",
                        "success",
                        f"Login validado com Netmiko ({netmiko_info}).",
                    )
                    return _result(True, "ok", "Acesso completo validado com sucesso.")

                try:
                    if device.use_telnet:
                        self._test_telnet(device, password, timeout)
                    else:
                        self._test_ssh(device, password, timeout, jump_host=jump_host)
                    self._append_step(
                        steps,
                        "device_auth",
                        "Autenticação no dispositivo",
                        "success",
                        "Login validado com fallback nativo.",
                    )
                    return _result(True, "ok", "Acesso completo validado com sucesso.")
                except Exception as exc:
                    self._append_step(
                        steps,
                        "device_auth",
                        "Autenticação no dispositivo",
                        "error",
                        str(exc),
                    )
                    if self._message_has_timeout(str(exc)):
                        return _result(False, "timeout", f"Timeout durante autenticacao no dispositivo: {exc}")
                    if self._message_has_auth_failure(str(exc)) or self._message_has_auth_failure(netmiko_info):
                        return _result(False, "device_auth_failed", f"Credencial do dispositivo invalida: {exc}")
                    if jump_host and self._message_has_route_failure(str(exc)):
                        return _result(False, "jump_host_no_route", f"Jump Host acessivel, mas sem rota/porta ate o dispositivo: {exc}")
                    return _result(False, "connectivity_failed", f"Falha de conectividade no dispositivo: {exc}")
            finally:
                if jump_client is not None:
                    try:
                        jump_client.close()
                    except Exception:
                        pass

        try:
            if group and uses_vpn_tunnel(group, device=device) and manage_vpn:
                with vpn_service.vpn_session(group, logger=logger):
                    return _run()
            return _run()
        except VpnError as exc:
            self._append_step(steps, "vpn", "Preparação de VPN", "error", str(exc))
            return _result(False, "vpn_failed", f"Falha ao preparar VPN: {exc}")
        except Exception as exc:
            self._append_step(steps, "diagnostic", "Diagnóstico", "error", str(exc))
            if self._message_has_timeout(str(exc)):
                return _result(False, "timeout", str(exc))
            return _result(False, "connectivity_failed", str(exc) or "Falha de conexao.")

    def test_device_connection(
        self,
        device: Device,
        group: Optional[DeviceGroup] = None,
        manage_vpn: bool = True,
        timeout: Optional[int] = None,
    ) -> ConnectionTestResult:
        timeout = int(timeout or self._recommended_timeout(device, group))
        logger = BackupLogger(device.name, verbose=False)
        password = decrypt_password(device.password_encrypted)
        script_name = self._script_name(device)
        protocol = "http" if script_name == "grafana_backup.py" else ("telnet" if device.use_telnet else "ssh")
        started = time.monotonic()
        tcp_ok = False
        jump_host = self._build_jump_host_config(group, device=device)
        if self._should_bypass_jump_host(device, jump_host):
            jump_host = None

        def _run():
            nonlocal tcp_ok
            if script_name == "grafana_backup.py":
                ok, msg = self._test_grafana_api(device, timeout)
                tcp_ok = ok
                if ok:
                    return msg
                raise RuntimeError(msg)

            self._test_tcp_port(
                device.ip_address,
                int(device.port or (23 if device.use_telnet else 22)),
                timeout,
                jump_host=jump_host,
            )
            tcp_ok = True

            ok, netmiko_info = self._test_netmiko(device, password, timeout, jump_host=jump_host)
            if ok:
                return f"Conexao validada com sucesso (netmiko: {netmiko_info})."

            fallback_error = None
            try:
                if device.use_telnet:
                    self._test_telnet(device, password, timeout)
                else:
                    self._test_ssh(device, password, timeout, jump_host=jump_host)
                return "Conexao validada com sucesso (fallback)."
            except Exception as exc:
                fallback_error = str(exc)

            raise RuntimeError(
                f"Falha de autenticacao. Netmiko: {netmiko_info}. Fallback: {fallback_error or 'desconhecido'}"
            )

        try:
            if group and uses_vpn_tunnel(group, device=device) and manage_vpn:
                with vpn_service.vpn_session(group, logger=logger):
                    msg = _run()
            else:
                msg = _run()

            elapsed = int((time.monotonic() - started) * 1000)
            return ConnectionTestResult(
                success=True,
                message=msg,
                protocol=protocol,
                elapsed_ms=elapsed,
                tcp_ok=tcp_ok,
            )
        except VpnError as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            return ConnectionTestResult(
                success=False,
                message=f"Falha ao preparar VPN: {exc}",
                protocol=protocol,
                elapsed_ms=elapsed,
                tcp_ok=tcp_ok,
            )
        except Exception as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            return ConnectionTestResult(
                success=False,
                message=str(exc) or "Falha de conexao.",
                protocol=protocol,
                elapsed_ms=elapsed,
                tcp_ok=tcp_ok,
            )


connection_test_service = ConnectionTestService()
