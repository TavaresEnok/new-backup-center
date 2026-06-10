import json
import logging
import os
import re
import socket
import time
from datetime import datetime
from typing import Any, Dict, Optional

from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.services.connection_mode import uses_jump_host
from app.services.connection_test_service import connection_test_service
from app.services.realtime_backup_logs import get_redis_client

logger = logging.getLogger(__name__)

JUMP_HOST_STATE_PREFIX = "backup_center:jump_host_state:"
JUMP_HOST_TTL_SECONDS = 60 * 60 * 24 * 30
SAFE_COMMAND_RE = re.compile(r'^[a-zA-Z0-9_./:@=,+% "\'-]{1,300}$')
FORBIDDEN_COMMAND_TOKENS = {
    "sudo",
    "su ",
    "rm ",
    "shutdown",
    "reboot",
    "systemctl ",
    "service ",
    "mkfs",
    "dd ",
    "passwd",
    "useradd",
    "usermod",
    "chmod 777",
    "chown ",
    "iptables ",
    "nft ",
    "docker ",
    "podman ",
    "kill ",
    "pkill ",
    "curl ",
    "wget ",
    "scp ",
    "sftp ",
}
SAFE_COMMAND_PREFIXES = (
    "hostname",
    "whoami",
    "uptime",
    "date",
    "pwd",
    "uname",
    "cat /etc/os-release",
    "df ",
    "free ",
    "ip ",
    "ss ",
    "netstat ",
    "route",
    "traceroute ",
    "tracepath ",
    "ping ",
    "nc ",
    "telnet ",
    "ssh ",
)


def _ssh_host_key_safe_flags() -> str:
    strict = os.getenv("BACKUP_SSH_STRICT_HOST_KEY_CHECKING", "0").strip().lower()
    if strict in {"1", "true", "yes", "on", "strict"}:
        return "-o StrictHostKeyChecking=yes "
    return "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "


def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _normalize_category(category: str) -> str:
    value = str(category or "").strip().lower()
    if value in {
        "jump_host_access_failed",
        "jump_host_no_route",
        "device_auth_failed",
        "timeout",
        "connectivity_failed",
        "vpn_failed",
        "ok",
        "disabled",
        "not_configured",
    }:
        return value
    return "connectivity_failed"


def recommendation_for_category(category: str, target_ip: str | None = None) -> str:
    category = _normalize_category(category)
    if category == "jump_host_access_failed":
        return "Senha ou chave do Jump Host podem estar incorretas, expiradas ou sem permissao."
    if category == "jump_host_no_route":
        target = target_ip or "o dispositivo final"
        return f"Jump Host acessivel, mas sem rota ou porta aberta ate {target}. Validar rota, ACL e firewall."
    if category == "device_auth_failed":
        return "Dispositivo respondeu ao acesso, mas rejeitou login. Revisar usuario, senha e metodo SSH/Telnet."
    if category == "timeout":
        return "Timeout no caminho. Verificar latencia, sobrecarga do Jump Host e disponibilidade da porta de gerencia."
    if category == "vpn_failed":
        return "Falha ao preparar VPN do grupo. Validar tunel, credenciais e estado da interface."
    if category == "not_configured":
        return "Grupo com Jump Host sem host/usuario/credencial suficientes para operar."
    if category == "disabled":
        return "Grupo nao usa Jump Host neste momento."
    return "Falha de conectividade. Validar reachability, rota e porta de gerencia."


class JumpHostService:
    def _state_key(self, tenant_id: str, group_id: str) -> str:
        return f"{JUMP_HOST_STATE_PREFIX}{tenant_id}:{group_id}"

    def _default_state(self, group: Optional[DeviceGroup] = None) -> Dict[str, Any]:
        return {
            "group_id": str(getattr(group, "id", "") or ""),
            "status": "unknown",
            "last_checked_at": None,
            "last_success_at": None,
            "last_failure_category": None,
            "last_failure_message": None,
            "last_password_change_at": None,
            "jump_host": str(getattr(group, "jump_host", "") or ""),
            "jump_port": int(getattr(group, "jump_port", 22) or 22),
            "jump_username": str(getattr(group, "jump_username", "") or ""),
            "uses_jump_host": bool(getattr(group, "uses_jump_host", False)),
        }

    def get_group_state(self, tenant_id: str, group: DeviceGroup) -> Dict[str, Any]:
        state = self._default_state(group)
        client = get_redis_client()
        if not client:
            return state
        try:
            raw = client.get(self._state_key(str(tenant_id), str(group.id)))
            if not raw:
                return state
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                state.update(parsed)
        except Exception:
            logger.exception("Falha ao carregar estado operacional do Jump Host do grupo %s", getattr(group, "id", None))
        return state

    def update_group_state(self, tenant_id: str, group: DeviceGroup, **fields: Any) -> Dict[str, Any]:
        state = self.get_group_state(tenant_id, group)
        state.update(fields)
        state["group_id"] = str(group.id)
        state["jump_host"] = str(getattr(group, "jump_host", "") or "")
        state["jump_port"] = int(getattr(group, "jump_port", 22) or 22)
        state["jump_username"] = str(getattr(group, "jump_username", "") or "")
        state["uses_jump_host"] = bool(getattr(group, "uses_jump_host", False))
        client = get_redis_client()
        if client:
            try:
                client.setex(
                    self._state_key(str(tenant_id), str(group.id)),
                    JUMP_HOST_TTL_SECONDS,
                    json.dumps(state, ensure_ascii=False),
                )
            except Exception:
                logger.exception("Falha ao salvar estado operacional do Jump Host do grupo %s", group.id)
        return state

    def mark_credentials_rotated(self, tenant_id: str, group: DeviceGroup) -> Dict[str, Any]:
        return self.update_group_state(
            tenant_id,
            group,
            last_password_change_at=_now_iso(),
        )

    def run_health_check(self, tenant_id: str, group: DeviceGroup, timeout: int = 8) -> Dict[str, Any]:
        started = time.monotonic()
        if not uses_jump_host(group):
            return self.update_group_state(
                tenant_id,
                group,
                status="disabled",
                last_checked_at=_now_iso(),
                last_failure_category="disabled",
                last_failure_message="Grupo nao usa Jump Host.",
            )

        jump_host = connection_test_service._build_jump_host_config(group)
        if not jump_host:
            return self.update_group_state(
                tenant_id,
                group,
                status="not_configured",
                last_checked_at=_now_iso(),
                last_failure_category="not_configured",
                last_failure_message="Configuracao do Jump Host incompleta.",
            )

        tcp_ok = False
        ssh_ok = False
        shell_ok = False
        checked_at = _now_iso()
        try:
            sock = socket.create_connection((jump_host["host"], int(jump_host.get("port") or 22)), timeout=timeout)
            sock.close()
            tcp_ok = True

            client = connection_test_service._open_jump_client(jump_host, timeout)
            try:
                ssh_ok = True
                stdin, stdout, stderr = client.exec_command("echo backup-center-jump-ok", timeout=timeout)
                stdout.channel.settimeout(timeout)
                output = (stdout.read() or b"").decode(errors="ignore").strip()
                shell_ok = output == "backup-center-jump-ok"
            finally:
                client.close()

            status = "healthy" if shell_ok else "degraded"
            state = self.update_group_state(
                tenant_id,
                group,
                status=status,
                last_checked_at=checked_at,
                last_success_at=checked_at,
                last_failure_category=None if shell_ok else "connectivity_failed",
                last_failure_message=None if shell_ok else "SSH conectado, mas shell nao respondeu como esperado.",
                tcp_ok=tcp_ok,
                ssh_ok=ssh_ok,
                shell_ok=shell_ok,
                last_elapsed_ms=int((time.monotonic() - started) * 1000),
            )
            return state
        except Exception as exc:
            message = str(exc) or "Falha ao validar Jump Host."
            text = message.lower()
            category = "timeout" if "timeout" in text or "timed out" in text else "jump_host_access_failed"
            if "auth" not in text and "permission" not in text and category != "timeout":
                category = "connectivity_failed"
            return self.update_group_state(
                tenant_id,
                group,
                status="unhealthy",
                last_checked_at=checked_at,
                last_failure_category=category,
                last_failure_message=message,
                tcp_ok=tcp_ok,
                ssh_ok=ssh_ok,
                shell_ok=shell_ok,
                last_elapsed_ms=int((time.monotonic() - started) * 1000),
            )

    def collect_remote_diagnostics(
        self,
        tenant_id: str,
        group: DeviceGroup,
        device: Optional[Device] = None,
        timeout: int = 12,
    ) -> Dict[str, Any]:
        commands = [
            ("hostname", "hostname"),
            ("uptime", "uptime"),
            ("data", "date"),
            ("rotas", "ip route"),
            ("sockets", "ss -tunap"),
        ]
        if device and getattr(device, "ip_address", None):
            target = str(device.ip_address)
            target_port = int(getattr(device, "port", 22) or 22)
            commands.extend(
                [
                    ("ping_alvo", f"ping -c 2 -W 2 {target}"),
                    ("porta_alvo", f"nc -vz -w 3 {target} {target_port}"),
                ]
            )

        result_items = []
        combined_output = []
        for label, command in commands:
            execution = self.exec_console_command(
                tenant_id=tenant_id,
                group=group,
                command=command,
                timeout=timeout,
                audit=False,
            )
            result_items.append(
                {
                    "label": label,
                    "command": command,
                    "ok": bool(execution.get("ok")),
                    "output": execution.get("output") or execution.get("error") or "",
                }
            )
            combined_output.append(f"$ {command}\n{result_items[-1]['output']}".strip())

        state = self.update_group_state(
            tenant_id,
            group,
            last_diagnostic_at=_now_iso(),
            last_diagnostic_summary="\n\n".join(combined_output).strip(),
        )
        return {
            "ok": all(item["ok"] for item in result_items),
            "items": result_items,
            "summary": "\n\n".join(combined_output).strip(),
            "state": state,
        }

    def exec_console_command(
        self,
        tenant_id: str,
        group: DeviceGroup,
        command: str,
        timeout: int = 15,
        audit: bool = True,
    ) -> Dict[str, Any]:
        raw_command = str(command or "").strip()
        if not raw_command:
            return {"ok": False, "error": "Informe um comando para executar."}
        if not SAFE_COMMAND_RE.match(raw_command):
            return {"ok": False, "error": "Comando contem caracteres nao permitidos."}

        lowered = raw_command.lower()
        if any(token in lowered for token in FORBIDDEN_COMMAND_TOKENS):
            return {"ok": False, "error": "Comando bloqueado por politica de seguranca."}
        if not any(lowered == prefix or lowered.startswith(prefix) for prefix in SAFE_COMMAND_PREFIXES):
            return {
                "ok": False,
                "error": "Comando fora da whitelist operacional. Use hostname, uptime, ip, ss, ping, nc, traceroute ou telnet.",
            }

        jump_host = connection_test_service._build_jump_host_config(group)
        if not jump_host:
            return {"ok": False, "error": "Jump Host nao configurado para este grupo."}

        # Normaliza e protege o comando antes de executar
        safe_command = raw_command
        cmd_lower = raw_command.lower()

        if cmd_lower.startswith("ping ") and "-c" not in raw_command:
            # Ping sem limite: adiciona -c 5 -W 2 automaticamente
            safe_command = raw_command.replace("ping ", "ping -c 5 -W 2 ", 1)

        elif cmd_lower.startswith("ssh "):
            # SSH nao-interativo: injeta flags de seguranca obrigatorias
            # BatchMode=yes: sem prompts de senha (nao bloqueia)
            # Host key checking segue BACKUP_SSH_STRICT_HOST_KEY_CHECKING.
            # ConnectTimeout=8: timeout de conexao rapido
            # NumberOfPasswordPrompts=0: garante sem prompt de senha
            safe_flags = (
                "-o BatchMode=yes "
                f"{_ssh_host_key_safe_flags()}"
                "-o ConnectTimeout=8 "
                "-o NumberOfPasswordPrompts=0 "
            )
            # Insere as flags logo apos 'ssh '
            safe_command = "ssh " + safe_flags + raw_command[4:].lstrip()
            timeout = 22  # SSH precisa de um pouco mais de tempo

        # Envolve com timeout Linux para garantir que o processo morra
        exec_command = f"timeout {timeout} {safe_command}"

        started = time.monotonic()
        try:
            client = connection_test_service._open_jump_client(jump_host, timeout + 3)
            try:
                stdin, stdout, stderr = client.exec_command(exec_command, timeout=timeout + 3)
                stdout.channel.settimeout(timeout + 3)
                stderr.channel.settimeout(timeout + 3)
                output = (stdout.read() or b"").decode(errors="ignore")
                error = (stderr.read() or b"").decode(errors="ignore")
            finally:
                client.close()

            ok = not bool(error.strip())
            checked_at = _now_iso()
            self.update_group_state(
                tenant_id,
                group,
                last_checked_at=checked_at,
                last_success_at=checked_at if ok else None,
                status="healthy" if ok else "degraded",
                last_failure_category=None if ok else "connectivity_failed",
                last_failure_message=None if ok else error.strip()[:500],
                last_console_command=raw_command,
                last_console_output=(output or error)[:2000],
                last_elapsed_ms=int((time.monotonic() - started) * 1000),
            )
            return {
                "ok": ok,
                "output": output.strip(),
                "error": error.strip(),
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
        except Exception as exc:
            message = str(exc) or "Falha ao executar comando no Jump Host."
            self.update_group_state(
                tenant_id,
                group,
                status="unhealthy",
                last_checked_at=_now_iso(),
                last_failure_category="timeout" if "timeout" in message.lower() else "jump_host_access_failed",
                last_failure_message=message[:500],
                last_console_command=raw_command,
                last_elapsed_ms=int((time.monotonic() - started) * 1000),
            )
            return {
                "ok": False,
                "error": message,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }


jump_host_service = JumpHostService()
