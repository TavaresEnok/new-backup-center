#!/usr/bin/env python3
"""Read-only comparison of JumpServer inventory and configured system Jump Hosts.

This utility never calls backup scripts and never changes device configuration.
JumpServer is queried only with GET requests. Active probes are restricted to
the Jump Host credentials already configured in Backup Center and must be
enabled explicitly with --execute-system-jumphost.
"""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import paramiko
from sqlalchemy import text
from sqlalchemy.orm import joinedload

from app.core.database import SessionLocal, engine
from app.models import Device
from app.services.connection_mode import uses_jump_host
from app.services.connection_test_service import ConnectionTestService
from app.scripts.backup_scripts.script_helpers import configure_paramiko_host_key_policy

logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)


FIELDS = [
    "Cliente/tenant",
    "Grupo",
    "Nome do dispositivo",
    "IP",
    "Porta",
    "Tipo de equipamento",
    "Script associado",
    "Caminho testado",
    "JumpHost acessivel",
    "Dispositivo alcancavel via ping",
    "Porta de gerencia aberta",
    "Login no dispositivo",
    "Comando seguro executado",
    "Resultado final",
    "Mensagem tecnica resumida",
    "Recomendacao objetiva",
    "Latencia ms",
    "Device ID",
]

RESULT_OK = "OK"
RESULT_JUMP = "Falha de JumpHost"
RESULT_ROUTE = "Falha de rota"
RESULT_PORT = "Porta fechada"
RESULT_AUTH = "Falha de credencial"
RESULT_TIMEOUT = "Timeout"
RESULT_REGISTRY = "Cadastro inconsistente"
RESULT_SCRIPT = "Script ausente"
RESULT_INCONCLUSIVE = "Inconclusivo"

INVALID_COMMAND_MARKERS = (
    "invalid command",
    "unknown command",
    "unrecognized command",
    "invalid input",
    "command not found",
    "incomplete command",
    "erro: comando",
)


def clean_message(message: Any, limit: int = 260) -> str:
    value = str(message or "").replace("\r", " ").replace("\n", " ")
    value = re.sub(
        r"(?i)\b(password|passwd|secret|token|authorization|key)\b\s*[:=]\s*\S+",
        r"\1=***",
        value,
    )
    value = re.sub(r"\s+", " ", value).strip()
    return value[:limit]


def tri(value: bool | None) -> str:
    if value is True:
        return "sim"
    if value is False:
        return "nao"
    return "nao aplicavel"


def empty_row(device: Device, path: str) -> dict[str, str]:
    group = getattr(device, "group", None)
    dtype = getattr(device, "type", None)
    tenant = getattr(device, "tenant", None)
    return {
        "Cliente/tenant": str(getattr(tenant, "name", "") or ""),
        "Grupo": str(getattr(group, "name", "") or ""),
        "Nome do dispositivo": str(device.name or ""),
        "IP": str(device.ip_address or ""),
        "Porta": str(device.port or (23 if device.use_telnet else 22)),
        "Tipo de equipamento": str(getattr(dtype, "name", "") or ""),
        "Script associado": str(getattr(dtype, "script_name", "") or ""),
        "Caminho testado": path,
        "JumpHost acessivel": "nao aplicavel",
        "Dispositivo alcancavel via ping": "nao aplicavel",
        "Porta de gerencia aberta": "nao aplicavel",
        "Login no dispositivo": "nao aplicavel",
        "Comando seguro executado": "nao aplicavel",
        "Resultado final": RESULT_INCONCLUSIVE,
        "Mensagem tecnica resumida": "",
        "Recomendacao objetiva": "",
        "Latencia ms": "",
        "Device ID": str(device.id),
    }


def load_devices(limit: int | None = None) -> list[Device]:
    db = SessionLocal()
    try:
        if engine.dialect.name == "postgresql":
            db.execute(text("SET TRANSACTION READ ONLY"))
        query = (
            db.query(Device)
            .options(
                joinedload(Device.tenant),
                joinedload(Device.group),
                joinedload(Device.subgroup),
                joinedload(Device.type),
            )
            .filter(Device.is_active.is_(True))
            .order_by(Device.name.asc(), Device.id.asc())
        )
        if limit:
            query = query.limit(int(limit))
        devices = query.all()
        db.expunge_all()
        db.rollback()
        return devices
    finally:
        db.close()


def script_status(device: Device) -> tuple[bool, str]:
    dtype = getattr(device, "type", None)
    script_name = str(getattr(dtype, "script_name", "") or "").strip()
    if not dtype or not script_name:
        return False, "Tipo de equipamento ou script nao associado."
    script_path = PROJECT_ROOT / "app" / "scripts" / "backup_scripts" / script_name
    if not script_path.is_file():
        return False, f"Arquivo de script nao localizado: {script_name}."
    try:
        tree = ast.parse(script_path.read_text(encoding="utf-8"), filename=str(script_path))
    except Exception:
        return False, f"Script nao pode ser analisado: {script_name}."
    has_entrypoint = any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "realizar_backup"
        for node in tree.body
    )
    if not has_entrypoint:
        return False, f"Script sem entrada realizar_backup: {script_name}."
    return True, "Script associado localizado."


class JumpServerReadOnlyClient:
    def __init__(self, base_url: str, key_id: str, secret: str, org_id: str, timeout: int):
        self.base_url = base_url.rstrip("/")
        self.key_id = key_id
        self.secret = secret
        self.org_id = org_id
        self.timeout = timeout

    def _headers(self, path: str) -> dict[str, str]:
        date = dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        accept = "application/json"
        signed = f"(request-target): get {path}\naccept: {accept}\ndate: {date}"
        digest = hmac.new(self.secret.encode(), signed.encode(), hashlib.sha256).digest()
        signature = base64.b64encode(digest).decode()
        authorization = (
            f'Signature keyId="{self.key_id}",algorithm="hmac-sha256",'
            f'headers="(request-target) accept date",signature="{signature}"'
        )
        return {
            "Accept": accept,
            "Date": date,
            "Authorization": authorization,
            "X-JMS-ORG": self.org_id,
        }

    def get(self, path: str) -> Any:
        request = urllib.request.Request(self.base_url + path, headers=self._headers(path))
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = clean_message(exc.read().decode("utf-8", "replace"))
            raise RuntimeError(f"JumpServer GET falhou (HTTP {exc.code}): {detail}") from exc

    def list_all(self, resource: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        offset = 0
        limit = 250
        while True:
            query = urllib.parse.urlencode({"limit": limit, "offset": offset})
            payload = self.get(f"/api/v1/assets/{resource}/?{query}")
            if isinstance(payload, dict):
                page = payload.get("data") or payload.get("results") or []
                count = int(payload.get("count") or len(page))
            else:
                page = payload or []
                count = len(page)
            rows.extend(page)
            if not page or len(rows) >= count:
                break
            offset += len(page)
        return rows


def object_id(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("id") or "")
    return str(value or "")


def jumpserver_rows(
    devices: list[Device],
    client: JumpServerReadOnlyClient | None,
    error: str | None = None,
) -> tuple[list[dict[str, str]], dict[str, int], dict[str, list[str]]]:
    rows: list[dict[str, str]] = []
    stats = {"assets": 0, "gateways": 0, "matched_devices": 0}
    gateway_addresses_by_zone: dict[str, list[str]] = defaultdict(list)
    assets_by_address: dict[str, list[dict[str, Any]]] = defaultdict(list)

    if client and not error:
        try:
            assets = client.list_all("assets")
            gateways = client.list_all("gateways")
            stats["assets"] = len(assets)
            stats["gateways"] = len(gateways)
            for asset in assets:
                assets_by_address[str(asset.get("address") or "").strip()].append(asset)
            for gateway in gateways:
                zone_id = object_id(gateway.get("zone"))
                if zone_id:
                    gateway_addresses_by_zone[zone_id].append(str(gateway.get("address") or ""))
        except Exception as exc:
            error = clean_message(exc)

    for device in devices:
        row = empty_row(device, "JumpServer (inventario read-only)")
        script_ok, script_msg = script_status(device)
        if error or not client:
            row["Resultado final"] = RESULT_INCONCLUSIVE
            row["Mensagem tecnica resumida"] = error or "Credencial/API do JumpServer nao fornecida."
            row["Recomendacao objetiva"] = "Validar acesso GET da API do JumpServer."
            rows.append(row)
            continue

        matches = assets_by_address.get(str(device.ip_address).strip(), [])
        if not matches:
            row["Resultado final"] = RESULT_REGISTRY
            row["Mensagem tecnica resumida"] = "Dispositivo nao localizado no inventario JumpServer pelo IP."
            row["Recomendacao objetiva"] = "Conferir cadastro do ativo no JumpServer ou o IP no Backup Center."
            rows.append(row)
            continue

        stats["matched_devices"] += 1
        asset = matches[0]
        zone_id = object_id(asset.get("zone"))
        gateways = [item for item in gateway_addresses_by_zone.get(zone_id, []) if item]
        gateway_note = f" Gateway(s) associado(s): {len(gateways)}." if gateways else " Sem gateway associado na zona."
        row["Resultado final"] = RESULT_INCONCLUSIVE if script_ok else RESULT_SCRIPT
        row["Mensagem tecnica resumida"] = (
            f"Ativo localizado no JumpServer.{gateway_note} "
            "Teste ativo bloqueado: exigiria criar sessao/tarefa no JumpServer."
        )
        row["Recomendacao objetiva"] = (
            "Autorizar posteriormente uma sessao auditada de leitura no JumpServer."
            if script_ok
            else script_msg
        )
        rows.append(row)
    return rows, stats, gateway_addresses_by_zone


def safe_command_for(device: Device) -> str:
    dtype = str(getattr(getattr(device, "type", None), "name", "") or "").lower()
    script = str(getattr(getattr(device, "type", None), "script_name", "") or "").lower()
    combined = f"{dtype} {script}"
    if "mikrotik" in combined or "routeros" in combined:
        return "/system identity print"
    if "huawei" in combined:
        return "display version"
    if "zte" in combined:
        return "show version"
    if any(token in combined for token in ("linux", "zabbix", "grafana", "erp")):
        return "hostname"
    return "show version"


def target_address(device: Device) -> tuple[str, int] | None:
    address = str(device.ip_address or "").strip()
    try:
        ipaddress.ip_address(address)
    except ValueError:
        return None
    return address, int(device.port or (23 if device.use_telnet else 22))


def remote_exec(client: paramiko.SSHClient, command: str, timeout: int) -> tuple[int, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    del stdin
    stdout.channel.settimeout(timeout)
    stderr.channel.settimeout(timeout)
    output = (stdout.read() + stderr.read()).decode("utf-8", "replace")
    return int(stdout.channel.recv_exit_status()), output


def probe_ping(jump_client: paramiko.SSHClient, address: str, timeout: int) -> bool | None:
    command = (
        "if command -v ping >/dev/null 2>&1; then "
        f"ping -c 1 -W {int(timeout)} {address} >/dev/null 2>&1; "
        "else exit 127; fi"
    )
    status, _ = remote_exec(jump_client, command, timeout + 2)
    if status == 127:
        return None
    return status == 0


def probe_tcp(jump_client: paramiko.SSHClient, address: str, port: int, timeout: int) -> bool | None:
    probe_code = (
        "import socket; "
        f"s=socket.create_connection(('{address}',{int(port)}),{int(timeout)}); s.close()"
    )
    command = (
        "if command -v nc >/dev/null 2>&1; then "
        f"nc -z -w {int(timeout)} {address} {int(port)} >/dev/null 2>&1; "
        "elif command -v python3 >/dev/null 2>&1; then "
        f"python3 -c \"{probe_code}\" >/dev/null 2>&1; "
        "else exit 127; fi"
    )
    status, _ = remote_exec(jump_client, command, timeout + 2)
    if status == 127:
        return None
    return status == 0


def command_response_ok(output: str, command: str) -> bool:
    lowered = str(output or "").lower()
    if any(marker in lowered for marker in INVALID_COMMAND_MARKERS):
        return False
    visible = [line.strip() for line in output.replace("\r", "").splitlines() if line.strip()]
    return any(line != command for line in visible)


def probe_ssh_device(
    helper: ConnectionTestService,
    jump_client: paramiko.SSHClient,
    device: Device,
    password: str,
    timeout: int,
) -> tuple[bool, bool, str]:
    destination = target_address(device)
    if not destination:
        return False, False, "IP do dispositivo invalido."
    address, port = destination
    channel = None
    target = configure_paramiko_host_key_policy(paramiko.SSHClient())
    try:
        channel = helper._open_jump_channel(jump_client, address, port, timeout)
        target.connect(
            hostname=address,
            port=port,
            username=device.username,
            password=password,
            sock=channel,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        command = safe_command_for(device)
        shell = target.invoke_shell(width=120, height=24)
        shell.settimeout(0.5)
        time.sleep(0.25)
        while shell.recv_ready():
            shell.recv(8192)
        shell.send(command + "\n")
        deadline = time.monotonic() + timeout
        chunks: list[str] = []
        while time.monotonic() < deadline:
            if shell.recv_ready():
                chunks.append(shell.recv(8192).decode("utf-8", "replace"))
                time.sleep(0.2)
                if not shell.recv_ready() and chunks:
                    break
            else:
                time.sleep(0.1)
        return True, command_response_ok("".join(chunks), command), "Login SSH concluido."
    except paramiko.AuthenticationException:
        return False, False, "Credencial SSH recusada pelo dispositivo."
    except (socket.timeout, TimeoutError):
        raise TimeoutError("Tempo esgotado durante login/comando SSH.")
    except Exception as exc:
        message = clean_message(exc)
        if "kex" in message.lower() or "algorithm" in message.lower():
            return False, False, "SSH legado/incompativel para este probe seguro."
        return False, False, f"Sessao SSH nao concluida: {message}"
    finally:
        target.close()
        if channel is not None:
            channel.close()


def read_channel(channel: Any, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    chunks: list[str] = []
    while time.monotonic() < deadline:
        if channel.recv_ready():
            chunks.append(channel.recv(8192).decode("utf-8", "replace"))
            time.sleep(0.1)
        else:
            time.sleep(0.1)
    return "".join(chunks)


def probe_telnet_device(
    helper: ConnectionTestService,
    jump_client: paramiko.SSHClient,
    device: Device,
    password: str,
    timeout: int,
) -> tuple[bool, bool, str]:
    destination = target_address(device)
    if not destination:
        return False, False, "IP do dispositivo invalido."
    address, port = destination
    channel = None
    try:
        channel = helper._open_jump_channel(jump_client, address, port, timeout)
        channel.settimeout(timeout)
        banner = read_channel(channel, min(timeout, 2))
        lower = banner.lower()
        if "login" in lower or "username" in lower or "user name" in lower:
            channel.send((str(device.username or "") + "\n").encode())
            banner += read_channel(channel, min(timeout, 2))
            lower = banner.lower()
        if "password" in lower or "senha" in lower or "passwd" in lower:
            channel.send((password + "\n").encode())
            banner = read_channel(channel, min(timeout, 3))
            lower = banner.lower()
        if any(value in lower for value in ("bad password", "login failed", "authentication failed", "denied")):
            return False, False, "Credencial Telnet recusada pelo dispositivo."
        if not re.search(r"[>#\]]\s*$|<[^>]+>", banner, re.MULTILINE):
            return False, False, "Prompt Telnet nao confirmado apos autenticacao."
        command = safe_command_for(device)
        channel.send((command + "\n").encode())
        output = read_channel(channel, min(timeout, 4))
        return True, command_response_ok(output, command), "Login Telnet concluido."
    except (socket.timeout, TimeoutError):
        raise TimeoutError("Tempo esgotado durante login/comando Telnet.")
    except Exception as exc:
        return False, False, f"Sessao Telnet nao concluida: {clean_message(exc)}"
    finally:
        if channel is not None:
            channel.close()


def inaccessible_rows(devices: Iterable[Device], result: str, message: str, recommendation: str) -> list[dict[str, str]]:
    rows = []
    for device in devices:
        row = empty_row(device, "JumpHost do sistema")
        row["JumpHost acessivel"] = "nao"
        row["Resultado final"] = result
        row["Mensagem tecnica resumida"] = clean_message(message)
        row["Recomendacao objetiva"] = recommendation
        rows.append(row)
    return rows


def configured_group_jump_host(helper: ConnectionTestService, device: Device, force: bool = False) -> dict[str, Any] | None:
    group = getattr(device, "group", None)
    if not force:
        return helper._build_jump_host_config(group, device=device)
    if not group or not getattr(group, "jump_host", None) or not getattr(group, "jump_username", None):
        return None

    from app.core.security import decrypt_password

    password = (
        decrypt_password(group.jump_password_encrypted)
        if getattr(group, "jump_password_encrypted", None)
        else None
    )
    key = (
        decrypt_password(group.jump_key_encrypted)
        if getattr(group, "jump_key_encrypted", None)
        else None
    )
    if not password and not key:
        return None
    return {
        "host": group.jump_host,
        "port": int(group.jump_port or 22),
        "username": group.jump_username,
        "password": password,
        "key": key,
    }


def validate_system_group(
    devices: list[Device],
    timeout: int,
    execute: bool,
    force_jump_host: bool = False,
) -> list[dict[str, str]]:
    helper = ConnectionTestService()
    first = devices[0]
    if not execute:
        rows = []
        for device in devices:
            row = empty_row(device, "JumpHost do sistema")
            row["Resultado final"] = RESULT_INCONCLUSIVE
            row["Mensagem tecnica resumida"] = "Probe ativo nao executado; use --execute-system-jumphost."
            row["Recomendacao objetiva"] = "Executar validacao somente leitura do JumpHost configurado."
            rows.append(row)
        return rows

    jump = configured_group_jump_host(helper, first, force=force_jump_host)
    if not jump:
        return inaccessible_rows(
            devices,
            RESULT_REGISTRY,
            "Caminho JumpHost efetivo sem host/usuario/credencial disponivel.",
            "Completar cadastro do JumpHost no grupo.",
        )

    started = time.monotonic()
    try:
        socket.create_connection((jump["host"], int(jump.get("port") or 22)), timeout=timeout).close()
    except socket.timeout:
        return inaccessible_rows(devices, RESULT_TIMEOUT, "Timeout TCP ao acessar JumpHost.", "Revisar rota/firewall do JumpHost.")
    except Exception as exc:
        return inaccessible_rows(devices, RESULT_JUMP, f"TCP do JumpHost falhou: {clean_message(exc)}", "Revisar host, porta ou firewall.")

    jump_client = None
    try:
        jump_client = helper._open_jump_client(jump, timeout)
        shell_status, shell_output = remote_exec(jump_client, "hostname; whoami; echo __JUMP_OK__", timeout)
        if shell_status != 0 or "__JUMP_OK__" not in shell_output:
            return inaccessible_rows(
                devices,
                RESULT_JUMP,
                "SSH autenticou, mas o shell seguro do JumpHost nao respondeu.",
                "Verificar permissao de shell do usuario do JumpHost.",
            )
        rows: list[dict[str, str]] = []
        for device in devices:
            row = empty_row(device, "JumpHost do sistema")
            row["JumpHost acessivel"] = "sim"
            row["Latencia ms"] = str(int((time.monotonic() - started) * 1000))
            valid_script, script_msg = script_status(device)
            destination = target_address(device)
            if not destination:
                row["Resultado final"] = RESULT_REGISTRY
                row["Mensagem tecnica resumida"] = "IP ou porta de gerencia invalido no cadastro."
                row["Recomendacao objetiva"] = "Corrigir cadastro do dispositivo."
                rows.append(row)
                continue
            address, port = destination
            try:
                ping_ok = probe_ping(jump_client, address, timeout)
                row["Dispositivo alcancavel via ping"] = tri(ping_ok)
            except Exception:
                row["Dispositivo alcancavel via ping"] = "nao aplicavel"
            try:
                tcp_started = time.monotonic()
                tcp_ok = probe_tcp(jump_client, address, port, timeout)
                row["Porta de gerencia aberta"] = tri(tcp_ok)
                row["Latencia ms"] = str(int((time.monotonic() - tcp_started) * 1000))
            except (socket.timeout, TimeoutError):
                tcp_ok = False
                row["Porta de gerencia aberta"] = "nao"
                row["Resultado final"] = RESULT_TIMEOUT
                row["Mensagem tecnica resumida"] = "Timeout no teste TCP executado a partir do JumpHost."
                row["Recomendacao objetiva"] = "Revisar rota, firewall ou porta de gerencia."
                rows.append(row)
                continue
            except Exception as exc:
                tcp_ok = False
                row["Porta de gerencia aberta"] = "nao"
                row["Resultado final"] = RESULT_ROUTE
                row["Mensagem tecnica resumida"] = f"Teste TCP via JumpHost falhou: {clean_message(exc)}"
                row["Recomendacao objetiva"] = "Revisar rota/firewall entre JumpHost e dispositivo."
                rows.append(row)
                continue
            if tcp_ok is None:
                row["Resultado final"] = RESULT_INCONCLUSIVE
                row["Mensagem tecnica resumida"] = "JumpHost sem ferramenta segura disponivel para teste TCP."
                row["Recomendacao objetiva"] = "Instalar ferramenta de diagnostico aprovada no JumpHost."
                rows.append(row)
                continue
            if not tcp_ok:
                row["Resultado final"] = RESULT_PORT
                row["Mensagem tecnica resumida"] = "Porta de gerencia nao respondeu a partir do JumpHost."
                row["Recomendacao objetiva"] = "Confirmar porta cadastrada e liberacao de firewall."
                rows.append(row)
                continue

            from app.core.security import decrypt_password

            password = decrypt_password(device.password_encrypted)
            try:
                if device.use_telnet:
                    login_ok, command_ok, detail = probe_telnet_device(helper, jump_client, device, password, timeout)
                else:
                    login_ok, command_ok, detail = probe_ssh_device(helper, jump_client, device, password, timeout)
            except TimeoutError as exc:
                row["Resultado final"] = RESULT_TIMEOUT
                row["Mensagem tecnica resumida"] = clean_message(exc)
                row["Recomendacao objetiva"] = "Confirmar protocolo, prompt e tempo de resposta do dispositivo."
                rows.append(row)
                continue
            finally:
                password = ""
            row["Login no dispositivo"] = tri(login_ok)
            row["Comando seguro executado"] = tri(command_ok if login_ok else None)
            if not login_ok:
                detail_lower = detail.lower()
                if "credencial" in detail_lower or "recusada" in detail_lower:
                    row["Resultado final"] = RESULT_AUTH
                    row["Recomendacao objetiva"] = "Corrigir usuario/senha cadastrados para o dispositivo."
                else:
                    row["Resultado final"] = RESULT_INCONCLUSIVE
                    row["Recomendacao objetiva"] = "Validar protocolo/prompt ou compatibilidade SSH do equipamento."
                row["Mensagem tecnica resumida"] = detail
            elif not command_ok:
                row["Resultado final"] = RESULT_REGISTRY
                row["Mensagem tecnica resumida"] = "Login OK, mas comando seguro associado ao tipo nao foi confirmado."
                row["Recomendacao objetiva"] = "Revisar tipo de equipamento ou comando de leitura do perfil."
            elif not valid_script:
                row["Resultado final"] = RESULT_SCRIPT
                row["Mensagem tecnica resumida"] = script_msg
                row["Recomendacao objetiva"] = "Associar um script valido antes de liberar backup."
            else:
                row["Resultado final"] = RESULT_OK
                row["Mensagem tecnica resumida"] = f"{detail} Comando seguro confirmado. {script_msg}"
                row["Recomendacao objetiva"] = "Pronto para teste controlado de backup."
            rows.append(row)
        return rows
    except paramiko.AuthenticationException:
        return inaccessible_rows(devices, RESULT_JUMP, "Credencial do JumpHost recusada.", "Corrigir credencial do JumpHost.")
    except (socket.timeout, TimeoutError):
        return inaccessible_rows(devices, RESULT_TIMEOUT, "Timeout durante SSH/shell do JumpHost.", "Revisar disponibilidade do JumpHost.")
    except Exception as exc:
        return inaccessible_rows(devices, RESULT_JUMP, f"Falha no JumpHost: {clean_message(exc)}", "Revisar acesso SSH do JumpHost.")
    finally:
        if jump_client is not None:
            jump_client.close()


def system_rows(
    devices: list[Device],
    timeout: int,
    workers: int,
    execute: bool,
) -> list[dict[str, str]]:
    grouped: dict[str, list[Device]] = defaultdict(list)
    rows: list[dict[str, str]] = []
    for device in devices:
        if not getattr(device, "group", None) or not uses_jump_host(device.group, device=device):
            row = empty_row(device, "JumpHost do sistema")
            row["Resultado final"] = RESULT_INCONCLUSIVE
            row["Mensagem tecnica resumida"] = "Dispositivo nao usa JumpHost como caminho efetivo no cadastro atual."
            row["Recomendacao objetiva"] = "Comparar pelo caminho efetivo (direto/VPN) em rodada especifica."
            rows.append(row)
            continue
        grouped[str(device.group.id)].append(device)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = [
            executor.submit(validate_system_group, group_devices, timeout, execute)
            for group_devices in grouped.values()
        ]
        for future in as_completed(futures):
            rows.extend(future.result())
    rows.sort(key=lambda row: (row["Cliente/tenant"], row["Grupo"], row["Nome do dispositivo"]))
    return rows


def summarize(devices: list[Device], system: list[dict[str, str]], jumpserver: list[dict[str, str]], js_stats: dict[str, int]) -> dict[str, Any]:
    by_device_system = {row["Device ID"]: row["Resultado final"] for row in system}
    by_device_js = {row["Device ID"]: row["Resultado final"] for row in jumpserver}
    system_ok = {key for key, value in by_device_system.items() if value == RESULT_OK}
    js_ok = {key for key, value in by_device_js.items() if value == RESULT_OK}
    all_ids = {str(device.id) for device in devices}
    failures = Counter(
        row["Resultado final"]
        for row in system + jumpserver
        if row["Resultado final"] != RESULT_OK
    )
    return {
        "total_dispositivos_analisados": len(devices),
        "funcionam_pelo_jumpserver": len(js_ok),
        "funcionam_pelo_jumphost_sistema": len(system_ok),
        "funcionam_nos_dois": len(system_ok & js_ok),
        "apenas_jumpserver": len(js_ok - system_ok),
        "apenas_jumphost_sistema": len(system_ok - js_ok),
        "nao_confirmados_em_nenhum": len(all_ids - system_ok - js_ok),
        "jumpserver_inventario": js_stats,
        "principais_causas": dict(failures.most_common()),
        "limitacao_jumpserver": (
            "Testes ativos pelo JumpServer nao foram executados: exigiriam POST para criar "
            "sessao/tarefa e alterariam estado no JumpServer. As consultas GET autenticadas "
            "podem atualizar metadados de ultimo uso/auditoria da AccessKey."
        ),
    }


def write_reports(output_dir: Path, rows: list[dict[str, str]], summary: dict[str, Any]) -> tuple[Path, Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = output_dir / f"validacao_comparativa_{stamp}.csv"
    json_path = output_dir / f"resumo_validacao_{stamp}.json"
    md_path = output_dir / f"resumo_validacao_{stamp}.md"
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    causes = "\n".join(f"- `{key}`: {value}" for key, value in summary["principais_causas"].items())
    md_path.write_text(
        "# Validacao comparativa de acesso\n\n"
        f"- Total de dispositivos analisados: {summary['total_dispositivos_analisados']}\n"
        f"- OK pelo JumpServer: {summary['funcionam_pelo_jumpserver']}\n"
        f"- OK pelo JumpHost do sistema: {summary['funcionam_pelo_jumphost_sistema']}\n"
        f"- OK nos dois: {summary['funcionam_nos_dois']}\n"
        f"- Apenas JumpServer: {summary['apenas_jumpserver']}\n"
        f"- Apenas JumpHost do sistema: {summary['apenas_jumphost_sistema']}\n"
        f"- Nao confirmados em nenhum: {summary['nao_confirmados_em_nenhum']}\n\n"
        "## Principais causas\n\n"
        f"{causes or '- Nenhuma falha registrada.'}\n\n"
        "## Limite desta rodada\n\n"
        f"{summary['limitacao_jumpserver']}\n",
        encoding="utf-8",
    )
    return csv_path, json_path, md_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Valida caminhos JumpServer/JumpHost sem executar backup.")
    parser.add_argument("--output-dir", default="/app/reports/jump_access_validation")
    parser.add_argument("--timeout", type=int, default=6)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--only-configured-jumphost", action="store_true")
    parser.add_argument("--device-id", action="append", default=[])
    parser.add_argument("--execute-system-jumphost", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    apply_after_filter = bool(args.only_configured_jumphost or args.device_id)
    devices = load_devices(None if apply_after_filter else (args.limit or None))
    if args.device_id:
        selected_ids = {str(item).strip() for item in args.device_id if str(item).strip()}
        devices = [device for device in devices if str(device.id) in selected_ids]
    if args.only_configured_jumphost:
        devices = [
            device
            for device in devices
            if getattr(device, "group", None) and uses_jump_host(device.group, device=device)
        ]
    if apply_after_filter and args.limit:
        devices = devices[: args.limit]
    jms_url = os.getenv("JUMPSERVER_URL", "").strip()
    jms_key = os.getenv("JUMPSERVER_ACCESS_KEY_ID", "").strip()
    jms_secret = os.getenv("JUMPSERVER_ACCESS_KEY_SECRET", "").strip()
    jms_org = os.getenv("JUMPSERVER_ORG_ID", "00000000-0000-0000-0000-000000000002").strip()
    client = None
    jms_error = None
    if jms_url and jms_key and jms_secret:
        client = JumpServerReadOnlyClient(jms_url, jms_key, jms_secret, jms_org, args.timeout)
    else:
        jms_error = "Variaveis de acesso ao JumpServer nao fornecidas."

    jumpserver, js_stats, _ = jumpserver_rows(devices, client, jms_error)
    system = system_rows(devices, args.timeout, args.max_workers, args.execute_system_jumphost)
    summary = summarize(devices, system, jumpserver, js_stats)
    csv_path, json_path, md_path = write_reports(Path(args.output_dir), jumpserver + system, summary)
    print(f"Relatorio CSV: {csv_path}")
    print(f"Resumo JSON: {json_path}")
    print(f"Resumo Markdown: {md_path}")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
