#!/usr/bin/env python3
"""Diagnostico somente leitura de SSH/Telnet via JumpHost cadastrado por grupo.

O script nao executa backup e nao persiste alteracoes. Para cada dispositivo
na porta cadastrada, testa primeiro o protocolo configurado e, quando esse
teste nao confirma acesso, tenta o protocolo alternativo para localizar
divergencias de cadastro.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import logging
import socket
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import paramiko

from app.core.security import decrypt_password
from app.services.connection_test_service import ConnectionTestService
from validate_jump_paths_readonly import (
    clean_message,
    configured_group_jump_host,
    load_devices,
    probe_ping,
    probe_ssh_device,
    probe_tcp,
    probe_telnet_device,
    remote_exec,
    script_status,
    target_address,
    tri,
)

logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

FIELDS = [
    "Grupo",
    "Device ID",
    "Nome do dispositivo",
    "IP",
    "Porta cadastrada",
    "Tipo de equipamento",
    "Script associado",
    "Protocolo cadastrado",
    "JumpHost acessivel",
    "Ping via JumpHost",
    "Porta acessivel via JumpHost",
    "Teste protocolo cadastrado",
    "Teste protocolo alternativo",
    "Protocolo confirmado",
    "Login confirmado",
    "Comando seguro confirmado",
    "Resultado final",
    "Mensagem resumida",
    "Recomendacao",
]


def normalize(value: Any) -> str:
    return str(value or "").strip().casefold()


def protocol_for(device: Any) -> str:
    return "telnet" if bool(getattr(device, "use_telnet", False)) else "ssh"


def run_protocol(
    helper: ConnectionTestService,
    jump_client: paramiko.SSHClient,
    device: Any,
    password: str,
    protocol: str,
    timeout: int,
) -> tuple[bool, bool, str]:
    original = bool(device.use_telnet)
    device.use_telnet = protocol == "telnet"
    try:
        if protocol == "telnet":
            return probe_telnet_device(helper, jump_client, device, password, timeout)
        return probe_ssh_device(helper, jump_client, device, password, timeout)
    except TimeoutError as exc:
        return False, False, clean_message(exc)
    finally:
        device.use_telnet = original


def describe_attempt(protocol: str, result: tuple[bool, bool, str] | None) -> str:
    if result is None:
        return "nao executado"
    login_ok, command_ok, detail = result
    if login_ok and command_ok:
        return f"{protocol}: login e comando seguro confirmados"
    if login_ok:
        return f"{protocol}: login confirmado, comando seguro nao confirmado"
    return f"{protocol}: {clean_message(detail)}"


def row_base(device: Any) -> dict[str, str]:
    dtype = getattr(device, "type", None)
    return {
        "Grupo": str(getattr(getattr(device, "group", None), "name", "") or ""),
        "Device ID": str(device.id),
        "Nome do dispositivo": str(device.name or ""),
        "IP": str(device.ip_address or ""),
        "Porta cadastrada": str(device.port or (23 if device.use_telnet else 22)),
        "Tipo de equipamento": str(getattr(dtype, "name", "") or ""),
        "Script associado": str(getattr(dtype, "script_name", "") or ""),
        "Protocolo cadastrado": protocol_for(device),
        "JumpHost acessivel": "sim",
        "Ping via JumpHost": "nao aplicavel",
        "Porta acessivel via JumpHost": "nao aplicavel",
        "Teste protocolo cadastrado": "nao executado",
        "Teste protocolo alternativo": "nao executado",
        "Protocolo confirmado": "nenhum",
        "Login confirmado": "nao",
        "Comando seguro confirmado": "nao",
        "Resultado final": "Inconclusivo",
        "Mensagem resumida": "",
        "Recomendacao": "",
    }


def inaccessible_rows(devices: list[Any], message: str) -> list[dict[str, str]]:
    rows = []
    for device in devices:
        row = row_base(device)
        row["JumpHost acessivel"] = "nao"
        row["Resultado final"] = "Falha de JumpHost"
        row["Mensagem resumida"] = clean_message(message)
        row["Recomendacao"] = "Revisar acesso SSH ao JumpHost cadastrado."
        rows.append(row)
    return rows


def probe_devices(group_name: str, timeout: int) -> tuple[list[dict[str, str]], str]:
    devices = [
        device for device in load_devices()
        if getattr(device, "group", None) and normalize(device.group.name) == normalize(group_name)
    ]
    if not devices:
        raise RuntimeError(f"Nenhum dispositivo ativo localizado no grupo {group_name}.")

    helper = ConnectionTestService()
    jump = configured_group_jump_host(helper, devices[0], force=True)
    if not jump:
        return inaccessible_rows(devices, "JumpHost cadastrado sem host, usuario ou credencial utilizavel."), ""

    jump_note = f"{jump['host']}:{int(jump.get('port') or 22)}"
    try:
        socket.create_connection((jump["host"], int(jump.get("port") or 22)), timeout=timeout).close()
    except Exception as exc:
        return inaccessible_rows(devices, f"TCP do JumpHost falhou: {clean_message(exc)}"), jump_note

    jump_client = None
    try:
        jump_client = helper._open_jump_client(jump, timeout)
        status, output = remote_exec(jump_client, "hostname; whoami; echo __JUMP_OK__", timeout)
        if status != 0 or "__JUMP_OK__" not in output:
            return inaccessible_rows(devices, "SSH autenticou, mas shell seguro do JumpHost nao respondeu."), jump_note

        rows: list[dict[str, str]] = []
        for device in devices:
            row = row_base(device)
            destination = target_address(device)
            if not destination:
                row["Resultado final"] = "Cadastro inconsistente"
                row["Mensagem resumida"] = "IP ou porta invalido no cadastro."
                row["Recomendacao"] = "Corrigir IP/porta cadastrados."
                rows.append(row)
                continue
            address, port = destination
            try:
                row["Ping via JumpHost"] = tri(probe_ping(jump_client, address, timeout))
            except Exception:
                row["Ping via JumpHost"] = "nao aplicavel"
            try:
                tcp_ok = probe_tcp(jump_client, address, port, timeout)
            except Exception as exc:
                tcp_ok = False
                row["Mensagem resumida"] = f"Teste TCP falhou: {clean_message(exc)}"
            row["Porta acessivel via JumpHost"] = tri(tcp_ok)
            if tcp_ok is not True:
                row["Resultado final"] = "Porta fechada" if tcp_ok is False else "Inconclusivo"
                if not row["Mensagem resumida"]:
                    row["Mensagem resumida"] = "Porta cadastrada nao respondeu a partir do JumpHost."
                row["Recomendacao"] = "Confirmar porta cadastrada e liberacao de rota/firewall."
                rows.append(row)
                continue

            configured = protocol_for(device)
            alternative = "telnet" if configured == "ssh" else "ssh"
            password = decrypt_password(device.password_encrypted)
            try:
                first = run_protocol(helper, jump_client, device, password, configured, timeout)
                row["Teste protocolo cadastrado"] = describe_attempt(configured, first)
                confirmed = configured if first[0] else ""
                command_ok = first[1] if first[0] else False
                second = None
                if not confirmed:
                    second = run_protocol(helper, jump_client, device, password, alternative, timeout)
                    row["Teste protocolo alternativo"] = describe_attempt(alternative, second)
                    if second[0]:
                        confirmed = alternative
                        command_ok = second[1]
                row["Protocolo confirmado"] = confirmed or "nenhum"
                row["Login confirmado"] = tri(bool(confirmed))
                row["Comando seguro confirmado"] = tri(command_ok if confirmed else None)
                valid_script, script_msg = script_status(device)
                if confirmed == alternative:
                    row["Resultado final"] = "Acessivel por protocolo alternativo"
                    row["Mensagem resumida"] = (
                        f"Login confirmado por {alternative}; cadastro indica {configured}."
                    )
                    row["Recomendacao"] = "Revisar protocolo cadastrado antes de liberar backup."
                elif confirmed and command_ok and valid_script:
                    row["Resultado final"] = "OK"
                    row["Mensagem resumida"] = f"Acesso {configured} e comando seguro confirmados. {script_msg}"
                    row["Recomendacao"] = "Pronto para teste controlado de backup."
                elif confirmed and not command_ok:
                    row["Resultado final"] = "Login OK, comando nao confirmado"
                    row["Mensagem resumida"] = "Login confirmado, mas comando seguro do tipo nao respondeu como esperado."
                    row["Recomendacao"] = "Revisar comando seguro/perfil do tipo de equipamento."
                elif confirmed and not valid_script:
                    row["Resultado final"] = "Script ausente"
                    row["Mensagem resumida"] = script_msg
                    row["Recomendacao"] = "Associar script valido antes de liberar backup."
                elif "credencial" in first[2].lower() or (second and "credencial" in second[2].lower()):
                    row["Resultado final"] = "Falha de credencial"
                    row["Mensagem resumida"] = "Porta respondeu, mas as credenciais nao foram aceitas."
                    row["Recomendacao"] = "Conferir credencial cadastrada sem expor seu conteudo."
                else:
                    row["Resultado final"] = "Inconclusivo"
                    row["Mensagem resumida"] = "Porta respondeu, mas SSH e Telnet nao confirmaram login seguro."
                    row["Recomendacao"] = "Confirmar protocolo, prompt ou algoritmo legado do equipamento."
            finally:
                password = ""
            rows.append(row)
        return rows, jump_note
    except paramiko.AuthenticationException:
        return inaccessible_rows(devices, "Credencial do JumpHost recusada."), jump_note
    except Exception as exc:
        return inaccessible_rows(devices, f"Falha durante acesso ao JumpHost: {clean_message(exc)}"), jump_note
    finally:
        if jump_client is not None:
            jump_client.close()


def write_outputs(output_dir: Path, group_name: str, jump_note: str, rows: list[dict[str, str]]) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = "_".join(group_name.lower().split())
    csv_path = output_dir / f"{slug}_protocolos_jumphost_{stamp}.csv"
    md_path = output_dir / f"{slug}_protocolos_jumphost_{stamp}.md"
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    counts = Counter(row["Resultado final"] for row in rows)
    accessible = [row for row in rows if row["Resultado final"] in {"OK", "Acessivel por protocolo alternativo"}]
    text = [
        f"# Diagnostico SSH/Telnet via JumpHost - {group_name}",
        "",
        f"- JumpHost cadastrado utilizado: {jump_note}",
        f"- Dispositivos analisados: {len(rows)}",
        f"- Acessiveis com comando seguro: {len(accessible)}",
        "",
        "## Resultados",
        "",
    ]
    text.extend(f"- {name}: {value}" for name, value in sorted(counts.items()))
    text.extend(["", "## Acessiveis", ""])
    text.extend(f"- {row['Nome do dispositivo']}: {row['Protocolo confirmado']}" for row in accessible)
    md_path.write_text("\n".join(text) + "\n", encoding="utf-8")
    return csv_path, md_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--group-name", required=True)
    parser.add_argument("--timeout", type=int, default=6)
    parser.add_argument("--output-dir", default="/app/reports/jump_group_validation")
    args = parser.parse_args()
    rows, jump_note = probe_devices(args.group_name, args.timeout)
    paths = write_outputs(Path(args.output_dir), args.group_name, jump_note, rows)
    print(json.dumps({"grupo": args.group_name, "jump_host": jump_note, "total": len(rows), "resultados": dict(Counter(row["Resultado final"] for row in rows))}, ensure_ascii=False))
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
