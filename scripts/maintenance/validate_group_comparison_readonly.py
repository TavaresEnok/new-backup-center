#!/usr/bin/env python3
"""Match one JumpServer node to one BackupCenter group and validate read-only access."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import difflib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_jump_paths_readonly import (  # noqa: E402
    JumpServerReadOnlyClient,
    RESULT_OK,
    clean_message,
    load_devices,
    validate_system_group,
)


FIELDS = [
    "Grupo/area JumpServer",
    "Cliente/grupo BackupCenter",
    "JumpServer Asset ID",
    "BackupCenter Device ID",
    "Nome no JumpServer",
    "Nome no BackupCenter",
    "IP JumpServer",
    "IP BackupCenter",
    "Porta JumpServer",
    "Porta BackupCenter",
    "Protocolo JumpServer",
    "Protocolo BackupCenter",
    "Tipo JumpServer",
    "Tipo BackupCenter",
    "Gateway/zona JumpServer",
    "JumpHost BackupCenter",
    "Nivel de correspondencia",
    "Evidencia da correspondencia",
    "Resultado via JumpServer",
    "Resultado via BackupCenter via JumpHost",
    "JumpHost BackupCenter acessivel",
    "Login BackupCenter",
    "Comando seguro BackupCenter",
    "Diferenca encontrada",
    "Causa provavel",
    "Mensagem tecnica resumida",
    "Recomendacao objetiva",
]


def normalize(value: Any) -> str:
    text = str(value or "").lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def asset_ip(address: Any) -> str:
    value = str(address or "").strip()
    if "://" in value:
        value = value.split("://", 1)[1].split("/", 1)[0]
    if value.count(":") == 1 and value.rsplit(":", 1)[1].isdigit():
        return value.rsplit(":", 1)[0]
    return value


def asset_port(asset: dict[str, Any]) -> int | None:
    protocols = asset.get("protocols") or []
    preferred = ("ssh", "telnet", "winbox", "http", "https", "postgresql")
    for protocol in preferred:
        for value in protocols:
            if isinstance(value, dict) and str(value.get("name") or "").lower() == protocol:
                try:
                    return int(value.get("port"))
                except (TypeError, ValueError):
                    return None
    return None


def asset_protocol(asset: dict[str, Any]) -> str:
    protocols = asset.get("protocols") or []
    return ",".join(str(item.get("name") or "") for item in protocols if isinstance(item, dict))


def apparent_function(value: Any) -> str:
    text = normalize(value)
    checks = [
        ("zabbix", "zabbix"),
        ("olt", "olt"),
        ("switch", "switch"),
        (" sw ", "switch"),
        ("router", "router"),
        ("cgnat", "cgnat"),
        ("hillstone", "cgnat"),
        ("firewall", "firewall"),
        ("mikrotik", "mikrotik"),
        (" mk ", "mikrotik"),
        ("grafana", "grafana"),
        ("linux", "linux"),
        ("banco de dados", "database"),
        ("web", "web"),
    ]
    padded = f" {text} "
    for token, result in checks:
        if token in padded:
            return result
    return ""


def similarity(left: str, right: str) -> float:
    return difflib.SequenceMatcher(None, normalize(left), normalize(right)).ratio()


def backupcenter_protocol(device: Any) -> str:
    if not device:
        return ""
    return "telnet" if bool(getattr(device, "use_telnet", False)) else "ssh"


def score_pair(asset: dict[str, Any], device: Any, group_name: str) -> tuple[int, list[str], str]:
    a_ip = asset_ip(asset.get("address"))
    d_ip = str(device.ip_address or "").strip()
    a_port = asset_port(asset)
    d_port = int(device.port or (23 if device.use_telnet else 22))
    name_ratio = similarity(str(asset.get("name") or ""), str(device.name or ""))
    js_function = apparent_function(f"{asset.get('name')} {asset.get('type')}")
    bc_function = apparent_function(f"{device.name} {getattr(getattr(device, 'type', None), 'name', '')}")
    compatible_function = bool(js_function and js_function == bc_function)
    score = 0
    evidence: list[str] = []
    if a_ip and a_ip == d_ip:
        score += 70
        evidence.append("IP igual")
        if a_port is not None and a_port == d_port:
            score += 25
            evidence.append("porta igual")
        elif a_port is not None:
            evidence.append(f"porta divergente ({a_port}/{d_port})")
    if name_ratio >= 0.9:
        score += 20
        evidence.append("nome quase identico")
    elif name_ratio >= 0.65:
        score += 12
        evidence.append("nome semelhante")
    elif name_ratio >= 0.45:
        score += 5
    if compatible_function:
        score += 10
        evidence.append(f"funcao compativel ({js_function})")
    if normalize(group_name) in normalize(asset.get("name")):
        score += 5
        evidence.append("mesma area aparente")
    if a_ip == d_ip and a_port is not None and a_port == d_port:
        level = "MATCH_FORTE"
    elif a_ip == d_ip and (name_ratio >= 0.65 or (name_ratio >= 0.45 and compatible_function)):
        level = "MATCH_PROVAVEL"
    elif a_ip == d_ip:
        evidence.append("IP compartilhado sem evidencia suficiente de mesmo ativo")
        level = "SEM_MATCH"
    elif name_ratio >= 0.65 and compatible_function:
        level = "MATCH_FRACO"
    else:
        level = "SEM_MATCH"
    return score, evidence, level


def select_exact(values: list[dict[str, Any]], key: str, group_name: str) -> dict[str, Any] | None:
    wanted = normalize(group_name)
    exact = [item for item in values if normalize(item.get(key)) == wanted]
    return exact[0] if len(exact) == 1 else None


def api_pages(client: JumpServerReadOnlyClient, path_prefix: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    offset = 0
    while True:
        sep = "&" if "?" in path_prefix else "?"
        payload = client.get(f"{path_prefix}{sep}limit=250&offset={offset}")
        data = payload.get("data") or payload.get("results") or (payload if isinstance(payload, list) else [])
        rows.extend(data)
        count = int(payload.get("count") or len(rows)) if isinstance(payload, dict) else len(rows)
        if not data or len(rows) >= count:
            return rows
        offset += len(data)


def load_context(client: JumpServerReadOnlyClient, group_name: str) -> tuple[dict[str, Any], dict[str, Any] | None, list[dict[str, Any]], list[dict[str, Any]]]:
    nodes = client.list_all("nodes")
    zones = client.list_all("zones")
    node = select_exact(nodes, "value", group_name)
    if not node:
        raise RuntimeError(f"Node exato nao localizado no JumpServer: {group_name}.")
    zone = select_exact(zones, "name", group_name)
    assets = api_pages(client, f"/api/v1/assets/nodes/{node['id']}/assets/")
    gateways = []
    if zone:
        gateways = api_pages(client, f"/api/v1/assets/gateways/?zone={zone['id']}")
    return node, zone, assets, gateways


def load_backupcenter_group(group_name: str) -> list[Any]:
    wanted = normalize(group_name)
    return [
        device
        for device in load_devices()
        if getattr(device, "group", None) and normalize(device.group.name) == wanted
    ]


def reconcile(assets: list[dict[str, Any]], devices: list[Any], group_name: str) -> list[dict[str, Any]]:
    candidates = []
    for asset_index, asset in enumerate(assets):
        for device_index, device in enumerate(devices):
            score, evidence, level = score_pair(asset, device, group_name)
            candidates.append((score, asset_index, device_index, evidence, level))
    candidates.sort(key=lambda item: item[0], reverse=True)
    matched_assets: set[int] = set()
    matched_devices: set[int] = set()
    matched: list[dict[str, Any]] = []
    for score, asset_index, device_index, evidence, level in candidates:
        if level not in {"MATCH_FORTE", "MATCH_PROVAVEL", "MATCH_FRACO"}:
            continue
        if asset_index in matched_assets or device_index in matched_devices:
            continue
        matched_assets.add(asset_index)
        matched_devices.add(device_index)
        matched.append(
            {
                "asset": assets[asset_index],
                "device": devices[device_index],
                "score": score,
                "evidence": evidence,
                "level": level,
            }
        )
    for index, asset in enumerate(assets):
        if index not in matched_assets:
            matched.append({"asset": asset, "device": None, "score": 0, "evidence": [], "level": "SEM_MATCH"})
    for index, device in enumerate(devices):
        if index not in matched_devices:
            matched.append({"asset": None, "device": device, "score": 0, "evidence": [], "level": "SEM_MATCH"})
    return matched


def evaluate_difference(js_result: str, bc_result: str, comparable: bool) -> str:
    if not comparable:
        return "Nao comparavel por falta de match confiavel"
    if js_result == "PENDENTE_VALIDACAO_AUDITADA":
        return "JumpServer pendente; resultado BackupCenter disponivel"
    if js_result == "NAO_APLICAVEL_PROTOCOLO":
        return "JumpServer nao comparavel por protocolo; resultado BackupCenter disponivel"
    if js_result == RESULT_OK and bc_result == RESULT_OK:
        return "Funciona nos dois"
    if js_result == RESULT_OK:
        return "Funciona so no JumpServer"
    if bc_result == RESULT_OK:
        return "Funciona so no BackupCenter"
    return "Nao funciona em nenhum"


def probable_cause(match: dict[str, Any], bc_result: str, js_result: str) -> str:
    if match["level"] == "SEM_MATCH":
        return "cadastro inexistente no BackupCenter" if match["asset"] else "cadastro inexistente no JumpServer"
    if match["level"] == "MATCH_FRACO":
        return "IP divergente"
    js_protocols = set(asset_protocol(match.get("asset") or {}).split(","))
    bc_protocol = backupcenter_protocol(match.get("device"))
    if js_protocols.intersection({"ssh", "telnet"}) and bc_protocol not in js_protocols:
        return "protocolo divergente SSH/Telnet"
    evidence = " ".join(match["evidence"]).lower()
    if "porta divergente" in evidence:
        return "porta divergente"
    mapping = {
        "Falha de JumpHost": "problema no JumpHost do BackupCenter",
        "Porta fechada": "porta divergente ou rota/firewall",
        "Falha de credencial": "credencial divergente",
        "Timeout": "problema no JumpHost do BackupCenter",
        "Cadastro inconsistente": "cadastro inconsistente ou comando seguro nao confirmado",
        "Inconclusivo": "inconclusivo",
    }
    if js_result == "PENDENTE_VALIDACAO_AUDITADA" and bc_result == RESULT_OK:
        return "validacao JumpServer pendente"
    if js_result == "NAO_APLICAVEL_PROTOCOLO":
        return "protocolo divergente SSH/Telnet"
    return mapping.get(bc_result, "inconclusivo")


def make_row(
    match: dict[str, Any],
    group_name: str,
    gateway_note: str,
    bc_probe: dict[str, str] | None,
    bc_execution_enabled: bool,
) -> dict[str, str]:
    asset = match.get("asset") or {}
    device = match.get("device")
    comparable = match["level"] in {"MATCH_FORTE", "MATCH_PROVAVEL"}
    cli_protocol = any(protocol in {"ssh", "telnet"} for protocol in asset_protocol(asset).split(","))
    if comparable and cli_protocol:
        js_result = "PENDENTE_VALIDACAO_AUDITADA"
    elif comparable:
        js_result = "NAO_APLICAVEL_PROTOCOLO"
    else:
        js_result = "NAO_TESTADO_SEM_MATCH"
    if bc_probe:
        bc_result = bc_probe["Resultado final"]
    elif comparable and not bc_execution_enabled:
        bc_result = "PENDENTE_EXECUCAO"
    else:
        bc_result = "NAO_TESTADO_SEM_MATCH"
    bc_group = str(getattr(getattr(device, "group", None), "name", "") or "") if device else ""
    bc_type = str(getattr(getattr(device, "type", None), "name", "") or "") if device else ""
    jump_host = str(getattr(getattr(device, "group", None), "jump_host", "") or "") if device else ""
    evidence = ", ".join(match["evidence"]) if match["evidence"] else "Nenhuma evidencia confiavel."
    message = (
        bc_probe["Mensagem tecnica resumida"]
        if bc_probe
        else "Teste de acesso nao executado sem correspondencia forte ou provavel."
    )
    if comparable and cli_protocol:
        message = (
            f"{message} JumpServer: teste ativo separado pendente, pois requer sessao/tarefa auditada."
        )
    elif comparable:
        message = (
            f"{message} JumpServer: protocolo publicado ({asset_protocol(asset)}) "
            "nao suporta comando CLI seguro nesta etapa."
        )
    recommendation = (
        bc_probe["Recomendacao objetiva"]
        if bc_probe
        else "Reconciliar cadastro antes de testar acesso."
    )
    return {
        "Grupo/area JumpServer": group_name,
        "Cliente/grupo BackupCenter": bc_group,
        "JumpServer Asset ID": str(asset.get("id") or ""),
        "BackupCenter Device ID": str(getattr(device, "id", "") or ""),
        "Nome no JumpServer": str(asset.get("name") or ""),
        "Nome no BackupCenter": str(getattr(device, "name", "") or ""),
        "IP JumpServer": asset_ip(asset.get("address")),
        "IP BackupCenter": str(getattr(device, "ip_address", "") or ""),
        "Porta JumpServer": str(asset_port(asset) or ""),
        "Porta BackupCenter": str(getattr(device, "port", "") or ""),
        "Protocolo JumpServer": asset_protocol(asset),
        "Protocolo BackupCenter": backupcenter_protocol(device),
        "Tipo JumpServer": f"{asset.get('type') or ''} ({asset_protocol(asset)})",
        "Tipo BackupCenter": bc_type,
        "Gateway/zona JumpServer": gateway_note,
        "JumpHost BackupCenter": jump_host,
        "Nivel de correspondencia": match["level"],
        "Evidencia da correspondencia": evidence,
        "Resultado via JumpServer": js_result,
        "Resultado via BackupCenter via JumpHost": bc_result,
        "JumpHost BackupCenter acessivel": bc_probe["JumpHost acessivel"] if bc_probe else "nao aplicavel",
        "Login BackupCenter": bc_probe["Login no dispositivo"] if bc_probe else "nao aplicavel",
        "Comando seguro BackupCenter": bc_probe["Comando seguro executado"] if bc_probe else "nao aplicavel",
        "Diferenca encontrada": evaluate_difference(js_result, bc_result, comparable),
        "Causa provavel": probable_cause(match, bc_result, js_result),
        "Mensagem tecnica resumida": clean_message(message),
        "Recomendacao objetiva": recommendation,
    }


def write_output(output_dir: Path, group_name: str, rows: list[dict[str, str]], summary: dict[str, Any]) -> tuple[Path, Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = re.sub(r"[^a-z0-9]+", "_", normalize(group_name)).strip("_")
    csv_path = output_dir / f"{slug}_comparativo_{stamp}.csv"
    json_path = output_dir / f"{slug}_resumo_{stamp}.json"
    md_path = output_dir / f"{slug}_resumo_{stamp}.md"
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    counts = summary["resultados_backupcenter"]
    md_path.write_text(
        f"# Validacao por area - {group_name}\n\n"
        f"- Ativos no JumpServer: {summary['total_ativos_jumpserver']}\n"
        f"- Dispositivos no BackupCenter: {summary['total_dispositivos_backupcenter']}\n"
        f"- Match forte: {summary['match_forte']}\n"
        f"- Match provavel: {summary['match_provavel']}\n"
        f"- Match fraco: {summary['match_fraco']}\n"
        f"- Ativos JumpServer sem match confiavel no BackupCenter: {summary['sem_match']}\n"
        f"- Cadastros BackupCenter sem ativo reconciliado no JumpServer: {summary['cadastros_backupcenter_sem_ativo_jumpserver']}\n"
        f"- OK pelo BackupCenter via JumpHost forcado: {counts.get('OK', 0)}\n\n"
        "## Resultado JumpServer\n\n"
        "A zona e o gateway foram identificados por consulta GET. O login/comando no ativo "
        "nao foi executado nesta rodada porque o JumpServer exige criar sessao ou tarefa "
        "auditada, operacao que altera estado e depende de autorizacao separada.\n\n"
        "## Falhas BackupCenter\n\n"
        + "\n".join(f"- {name}: {value}" for name, value in counts.items() if name != "OK")
        + "\n",
        encoding="utf-8",
    )
    return csv_path, json_path, md_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compara uma area JumpServer com um grupo BackupCenter.")
    parser.add_argument("--group-name", required=True)
    parser.add_argument("--output-dir", default="/app/reports/jump_group_validation")
    parser.add_argument("--timeout", type=int, default=6)
    parser.add_argument("--execute-backupcenter-jumphost", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = JumpServerReadOnlyClient(
        os.environ["JUMPSERVER_URL"],
        os.environ["JUMPSERVER_ACCESS_KEY_ID"],
        os.environ["JUMPSERVER_ACCESS_KEY_SECRET"],
        os.getenv("JUMPSERVER_ORG_ID", "00000000-0000-0000-0000-000000000002"),
        args.timeout,
    )
    node, zone, assets, gateways = load_context(client, args.group_name)
    devices = load_backupcenter_group(args.group_name)
    matched = reconcile(assets, devices, args.group_name)
    trusted = [entry for entry in matched if entry["level"] in {"MATCH_FORTE", "MATCH_PROVAVEL"} and entry["device"]]
    probes: dict[str, dict[str, str]] = {}
    if args.execute_backupcenter_jumphost:
        for entry in trusted:
            device = entry["device"]
            result = validate_system_group([device], args.timeout, True, force_jump_host=True)[0]
            probes[str(device.id)] = result
    gateway_note = (
        ", ".join(
            f"{item.get('name')} {item.get('address')}:{asset_port(item) or ''}"
            for item in gateways
        )
        if gateways
        else f"Zona {zone.get('name') if zone else 'nao localizada'} sem gateway listado"
    )
    rows = [
        make_row(
            entry,
            args.group_name,
            gateway_note,
            probes.get(str(entry["device"].id)) if entry.get("device") else None,
            args.execute_backupcenter_jumphost,
        )
        for entry in matched
    ]
    rows.sort(key=lambda item: (item["Nivel de correspondencia"], item["Nome no JumpServer"], item["Nome no BackupCenter"]))
    match_counts = Counter(entry["level"] for entry in matched if entry.get("asset"))
    bc_counts = Counter(row["Resultado via BackupCenter via JumpHost"] for row in rows if row["Nivel de correspondencia"] in {"MATCH_FORTE", "MATCH_PROVAVEL"})
    summary = {
        "grupo_area": args.group_name,
        "jumpserver_node_id": str(node.get("id") or ""),
        "jumpserver_zone_id": str(zone.get("id") or "") if zone else "",
        "gateway_zona": gateway_note,
        "total_ativos_jumpserver": len(assets),
        "total_dispositivos_backupcenter": len(devices),
        "match_forte": match_counts.get("MATCH_FORTE", 0),
        "match_provavel": match_counts.get("MATCH_PROVAVEL", 0),
        "match_fraco": match_counts.get("MATCH_FRACO", 0),
        "sem_match": match_counts.get("SEM_MATCH", 0),
        "cadastros_backupcenter_sem_ativo_jumpserver": sum(1 for entry in matched if entry.get("asset") is None),
        "resultados_backupcenter": dict(bc_counts),
        "resultado_jumpserver": "PENDENTE_VALIDACAO_AUDITADA",
        "observacao_jumpserver": (
            "GET de inventario executado. Teste ativo nao executado porque requer criacao "
            "de sessao/tarefa auditada no JumpServer."
        ),
    }
    paths = write_output(Path(args.output_dir), args.group_name, rows, summary)
    print(json.dumps(summary, ensure_ascii=False))
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
