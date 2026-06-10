#!/usr/bin/env python3
"""Dispara e acompanha teste de conectividade nativo do JumpServer por node.

Esta rotina usa a API do JumpServer para criar uma tarefa auditada de
"Test assets connectivity" no node informado. Ela nao executa comandos
customizados nem altera dispositivos, mas cria tarefa no JumpServer e atualiza
o campo connectivity/date_verified dos ativos conforme o proprio JumpServer.
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

FIELDS = [
    "Grupo/area JumpServer",
    "JumpServer Asset ID",
    "Nome do ativo",
    "Endereco",
    "Porta",
    "Protocolo",
    "Tipo/plataforma",
    "Connectivity antes",
    "Connectivity depois",
    "Date verified antes",
    "Date verified depois",
    "Resultado final",
    "Mensagem resumida",
]


def clean_message(message: Any, limit: int = 260) -> str:
    value = str(message or "").replace("\r", " ").replace("\n", " ")
    value = re.sub(
        r"(?i)\b(password|passwd|secret|token|authorization|key)\b\s*[:=]\s*\S+",
        r"\1=***",
        value,
    )
    value = re.sub(r"\s+", " ", value).strip()
    return value[:limit]


def normalize(value: Any) -> str:
    text = str(value or "").lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def select_exact(values: list[dict[str, Any]], key: str, group_name: str) -> dict[str, Any] | None:
    wanted = normalize(group_name)
    exact = [item for item in values if normalize(item.get(key)) == wanted]
    return exact[0] if len(exact) == 1 else None


def asset_port(asset: dict[str, Any]) -> int | None:
    for key in ("port", "login_port"):
        value = asset.get(key)
        if value:
            try:
                return int(value)
            except (TypeError, ValueError):
                pass
    for protocol in asset.get("protocols") or []:
        if isinstance(protocol, dict):
            value = protocol.get("port")
            if value:
                try:
                    return int(value)
                except (TypeError, ValueError):
                    pass
    address = str(asset.get("address") or "")
    if ":" in address:
        maybe = address.rsplit(":", 1)[-1]
        if maybe.isdigit():
            return int(maybe)
    return None


class JumpServerClient:
    def __init__(self, base_url: str, key_id: str, secret: str, org_id: str, timeout: int):
        self.base_url = base_url.rstrip("/")
        self.key_id = key_id
        self.secret = secret
        self.org_id = org_id
        self.timeout = timeout

    def _headers(self, method: str, path: str, body: bytes | None = None) -> dict[str, str]:
        method = method.lower()
        date = dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        accept = "application/json"
        lines = [f"(request-target): {method} {path}", f"accept: {accept}", f"date: {date}"]
        headers = {
            "Accept": accept,
            "Date": date,
            "X-JMS-ORG": self.org_id,
        }
        if body is not None:
            digest = "SHA-256=" + base64.b64encode(hashlib.sha256(body).digest()).decode()
            lines.append(f"digest: {digest}")
            headers["Digest"] = digest
            headers["Content-Type"] = "application/json"
            signed_headers = "(request-target) accept date digest"
        else:
            signed_headers = "(request-target) accept date"
        signed = "\n".join(lines)
        signature = base64.b64encode(hmac.new(self.secret.encode(), signed.encode(), hashlib.sha256).digest()).decode()
        headers["Authorization"] = (
            f'Signature keyId="{self.key_id}",algorithm="hmac-sha256",'
            f'headers="{signed_headers}",signature="{signature}"'
        )
        return headers

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers=self._headers(method, path, body),
            method=method.upper(),
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = clean_message(exc.read().decode("utf-8", "replace"))
            raise RuntimeError(f"JumpServer {method.upper()} falhou (HTTP {exc.code}): {detail}") from exc

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        return self.request("POST", path, payload)

    def list_all(self, resource: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        offset = 0
        while True:
            query = urllib.parse.urlencode({"limit": 250, "offset": offset})
            payload = self.get(f"/api/v1/assets/{resource}/?{query}")
            page = payload.get("data") or payload.get("results") or (payload if isinstance(payload, list) else [])
            count = int(payload.get("count") or len(rows) + len(page)) if isinstance(payload, dict) else len(page)
            rows.extend(page)
            if not page or len(rows) >= count:
                return rows
            offset += len(page)


def api_pages(client: JumpServerClient, path_prefix: str) -> list[dict[str, Any]]:
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


def protocol(asset: dict[str, Any]) -> str:
    protocols = asset.get("protocols") or []
    names = []
    for item in protocols:
        if isinstance(item, dict):
            name = item.get("name") or item.get("value")
            if name:
                names.append(str(name))
    if names:
        return ",".join(sorted(set(names)))
    return str(asset.get("protocol") or "")


def connectivity(asset: dict[str, Any]) -> str:
    value = asset.get("connectivity")
    if isinstance(value, dict):
        return str(value.get("value") or value.get("label") or "")
    return str(value or "")


def verified(asset: dict[str, Any]) -> str:
    return str(asset.get("date_verified") or asset.get("date_verified_display") or "")


def asset_map(assets: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(asset.get("id")): asset for asset in assets}


def result_from_connectivity(value: str) -> str:
    low = normalize(value)
    if low in {"ok", "success", "connected"}:
        return "OK"
    if low in {"err", "error", "failed", "fail"}:
        return "Falha"
    if low in {"", "-", "unknown", "none", "null"}:
        return "Inconclusivo"
    return value or "Inconclusivo"


def write_outputs(output_dir: Path, group_name: str, rows: list[dict[str, str]], summary: dict[str, Any]) -> tuple[Path, Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = re.sub(r"[^a-z0-9]+", "_", normalize(group_name)).strip("_")
    csv_path = output_dir / f"{slug}_jumpserver_api_connectivity_{stamp}.csv"
    json_path = output_dir / f"{slug}_jumpserver_api_connectivity_{stamp}.json"
    md_path = output_dir / f"{slug}_jumpserver_api_connectivity_{stamp}.md"
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    counts = Counter(row["Resultado final"] for row in rows)
    lines = [
        f"# Teste via API JumpServer - {group_name}",
        "",
        f"- Ativos analisados: {len(rows)}",
        f"- Task auditada: {summary.get('task_id', '')}",
        "",
        "## Resultado",
        "",
    ]
    lines.extend(f"- {name}: {value}" for name, value in sorted(counts.items()))
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return csv_path, json_path, md_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--group-name", required=True)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--poll-seconds", type=int, default=180)
    parser.add_argument("--output-dir", default="/app/reports/jump_group_validation")
    parser.add_argument("--existing-task-id", default="")
    args = parser.parse_args()

    client = JumpServerClient(
        os.environ["JUMPSERVER_URL"],
        os.environ["JUMPSERVER_ACCESS_KEY_ID"],
        os.environ["JUMPSERVER_ACCESS_KEY_SECRET"],
        os.getenv("JUMPSERVER_ORG_ID", "00000000-0000-0000-0000-000000000002"),
        args.timeout,
    )

    nodes = client.list_all("nodes")
    node = select_exact(nodes, "value", args.group_name)
    if not node:
        raise RuntimeError(f"Node exato nao encontrado: {args.group_name}")
    node_id = str(node["id"])
    before_assets = api_pages(client, f"/api/v1/assets/nodes/{node_id}/assets/")
    before = asset_map(before_assets)

    if args.existing_task_id:
        task_id = args.existing_task_id
    else:
        created = client.post(f"/api/v1/assets/nodes/{node_id}/tasks/", {"action": "test"})
        task_id = str(created.get("task") or "")

    deadline = time.monotonic() + args.poll_seconds
    after_assets = before_assets
    while time.monotonic() < deadline:
        if task_id:
            try:
                task = client.get(f"/api/v1/ops/task-executions/{task_id}/")
                if task.get("is_finished"):
                    after_assets = api_pages(client, f"/api/v1/assets/nodes/{node_id}/assets/")
                    break
            except Exception:
                pass
        time.sleep(10)
        current = api_pages(client, f"/api/v1/assets/nodes/{node_id}/assets/")
        current_map = asset_map(current)
        changed = sum(
            1
            for asset_id, asset in current_map.items()
            if verified(asset) and verified(asset) != verified(before.get(asset_id, {}))
        )
        after_assets = current
        if changed >= len(before_assets):
            break

    after = asset_map(after_assets)
    rows: list[dict[str, str]] = []
    for asset in before_assets:
        asset_id = str(asset.get("id"))
        now = after.get(asset_id, asset)
        conn_before = connectivity(asset)
        conn_after = connectivity(now)
        result = result_from_connectivity(conn_after)
        rows.append(
            {
                "Grupo/area JumpServer": args.group_name,
                "JumpServer Asset ID": asset_id,
                "Nome do ativo": str(asset.get("name") or ""),
                "Endereco": str(asset.get("address") or ""),
                "Porta": str(asset_port(asset) or ""),
                "Protocolo": protocol(asset),
                "Tipo/plataforma": str(asset.get("type") or asset.get("platform") or ""),
                "Connectivity antes": conn_before,
                "Connectivity depois": conn_after,
                "Date verified antes": verified(asset),
                "Date verified depois": verified(now),
                "Resultado final": result,
                "Mensagem resumida": (
                    "Conectividade retornada pelo teste nativo do JumpServer."
                    if verified(now) != verified(asset)
                    else "Sem mudanca visivel em date_verified dentro da janela de polling."
                ),
            }
        )

    counts = Counter(row["Resultado final"] for row in rows)
    summary = {
        "grupo_area": args.group_name,
        "node_id": node_id,
        "task_id": task_id,
        "total_ativos": len(rows),
        "resultados": dict(counts),
        "observacao": "Teste criado via API nativa do JumpServer; atualiza connectivity/date_verified dos ativos.",
    }
    paths = write_outputs(Path(args.output_dir), args.group_name, rows, summary)
    print(json.dumps(summary, ensure_ascii=False))
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
