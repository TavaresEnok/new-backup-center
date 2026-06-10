#!/usr/bin/env python3
"""Monitor Backup Center tenant realtime logs and write an incremental Markdown report."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, build_opener


FINAL_RE = re.compile(r"Finalizado\.\s*Sucesso:\s*(\d+)\s*\|\s*Falhas:\s*(\d+)", re.I)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_session_cookie(cookie_file: Path) -> str:
    for line in cookie_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 7 and parts[5] == "session":
            return parts[6].strip()
    raise RuntimeError(f"session cookie not found in {cookie_file}")


def get_json(opener, url: str, session_cookie: str, timeout: int = 20) -> dict:
    req = Request(
        url,
        headers={
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Cookie": f"session={session_cookie}",
        },
    )
    with opener.open(req, timeout=timeout) as response:
        body = response.read().decode("utf-8")
        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type.lower():
            raise ValueError(f"non-json response content_type={content_type!r} body_prefix={body[:120]!r}")
        return json.loads(body)


def log_url(base_url: str, tenant_slug: str, after: int) -> str:
    qs = urlencode({"after": str(after)})
    return f"{base_url.rstrip('/')}/tenant/{tenant_slug}/backups/logs/global?{qs}"


def task_status_url(base_url: str, tenant_slug: str, task_id: str) -> str:
    return f"{base_url.rstrip('/')}/tenant/{tenant_slug}/backups/tasks/{task_id}/status"


def fmt_entry(entry: dict) -> str:
    seq = int(entry.get("global_seq") or 0)
    ts = entry.get("timestamp_iso") or entry.get("timestamp") or ""
    level = str(entry.get("level") or "info").upper()
    device = str(entry.get("device_name") or "Sistema").replace("\n", " ").strip()
    task_id = str(entry.get("task_id") or "").strip()
    msg = str(entry.get("message") or "").replace("\n", " ").strip()
    return f"| {seq} | {ts} | {level} | {device} | `{task_id}` | {msg} |"


def write_report(
    report_path: Path,
    *,
    tenant_slug: str,
    started_at: str,
    last_update: str,
    last_seq: int,
    entries: list[dict],
    task_status: dict[str, dict],
    quiet_seconds: int,
    completed: bool,
) -> None:
    counts = Counter(str(e.get("level") or "info").lower() for e in entries)
    task_ids = sorted({str(e.get("task_id") or "") for e in entries if e.get("task_id")})
    by_device = Counter(str(e.get("device_name") or "Sistema") for e in entries)
    errors = [e for e in entries if str(e.get("level") or "").lower() == "error"]
    warnings = [e for e in entries if str(e.get("level") or "").lower() == "warning"]
    final_totals = defaultdict(lambda: {"success": 0, "failed": 0})
    for e in entries:
        match = FINAL_RE.search(str(e.get("message") or ""))
        if match:
            final_totals[str(e.get("task_id") or "")]["success"] += int(match.group(1))
            final_totals[str(e.get("task_id") or "")]["failed"] += int(match.group(2))

    status_counts = Counter(str(v.get("status") or v.get("celery_state") or "unknown") for v in task_status.values())

    lines: list[str] = []
    lines.append("# Backup em massa - acompanhamento")
    lines.append("")
    lines.append(f"- Tenant: `{tenant_slug}`")
    lines.append(f"- Inicio do monitor: {started_at}")
    lines.append(f"- Ultima atualizacao: {last_update}")
    lines.append(f"- Ultimo `global_seq`: {last_seq}")
    lines.append(f"- Estado do monitor: {'concluido por inatividade' if completed else 'em acompanhamento'}")
    lines.append(f"- Janela de calma configurada: {quiet_seconds}s")
    lines.append("")
    lines.append("## Resumo parcial")
    lines.append("")
    lines.append(f"- Eventos capturados: {len(entries)}")
    lines.append(f"- Tasks vistas: {len(task_ids)}")
    lines.append(f"- Info: {counts.get('info', 0)}")
    lines.append(f"- Success: {counts.get('success', 0)}")
    lines.append(f"- Warning: {counts.get('warning', 0)}")
    lines.append(f"- Error: {counts.get('error', 0)}")
    if final_totals:
        success_sum = sum(v["success"] for v in final_totals.values())
        failed_sum = sum(v["failed"] for v in final_totals.values())
        lines.append(f"- Totais declarados por grupos finalizados: sucesso={success_sum}, falhas={failed_sum}")
    if status_counts:
        status_text = ", ".join(f"{k}={v}" for k, v in sorted(status_counts.items()))
        lines.append(f"- Status das tasks consultadas: {status_text}")
    lines.append("")
    lines.append("## Erros")
    lines.append("")
    if errors:
        for e in errors[-80:]:
            lines.append(f"- `{e.get('global_seq')}` {e.get('timestamp_iso')}: **{e.get('device_name')}** - {e.get('message')}")
    else:
        lines.append("- Nenhum erro capturado até agora.")
    lines.append("")
    lines.append("## Avisos")
    lines.append("")
    if warnings:
        for e in warnings[-80:]:
            lines.append(f"- `{e.get('global_seq')}` {e.get('timestamp_iso')}: **{e.get('device_name')}** - {e.get('message')}")
    else:
        lines.append("- Nenhum aviso capturado até agora.")
    lines.append("")
    lines.append("## Dispositivos com mais eventos")
    lines.append("")
    for device, count in by_device.most_common(40):
        lines.append(f"- {device}: {count}")
    lines.append("")
    lines.append("## Logs")
    lines.append("")
    lines.append("| Seq | Horario | Nivel | Dispositivo | Task | Mensagem |")
    lines.append("|---:|---|---|---|---|---|")
    lines.extend(fmt_entry(e) for e in entries)
    lines.append("")
    report_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8050")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--cookie-file", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--after", type=int, default=0)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--quiet-seconds", type=int, default=600)
    parser.add_argument("--status-every", type=int, default=6)
    args = parser.parse_args()

    opener = build_opener()
    session_cookie = read_session_cookie(args.cookie_file)
    entries: list[dict] = []
    seen_seq: set[int] = set()
    task_status: dict[str, dict] = {}
    last_seq = max(0, int(args.after or 0))
    last_new = time.monotonic()
    started_at = now_iso()
    status_tick = 0

    args.report.parent.mkdir(parents=True, exist_ok=True)
    print(f"monitor_start report={args.report} after={last_seq}", flush=True)

    while True:
        try:
            payload = get_json(opener, log_url(args.base_url, args.tenant, last_seq), session_cookie)
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            print(f"monitor_warning log_fetch_failed={type(exc).__name__}: {exc}", flush=True)
            time.sleep(args.poll_seconds)
            continue

        new_entries = []
        for entry in payload.get("entries") or []:
            try:
                seq = int(entry.get("global_seq") or 0)
            except Exception:
                seq = 0
            if seq <= 0 or seq in seen_seq:
                continue
            seen_seq.add(seq)
            new_entries.append(entry)
            last_seq = max(last_seq, seq)

        if new_entries:
            entries.extend(new_entries)
            entries.sort(key=lambda e: int(e.get("global_seq") or 0))
            last_new = time.monotonic()
            print(
                f"monitor_new count={len(new_entries)} last_seq={last_seq} total={len(entries)}",
                flush=True,
            )

        status_tick += 1
        task_ids = sorted({str(e.get("task_id") or "") for e in entries if e.get("task_id")})
        if task_ids and status_tick >= max(1, args.status_every):
            status_tick = 0
            for task_id in task_ids[-250:]:
                try:
                    status_payload = get_json(
                        opener,
                        task_status_url(args.base_url, args.tenant, task_id),
                        session_cookie,
                        timeout=10,
                    )
                    if status_payload.get("ok"):
                        task_status[task_id] = status_payload
                except Exception:
                    pass

        idle_for = int(time.monotonic() - last_new)
        completed = bool(entries) and idle_for >= args.quiet_seconds
        write_report(
            args.report,
            tenant_slug=args.tenant,
            started_at=started_at,
            last_update=now_iso(),
            last_seq=last_seq,
            entries=entries,
            task_status=task_status,
            quiet_seconds=args.quiet_seconds,
            completed=completed,
        )

        if completed:
            print(f"monitor_complete idle_for={idle_for}s last_seq={last_seq} total={len(entries)}", flush=True)
            return 0

        print(f"monitor_tick idle_for={idle_for}s last_seq={last_seq} total={len(entries)}", flush=True)
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    sys.exit(main())
