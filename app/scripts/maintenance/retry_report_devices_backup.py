#!/usr/bin/env python3
"""Run one backup attempt per device listed in a Markdown report and write full logs."""

from __future__ import annotations

import argparse
import contextlib
import io
import logging
import os
import re
import sys
import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from multiprocessing import Process, Queue
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _prepare_env() -> None:
    try:
        import dotenv

        dotenv.load_dotenv(ROOT / ".env", override=False)
    except Exception:
        pass

    os.environ["DEBUG"] = "false"
    db_url = os.environ.get("DATABASE_URL", "")
    db_host = os.environ.get("BACKUP_CENTER_DB_HOST_OVERRIDE", "172.18.0.3")
    if "@db:" in db_url and db_host:
        os.environ["DATABASE_URL"] = db_url.replace("@db:", f"@{db_host}:")
    os.environ.setdefault("BACKUP_NETWORK_PRECHECK_TIMEOUT_SECONDS", "3")


_prepare_env()

from app.core.database import SessionLocal  # noqa: E402
from app.models import Backup, Device, DeviceGroup, DeviceType, Tenant  # noqa: E402
from app.models.backup import BackupStatus  # noqa: E402


DEVICE_ID_RE = re.compile(
    r"\|\s*\d+\s*\|.*?\|\s*`([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`\s*\|"
)
CATEGORY_RE = re.compile(r"^##\s+(.+?)(?:\s+\{#.*\})?\s*$")


@dataclass
class ReportDevice:
    device_id: str
    source_category: str
    source_order: int


@dataclass
class DeviceAttempt:
    source_order: int
    source_category: str
    device_id: str
    name: str = ""
    ip_address: str = ""
    port: int | None = None
    device_type: str = ""
    script_name: str = ""
    group_name: str = ""
    tenant_slug: str = ""
    started_at: str = ""
    completed_at: str = ""
    elapsed_seconds: float = 0.0
    worker_status: str = "not_started"
    success: bool = False
    message: str = ""
    backup_id: str = ""
    backup_status: str = ""
    backup_created_at: str = ""
    backup_file_path: str = ""
    backup_file_size: int | None = None
    backup_hash: str = ""
    stdout: str = ""
    stderr: str = ""
    traceback_text: str = ""


def parse_report(path: Path) -> list[ReportDevice]:
    category = "Sem categoria"
    devices: list[ReportDevice] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        category_match = CATEGORY_RE.match(line.strip())
        if category_match:
            category = category_match.group(1).strip()
            continue
        match = DEVICE_ID_RE.search(line)
        if not match:
            continue
        device_id = str(uuid.UUID(match.group(1)))
        if device_id in seen:
            continue
        seen.add(device_id)
        devices.append(ReportDevice(device_id=device_id, source_category=category, source_order=len(devices) + 1))
    return devices


def _latest_backup_dict(db, device_id: str) -> dict[str, Any]:
    backup = (
        db.query(Backup)
        .filter(Backup.device_id == device_id)
        .order_by(Backup.created_at.desc())
        .first()
    )
    if not backup:
        return {}
    status = backup.status.value if hasattr(backup.status, "value") else str(backup.status or "")
    return {
        "backup_id": str(backup.id),
        "backup_status": status,
        "backup_created_at": backup.created_at.isoformat(sep=" ", timespec="seconds") if backup.created_at else "",
        "backup_file_path": backup.file_path or "",
        "backup_file_size": backup.file_size_bytes,
        "backup_hash": backup.hash_sha256 or "",
        "backup_error_message": backup.error_message or "",
    }


def _device_metadata(db, report_device: ReportDevice) -> DeviceAttempt:
    device = db.query(Device).filter(Device.id == report_device.device_id).first()
    if not device:
        return DeviceAttempt(
            source_order=report_device.source_order,
            source_category=report_device.source_category,
            device_id=report_device.device_id,
            worker_status="device_not_found",
            message="Dispositivo nao encontrado no banco.",
        )

    group = db.query(DeviceGroup).filter(DeviceGroup.id == device.group_id).first() if device.group_id else None
    device_type = db.query(DeviceType).filter(DeviceType.id == device.device_type_id).first() if device.device_type_id else None
    tenant = db.query(Tenant).filter(Tenant.id == device.tenant_id).first() if device.tenant_id else None
    return DeviceAttempt(
        source_order=report_device.source_order,
        source_category=report_device.source_category,
        device_id=str(device.id),
        name=device.name or "",
        ip_address=device.ip_address or "",
        port=int(device.port or 0),
        device_type=(device_type.name if device_type else ""),
        script_name=(device_type.script_name if device_type else ""),
        group_name=(group.name if group else "Sem Grupo"),
        tenant_slug=(tenant.slug if tenant else ""),
    )


def _collect_device_metadata(devices: list[ReportDevice]) -> list[DeviceAttempt]:
    db = SessionLocal()
    try:
        return [_device_metadata(db, item) for item in devices]
    finally:
        db.close()


def _worker(device_id: str, queue: Queue) -> None:
    _prepare_env()
    stdout = io.StringIO()
    stderr = io.StringIO()
    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)

    try:
        from app.services.backup_executor import backup_executor

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            ok, msg = backup_executor.run_backup_for_device_id(
                device_id,
                manage_vpn=True,
                task_id=None,
            )

        db = SessionLocal()
        try:
            backup = _latest_backup_dict(db, device_id)
        finally:
            db.close()

        queue.put(
            {
                "ok": bool(ok),
                "message": str(msg or ""),
                "stdout": stdout.getvalue(),
                "stderr": stderr.getvalue(),
                "logs": log_stream.getvalue(),
                "backup": backup,
            }
        )
    except Exception:
        queue.put(
            {
                "ok": False,
                "message": "worker_exception",
                "stdout": stdout.getvalue(),
                "stderr": stderr.getvalue(),
                "logs": log_stream.getvalue(),
                "traceback": traceback.format_exc(),
                "backup": {},
            }
        )
    finally:
        root_logger.removeHandler(handler)


def _persist_timeout_failure(attempt: DeviceAttempt, timeout_seconds: int) -> dict[str, Any]:
    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == attempt.device_id).first()
        if not device:
            return {}
        now = datetime.utcnow()
        message = (
            "Reteste de reanalise encerrado por timeout operacional "
            f"apos {timeout_seconds}s; processo filho finalizado para evitar travamento."
        )
        backup = Backup(
            device_id=device.id,
            status=BackupStatus.FAILED,
            error_message=message,
            started_at=now,
            completed_at=now,
            duration_seconds=timeout_seconds,
        )
        db.add(backup)
        device.last_backup_at = now
        device.last_backup_status = "failure"
        extra = dict(device.extra_parameters or {})
        extra["last_backup_failure_category"] = "timeout"
        extra["last_backup_failure_label"] = "Timeout operacional na reanalise"
        extra["last_backup_failure_message"] = message
        extra["last_backup_failure_at"] = now.isoformat() + "Z"
        device.extra_parameters = extra
        db.commit()
        return _latest_backup_dict(db, attempt.device_id)
    finally:
        db.close()


def run_attempt(attempt: DeviceAttempt, timeout_seconds: int, persist_timeout_failure: bool) -> DeviceAttempt:
    if attempt.worker_status == "device_not_found":
        return attempt

    queue: Queue = Queue()
    started = time.monotonic()
    attempt.started_at = datetime.now().isoformat(sep=" ", timespec="seconds")
    proc = Process(target=_worker, args=(attempt.device_id, queue), daemon=True)
    proc.start()
    proc.join(timeout_seconds)
    attempt.elapsed_seconds = round(time.monotonic() - started, 3)
    attempt.completed_at = datetime.now().isoformat(sep=" ", timespec="seconds")

    if proc.is_alive():
        proc.terminate()
        proc.join(5)
        attempt.worker_status = "timeout"
        attempt.success = False
        attempt.message = f"worker_timeout:{timeout_seconds}s"
        if persist_timeout_failure:
            backup = _persist_timeout_failure(attempt, timeout_seconds)
            _apply_backup(attempt, backup)
        return attempt

    if queue.empty():
        attempt.worker_status = "no_result"
        attempt.success = False
        attempt.message = "worker_no_result"
        return attempt

    payload = queue.get()
    attempt.worker_status = "completed"
    attempt.success = bool(payload.get("ok"))
    attempt.message = str(payload.get("message") or "")
    attempt.stdout = str(payload.get("stdout") or "")
    logs = str(payload.get("logs") or "")
    stderr = str(payload.get("stderr") or "")
    attempt.stderr = (logs + "\n" + stderr).strip()
    attempt.traceback_text = str(payload.get("traceback") or "")
    _apply_backup(attempt, payload.get("backup") or {})
    if not attempt.message and attempt.backup_status == "failed":
        attempt.message = str((payload.get("backup") or {}).get("backup_error_message") or "")
    return attempt


def _apply_backup(attempt: DeviceAttempt, backup: dict[str, Any]) -> None:
    attempt.backup_id = str(backup.get("backup_id") or "")
    attempt.backup_status = str(backup.get("backup_status") or "")
    attempt.backup_created_at = str(backup.get("backup_created_at") or "")
    attempt.backup_file_path = str(backup.get("backup_file_path") or "")
    attempt.backup_file_size = backup.get("backup_file_size")
    attempt.backup_hash = str(backup.get("backup_hash") or "")


def md_escape(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("|", "/").replace("\n", " ").strip()


def fenced(text: str) -> list[str]:
    text = text.strip()
    if not text:
        return ["_(sem saída)_"]
    return ["```text", text, "```"]


def write_markdown(path: Path, source_report: Path, attempts: list[DeviceAttempt], completed: int, total: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    success_count = sum(1 for a in attempts if a.worker_status != "not_started" and a.success)
    failed_count = sum(1 for a in attempts if a.worker_status != "not_started" and not a.success)
    timeout_count = sum(1 for a in attempts if a.worker_status == "timeout")
    pending_count = sum(1 for a in attempts if a.worker_status == "not_started")

    lines: list[str] = []
    lines.append("# Reanalise de Backup dos Dispositivos com Falha")
    lines.append("")
    lines.append(f"- **Relatorio de origem:** `{source_report}`")
    lines.append(f"- **Gerado em:** {datetime.now().isoformat(sep=' ', timespec='seconds')}")
    lines.append(f"- **Dispositivos planejados:** {total}")
    lines.append(f"- **Dispositivos processados:** {completed}")
    lines.append(f"- **Sucessos nesta rodada:** {success_count}")
    lines.append(f"- **Falhas nesta rodada:** {failed_count}")
    lines.append(f"- **Timeouts operacionais:** {timeout_count}")
    lines.append(f"- **Pendentes:** {pending_count}")
    lines.append("")
    lines.append("## Resumo")
    lines.append("")
    lines.append("| # | Categoria origem | Dispositivo | IP | Porta | Tipo | Script | Grupo | Resultado | Backup ID | Mensagem |")
    lines.append("|---:|---|---|---|---:|---|---|---|---|---|---|")
    for attempt in attempts:
        result = "pendente"
        if attempt.worker_status != "not_started":
            result = "sucesso" if attempt.success else f"falha/{attempt.worker_status}"
        backup_id = f"`{attempt.backup_id}`" if attempt.backup_id else "-"
        lines.append(
            "| "
            + " | ".join(
                [
                    str(attempt.source_order),
                    md_escape(attempt.source_category),
                    md_escape(attempt.name or attempt.device_id),
                    md_escape(attempt.ip_address),
                    str(attempt.port or ""),
                    md_escape(attempt.device_type),
                    md_escape(attempt.script_name),
                    md_escape(attempt.group_name),
                    md_escape(result),
                    backup_id,
                    md_escape(attempt.message)[:240],
                ]
            )
            + " |"
        )

    lines.append("")
    lines.append("## Logs por Dispositivo")
    lines.append("")
    for attempt in attempts:
        if attempt.worker_status == "not_started":
            continue
        lines.append(f"### {attempt.source_order}. {attempt.name or attempt.device_id}")
        lines.append("")
        lines.append(f"- **Device ID:** `{attempt.device_id}`")
        lines.append(f"- **Categoria no relatorio original:** {attempt.source_category}")
        lines.append(f"- **Alvo:** `{attempt.ip_address}:{attempt.port or ''}`")
        lines.append(f"- **Tipo/script:** {attempt.device_type} / `{attempt.script_name}`")
        lines.append(f"- **Grupo/tenant:** {attempt.group_name} / `{attempt.tenant_slug}`")
        lines.append(f"- **Inicio:** {attempt.started_at}")
        lines.append(f"- **Fim:** {attempt.completed_at}")
        lines.append(f"- **Duracao:** {attempt.elapsed_seconds}s")
        lines.append(f"- **Status worker:** `{attempt.worker_status}`")
        lines.append(f"- **Sucesso:** `{attempt.success}`")
        lines.append(f"- **Mensagem:** {attempt.message or '(sem mensagem)'}")
        lines.append(f"- **Backup registrado:** `{attempt.backup_id or 'n/a'}` ({attempt.backup_status or 'n/a'})")
        if attempt.backup_file_path:
            lines.append(f"- **Arquivo:** `{attempt.backup_file_path}`")
            lines.append(f"- **Tamanho:** {attempt.backup_file_size or 0} bytes")
            lines.append(f"- **SHA256:** `{attempt.backup_hash or 'n/a'}`")
        lines.append("")
        lines.append("#### Logs operacionais")
        lines.extend(fenced(attempt.stderr))
        lines.append("")
        lines.append("#### Stdout")
        lines.extend(fenced(attempt.stdout))
        if attempt.traceback_text:
            lines.append("")
            lines.append("#### Traceback")
            lines.extend(fenced(attempt.traceback_text))
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=360)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--start-at", type=int, default=1)
    parser.add_argument("--no-persist-timeout-failures", action="store_true")
    args = parser.parse_args()

    source_report = args.report.resolve()
    if not source_report.exists():
        print(f"REPORT_NOT_FOUND|{source_report}", flush=True)
        return 2

    report_devices = parse_report(source_report)
    if args.start_at > 1:
        report_devices = [d for d in report_devices if d.source_order >= args.start_at]
    if args.limit and args.limit > 0:
        report_devices = report_devices[: args.limit]

    attempts = _collect_device_metadata(report_devices)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output = args.output or (ROOT / "reports" / "mass_backup_logs" / f"reanalise_backups_dispositivos_{ts}.md")
    completed = 0
    write_markdown(output, source_report, attempts, completed, len(attempts))
    print(f"RUN_START|total={len(attempts)}|output={output}", flush=True)

    for index, attempt in enumerate(attempts, start=1):
        print(
            f"DEVICE_START|{index}/{len(attempts)}|order={attempt.source_order}|"
            f"id={attempt.device_id}|name={attempt.name}|target={attempt.ip_address}:{attempt.port}|"
            f"script={attempt.script_name}",
            flush=True,
        )
        run_attempt(
            attempt,
            timeout_seconds=max(30, int(args.timeout_seconds)),
            persist_timeout_failure=not args.no_persist_timeout_failures,
        )
        completed += 1
        write_markdown(output, source_report, attempts, completed, len(attempts))
        print(
            f"DEVICE_END|{index}/{len(attempts)}|order={attempt.source_order}|"
            f"id={attempt.device_id}|ok={attempt.success}|worker={attempt.worker_status}|"
            f"backup_id={attempt.backup_id or '-'}|msg={attempt.message}",
            flush=True,
        )

    print(f"RUN_END|processed={completed}|output={output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
