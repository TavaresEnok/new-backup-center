#!/usr/bin/env python3
"""
Retesta, de forma sequencial, todos os dispositivos com ultimo status FAILED
de um grupo especifico e emite contagem antes/depois.

Uso (dentro do container app):
  PYTHONPATH=/app python /app/app/scripts/maintenance/retest_group_failed.py --group-name "Pix Fibra"
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from multiprocessing import Process, Queue
from typing import Iterable, List, Tuple

from app.core.database import SessionLocal
from app.models import Backup, Device, DeviceGroup, DeviceType
from app.services.backup_executor import backup_executor


EXCLUDE_TYPE_KEYWORDS = ("grafana", "zabbix")


@dataclass
class CountSummary:
    total: int = 0
    success: int = 0
    failed: int = 0
    other: int = 0


def _is_excluded_type(device_type: DeviceType | None) -> bool:
    if not device_type:
        return False
    values = [
        str(getattr(device_type, "name", "") or "").lower(),
        str(getattr(device_type, "slug", "") or "").lower(),
        str(getattr(device_type, "script_name", "") or "").lower(),
    ]
    for value in values:
        if any(keyword in value for keyword in EXCLUDE_TYPE_KEYWORDS):
            return True
    return False


def _last_backup(db, device_id) -> Backup | None:
    return (
        db.query(Backup)
        .filter(Backup.device_id == device_id)
        .order_by(Backup.created_at.desc())
        .first()
    )


def _collect_eligible_devices(db, group_id) -> List[Tuple[Device, DeviceType | None]]:
    devices = (
        db.query(Device)
        .filter(Device.group_id == group_id, Device.is_active.is_(True))
        .order_by(Device.name.asc())
        .all()
    )
    eligible: List[Tuple[Device, DeviceType | None]] = []
    for device in devices:
        device_type = (
            db.query(DeviceType).filter(DeviceType.id == device.device_type_id).first()
            if device.device_type_id
            else None
        )
        if _is_excluded_type(device_type):
            continue
        eligible.append((device, device_type))
    return eligible


def _count_status(db, eligible: Iterable[Tuple[Device, DeviceType | None]]) -> CountSummary:
    summary = CountSummary()
    for device, _ in eligible:
        summary.total += 1
        backup = _last_backup(db, device.id)
        status = str(backup.status).lower() if backup else ""
        if status.endswith("success"):
            summary.success += 1
        elif status.endswith("failed"):
            summary.failed += 1
        else:
            summary.other += 1
    return summary


def _run_backup_worker(device_id: str, queue: Queue) -> None:
    """Executa o backup em subprocesso para permitir timeout/kill por dispositivo."""
    try:
        ok, msg = backup_executor.run_backup_for_device_id(
            device_id,
            manage_vpn=True,
            task_id=None,
        )
        queue.put((ok, str(msg)))
    except Exception as exc:  # pragma: no cover
        queue.put((False, f"worker_exception:{exc}"))


def _run_with_timeout(device_id: str, timeout_seconds: int) -> tuple[bool, str]:
    queue: Queue = Queue()
    proc = Process(target=_run_backup_worker, args=(device_id, queue), daemon=True)
    proc.start()
    proc.join(timeout_seconds)

    if proc.is_alive():
        proc.terminate()
        proc.join(5)
        return (
            False,
            f"worker_timeout:{timeout_seconds}s (processo encerrado para evitar travamento do reteste)",
        )

    if queue.empty():
        return False, "worker_no_result"

    ok, msg = queue.get()
    return bool(ok), str(msg)


def _run_with_timeout_retry(device_id: str, timeout_seconds: int) -> tuple[bool, str]:
    """
    Executa reteste com timeout e, em caso de estouro, tenta uma segunda vez com timeout maior.
    Isso reduz falso-negativo em equipamentos que demoram mais para estabilizar prompt/shell.
    """
    base_timeout = max(30, int(timeout_seconds))
    ok, msg = _run_with_timeout(device_id, base_timeout)
    if ok:
        return ok, msg
    if not str(msg).startswith("worker_timeout:"):
        return ok, msg

    # Escalada conservadora: uma única segunda tentativa com janela maior.
    retry_timeout = min(240, max(base_timeout + 45, int(base_timeout * 2)))
    ok2, msg2 = _run_with_timeout(device_id, retry_timeout)
    if ok2:
        return True, f"{msg2} (após retry_timeout={retry_timeout}s)"
    return False, f"{msg2} [retry_timeout={retry_timeout}s]"


def main() -> int:
    parser = argparse.ArgumentParser(description="Reteste sequencial de falhas por grupo.")
    parser.add_argument("--group-name", required=True, help="Nome exato do grupo.")
    parser.add_argument(
        "--max-devices",
        type=int,
        default=0,
        help="Limita quantos falhos retestar (0 = todos).",
    )
    parser.add_argument(
        "--device-timeout-seconds",
        type=int,
        default=300,
        help="Timeout maximo por dispositivo no reteste (evita travar o grupo inteiro).",
    )
    args = parser.parse_args()

    db = SessionLocal()
    try:
        group = (
            db.query(DeviceGroup)
            .filter(DeviceGroup.name == args.group_name, DeviceGroup.is_active.is_(True))
            .first()
        )
        if not group:
            print(f"GROUP_NOT_FOUND|{args.group_name}")
            return 2

        eligible = _collect_eligible_devices(db, group.id)
        before = _count_status(db, eligible)
        print(
            f"BEFORE|group={group.name}|total={before.total}|success={before.success}|failed={before.failed}|other={before.other}"
        )

        failed_devices: List[Device] = []
        for device, _ in eligible:
            last = _last_backup(db, device.id)
            if last and str(last.status).lower().endswith("failed"):
                failed_devices.append(device)

        if args.max_devices and args.max_devices > 0:
            failed_devices = failed_devices[: args.max_devices]

        print(f"RETEST_PLAN|group={group.name}|failed_before={before.failed}|will_retest={len(failed_devices)}")

        for index, device in enumerate(failed_devices, start=1):
            print(f"RETEST_START|{index}/{len(failed_devices)}|{device.id}|{device.name}")
            ok, msg = _run_with_timeout_retry(str(device.id), max(30, int(args.device_timeout_seconds)))
            print(f"RETEST_END|{index}/{len(failed_devices)}|{device.id}|{device.name}|ok={ok}|msg={msg}")

        # Recarrega elegiveis para contabilizacao final
        eligible_after = _collect_eligible_devices(db, group.id)
        after = _count_status(db, eligible_after)
        print(
            f"AFTER|group={group.name}|total={after.total}|success={after.success}|failed={after.failed}|other={after.other}"
        )
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
