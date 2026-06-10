from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path

from celery.result import AsyncResult
from sqlalchemy.orm import joinedload

from app import create_flask_app
from app.celery_app import celery_app
from app.core.database import SessionLocal
from app.models.device import Device
from app.services.connection_mode import uses_jump_host, uses_vpn_tunnel
from app.tasks.backups import run_backup_task


def _queue_for_device(device: Device) -> str:
    if device.group and uses_vpn_tunnel(device.group, device=device):
        return "vpn_queue"
    if device.group and uses_jump_host(device.group, device=device):
        return "jump_queue"
    return "celery"


def main():
    parser = argparse.ArgumentParser(description="Retesta dispositivos reconciliados por CSV seguro.")
    parser.add_argument("--input", required=True, help="JSON gerado pelo reconcile_failed_devices_from_assets.")
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args()

    root = json.loads(Path(args.input).read_text(encoding="utf-8"))
    target_ids = [
        row["device_id"]
        for row in root.get("rows", [])
        if row.get("status") in {"safe_update", "already_ok"} and row.get("device_id")
    ]

    app = create_flask_app()
    with app.app_context():
        db = SessionLocal()
        try:
            devices = (
                db.query(Device)
                .options(joinedload(Device.group), joinedload(Device.subgroup), joinedload(Device.type))
                .filter(Device.id.in_(target_ids))
                .all()
            )
            by_id = {str(device.id): device for device in devices}
            ordered = [by_id[device_id] for device_id in target_ids if device_id in by_id]

            queued = []
            queue_counts = Counter()
            for device in ordered:
                queue = _queue_for_device(device)
                if queue == "vpn_queue":
                    countdown = queue_counts[queue] * 8
                elif queue == "jump_queue":
                    countdown = queue_counts[queue] * 5
                else:
                    countdown = queue_counts[queue] * 2
                queue_counts[queue] += 1
                task = run_backup_task.apply_async(args=[str(device.id)], queue=queue, countdown=countdown)
                item = {
                    "device_id": str(device.id),
                    "device_name": str(device.name or ""),
                    "group": str(device.group.name if device.group else ""),
                    "type": str(device.type.name if device.type else ""),
                    "queue": queue,
                    "task_id": task.id,
                    "countdown": countdown,
                }
                queued.append(item)
                print(
                    f"ENQUEUED {len(queued)}/{len(ordered)} {queue} +{countdown}s | "
                    f"{item['group'] or '-'} | {item['device_name']}",
                    flush=True,
                )
        finally:
            db.close()

    pending = {item["task_id"]: item for item in queued}
    completed = []
    started_at = time.time()
    last_print = 0.0

    while pending:
        done_ids = []
        for task_id, item in list(pending.items()):
            result = AsyncResult(task_id, app=celery_app)
            if not result.ready():
                continue
            payload = result.result if isinstance(result.result, dict) else {
                "success": False,
                "message": str(result.result),
            }
            item.update(
                {
                    "state": result.state,
                    "success": bool(payload.get("success")),
                    "message": str(payload.get("message") or payload.get("error") or "")[:700],
                    "failure_category": payload.get("failure_category"),
                }
            )
            completed.append(item)
            done_ids.append(task_id)
            print(
                f"DONE {len(completed)}/{len(queued)} success={item['success']} state={result.state} | "
                f"{item['device_name']} | {item['message'][:160]}",
                flush=True,
            )

        for task_id in done_ids:
            pending.pop(task_id, None)

        now = time.time()
        if pending and now - last_print > 30:
            last_print = now
            print(f"WAIT pending={len(pending)} completed={len(completed)} elapsed={int(now - started_at)}s", flush=True)

        if now - started_at > max(60, int(args.timeout_seconds)):
            print(f"TIMEOUT monitor {args.timeout_seconds}s; salvando parciais", flush=True)
            break
        time.sleep(3)

    summary = Counter("success" if item.get("success") else (item.get("failure_category") or "failure") for item in completed)
    output = {
        "started_at": started_at,
        "finished_at": time.time(),
        "queued": queued,
        "completed": completed,
        "pending": list(pending.values()),
        "summary": dict(summary),
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        "RETEST_DONE "
        + json.dumps(
            {
                "queued": len(queued),
                "completed": len(completed),
                "pending": len(pending),
                "summary": dict(summary),
                "output": str(out_path),
            },
            ensure_ascii=False,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
