from __future__ import annotations

import argparse
import fcntl
import json
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

from celery.result import AsyncResult

from app import create_flask_app
from app.celery_app import celery_app
from app.core.database import SessionLocal
from app.models.backup import Backup, BackupStatus
from app.models.device import Device
from app.models.device_subgroup import DeviceSubgroup
from app.models.tenant import Tenant
from app.services.connection_mode import get_effective_connection_type, uses_jump_host, uses_vpn_tunnel
from app.tasks.backups import run_backup_task


JUMP_SUBGROUP_NAME = "Conexão Jump Host"
RUNNER_LOCK_PATH = "/tmp/route_failed_current_then_jump.lock"
SUBGROUP_OVERRIDE_KEYS = (
    "connection_subgroup_type",
    "subgroup_connection_type",
    "connection_subgroup_enabled",
    "subgroup_connection_enabled",
)


def _queue_for_device(device: Device) -> str:
    if device.group and uses_vpn_tunnel(device.group, device=device):
        return "vpn_queue"
    if device.group and uses_jump_host(device.group, device=device):
        return "jump_queue"
    return "celery"


def _group_has_jump_host(group) -> bool:
    if not group:
        return False
    host = str(getattr(group, "jump_host", "") or "").strip()
    username = str(getattr(group, "jump_username", "") or "").strip()
    has_password = bool(getattr(group, "jump_password_encrypted", None))
    has_key = bool(getattr(group, "jump_key_encrypted", None))
    return bool(host and username and (has_password or has_key))


def _task_result(task_id: str, timeout_seconds: int) -> tuple[bool, dict]:
    started = time.time()
    while time.time() - started <= timeout_seconds:
        result = AsyncResult(task_id, app=celery_app)
        if result.ready():
            payload = result.result if isinstance(result.result, dict) else {
                "success": False,
                "message": str(result.result),
            }
            return True, {
                "state": result.state,
                "success": bool(payload.get("success")),
                "message": str(payload.get("message") or payload.get("error") or "")[:900],
                "failure_category": payload.get("failure_category"),
            }
        time.sleep(3)
    celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
    return False, {
        "state": "TIMEOUT",
        "success": False,
        "message": f"Timeout aguardando resultado da task por {timeout_seconds}s; task revogada.",
        "failure_category": "timeout",
    }


def _snapshot_device(device: Device) -> dict:
    return {
        "subgroup_id": str(device.subgroup_id) if device.subgroup_id else None,
        "extra_parameters": dict(device.extra_parameters or {}),
        "effective_connection_type": get_effective_connection_type(device.group, device=device) if device.group else "direct",
    }


def _restore_device(db, device_id: str, original: dict):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        return
    device.subgroup_id = original.get("subgroup_id")
    device.extra_parameters = original.get("extra_parameters") or {}
    db.commit()


def _ensure_jump_subgroup(db, device: Device):
    group = device.group
    if not group:
        return None
    current_group_mode = get_effective_connection_type(group)
    if current_group_mode == "jump_host":
        return None
    subgroup = (
        db.query(DeviceSubgroup)
        .filter(
            DeviceSubgroup.tenant_id == device.tenant_id,
            DeviceSubgroup.group_id == device.group_id,
            DeviceSubgroup.connection_type == "jump_host",
        )
        .order_by(DeviceSubgroup.is_active.desc(), DeviceSubgroup.created_at.asc())
        .first()
    )
    if subgroup:
        if subgroup.name != JUMP_SUBGROUP_NAME or not subgroup.is_active:
            subgroup.name = JUMP_SUBGROUP_NAME
            subgroup.is_active = True
            db.commit()
        return subgroup
    subgroup = DeviceSubgroup(
        tenant_id=device.tenant_id,
        group_id=device.group_id,
        name=JUMP_SUBGROUP_NAME,
        connection_type="jump_host",
        is_active=True,
    )
    db.add(subgroup)
    db.commit()
    return subgroup


def _apply_jump_route(db, device_id: str) -> dict:
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device or not device.group:
        raise RuntimeError("Dispositivo sem grupo para aplicar Jump Host.")
    subgroup = _ensure_jump_subgroup(db, device)
    device.subgroup_id = subgroup.id if subgroup else None
    extra = dict(device.extra_parameters or {})
    for key in SUBGROUP_OVERRIDE_KEYS:
        extra.pop(key, None)
    extra["route_retest_last_attempt_at"] = datetime.utcnow().isoformat() + "Z"
    extra["route_retest_last_attempt_mode"] = "jump_host"
    device.extra_parameters = extra
    db.commit()
    return {
        "subgroup_id": str(device.subgroup_id) if device.subgroup_id else None,
        "effective_connection_type": get_effective_connection_type(device.group, device=device),
    }


def _load_candidates(args):
    app = create_flask_app()
    with app.app_context():
        db = SessionLocal()
        try:
            tenant = db.query(Tenant).filter(Tenant.slug == args.tenant_slug).first()
            if not tenant:
                raise RuntimeError(f"Tenant nao encontrado: {args.tenant_slug}")
            query = db.query(Device).filter(
                Device.tenant_id == tenant.id,
                Device.is_active.is_(True),
                Device.last_backup_status == "failure",
            )
            devices = query.all()
            candidates = []
            skipped = Counter()
            for device in devices:
                group = device.group
                if group and not bool(getattr(group, "is_active", True)):
                    skipped["inactive_group"] += 1
                    continue
                has_success = (
                    db.query(Backup.id)
                    .filter(Backup.device_id == device.id, Backup.status == BackupStatus.SUCCESS)
                    .first()
                    is not None
                )
                if not has_success:
                    skipped["never_success"] += 1
                    continue
                candidates.append(
                    {
                        "device_id": str(device.id),
                        "device_name": str(device.name or ""),
                        "group": str(group.name if group else ""),
                        "group_id": str(device.group_id) if device.group_id else None,
                        "type": str(device.type.name if device.type else ""),
                        "ip": str(device.ip_address or ""),
                        "port": int(device.port or 22),
                        "original_mode": get_effective_connection_type(group, device=device) if group else "direct",
                        "jump_available": bool(_group_has_jump_host(group)),
                    }
                )
            return candidates, dict(skipped)
        finally:
            db.close()


def _write_report(path: Path, report: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def _looks_like_lockout(message: str) -> bool:
    normalized = str(message or "").lower()
    lockout_markers = (
        "has been locked",
        "user has been locked",
        "ip and user has been locked",
        "usuario bloqueado",
        "usuário bloqueado",
        "conta bloqueada",
        "account locked",
        "too many failed",
        "too many authentication failures",
    )
    return any(marker in normalized for marker in lockout_markers)


def _acquire_runner_lock():
    lock_file = open(RUNNER_LOCK_PATH, "w", encoding="utf-8")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise RuntimeError(
            f"Outro reteste de rotas ja esta em execucao ({RUNNER_LOCK_PATH})."
        ) from exc
    lock_file.write(f"{datetime.utcnow().isoformat()}Z\n")
    lock_file.flush()
    return lock_file


def main():
    parser = argparse.ArgumentParser(description="Retesta falhas atuais na rota atual e depois Jump Host.")
    parser.add_argument("--tenant-slug", default="ajust-consulting")
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=720)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    runner_lock = _acquire_runner_lock()

    try:
        out_path = Path(args.output)
        previous_items = []
        completed_ids = set()
        if args.resume and out_path.exists():
            previous = json.loads(out_path.read_text(encoding="utf-8"))
            previous_items = list(previous.get("items") or [])
            completed_ids = {item.get("device_id") for item in previous_items if item.get("device_id")}

        candidates, skipped = _load_candidates(args)
        candidates = [candidate for candidate in candidates if candidate["device_id"] not in completed_ids]
        if args.limit > 0:
            candidates = candidates[: args.limit]

        report = {
            "tenant_slug": args.tenant_slug,
            "started_at_utc": datetime.utcnow().isoformat() + "Z",
            "strategy": "backup current effective route; if it fails, test Jump Host when available; keep Jump only on backup success",
            "dry_run": bool(args.dry_run),
            "skipped": skipped,
            "total_candidates": len(candidates) + len(previous_items),
            "remaining_candidates": len(candidates),
            "items": previous_items,
        }

        if args.dry_run:
            report["candidate_preview"] = candidates
            _write_report(out_path, report)
            print(json.dumps({"dry_run": True, "candidates": len(candidates), "skipped": skipped, "output": str(out_path)}, ensure_ascii=False), flush=True)
            return

        app = create_flask_app()
        for index, candidate in enumerate(candidates, start=1):
            device_id = candidate["device_id"]
            item = {
                **candidate,
                "started_at_utc": datetime.utcnow().isoformat() + "Z",
                "attempts": [],
                "winner": None,
                "final_action": None,
            }

            with app.app_context():
                db = SessionLocal()
                try:
                    device = db.query(Device).filter(Device.id == device_id).first()
                    if not device:
                        item["final_action"] = "device_not_found"
                        report["items"].append(item)
                        _write_report(out_path, report)
                        continue
                    original = _snapshot_device(device)
                    actual_mode = original.get("effective_connection_type") or candidate["original_mode"]
                    jump_available = bool(_group_has_jump_host(device.group))
                    item["original_mode"] = actual_mode
                    item["jump_available"] = jump_available
                    current_queue = _queue_for_device(device)
                finally:
                    db.close()

            print(
                f"[{index}/{len(candidates)}] {candidate['group']} | {candidate['device_name']} | "
                f"current={item['original_mode']} jump_available={item['jump_available']}",
                flush=True,
            )

            task = run_backup_task.apply_async(args=[device_id], queue=current_queue)
            done, result = _task_result(task.id, args.timeout_seconds)
            current_attempt = {
                "mode": item["original_mode"],
                "queue": current_queue,
                "task_id": task.id,
                "done": done,
                **result,
            }
            item["attempts"].append(current_attempt)
            print(f"  atual: success={result['success']} queue={current_queue} msg={result['message'][:140]}", flush=True)

            if (
                not done
                and (
                    item["original_mode"] == "jump_host"
                    or current_queue == "jump_queue"
                    or not item["jump_available"]
                )
            ):
                item["final_action"] = "current_task_monitor_timeout_no_route_change"
                report["items"].append(item)
                _write_report(out_path, report)
                continue

            if result["success"]:
                item["winner"] = item["original_mode"]
                item["final_action"] = "kept_original_success"
                report["items"].append(item)
                _write_report(out_path, report)
                continue

            if _looks_like_lockout(result["message"]):
                item["final_action"] = "current_failed_lockout_no_jump"
                report["items"].append(item)
                _write_report(out_path, report)
                continue

            if item["original_mode"] == "jump_host" or current_queue == "jump_queue" or not item["jump_available"]:
                item["final_action"] = "no_jump_alternative_restored"
                with app.app_context():
                    db = SessionLocal()
                    try:
                        _restore_device(db, device_id, original)
                    finally:
                        db.close()
                report["items"].append(item)
                _write_report(out_path, report)
                continue

            with app.app_context():
                db = SessionLocal()
                try:
                    applied = _apply_jump_route(db, device_id)
                finally:
                    db.close()

            task = run_backup_task.apply_async(args=[device_id], queue="jump_queue")
            done, result = _task_result(task.id, args.timeout_seconds)
            jump_attempt = {
                "mode": "jump_host",
                "queue": "jump_queue",
                "task_id": task.id,
                "done": done,
                "applied": applied,
                **result,
            }
            item["attempts"].append(jump_attempt)
            print(f"  jump: success={result['success']} msg={result['message'][:140]}", flush=True)

            with app.app_context():
                db = SessionLocal()
                try:
                    if result["success"]:
                        item["winner"] = "jump_host"
                        item["final_action"] = "kept_jump_host"
                    else:
                        _restore_device(db, device_id, original)
                        item["final_action"] = (
                            "restored_original_after_jump_monitor_timeout"
                            if not done
                            else "restored_original_after_jump_failure"
                        )
                finally:
                    db.close()

            report["items"].append(item)
            _write_report(out_path, report)

        report["finished_at_utc"] = datetime.utcnow().isoformat() + "Z"
        summary = Counter(item.get("winner") or item.get("final_action") or "unknown" for item in report["items"])
        report["summary"] = dict(summary)
        _write_report(out_path, report)
        print(json.dumps({"done": len(report["items"]), "summary": dict(summary), "output": str(out_path)}, ensure_ascii=False), flush=True)
    finally:
        fcntl.flock(runner_lock.fileno(), fcntl.LOCK_UN)
        runner_lock.close()


if __name__ == "__main__":
    main()
