from flask import Blueprint, render_template, redirect, url_for, request, flash, session, abort, send_file, jsonify, Response, stream_with_context
from app.web.auth.decorators import login_required, tenant_admin_required
from app.core.database import SessionLocal
from app.models.backup import Backup, BackupStatus
from app.models.device import Device
from app.models.tenant import Tenant
from app.models.user import UserRole
from app.celery_app import celery_app
from app.services.realtime_backup_logs import (
    get_task_meta,
    get_task_logs,
    get_global_logs,
    update_task_meta,
    append_task_log,
    get_redis_client,
)
from app.services.backup_diagnostics import classify_failure, failure_label
from app.services.plan_limits_service import PlanLimitsService
from sqlalchemy import desc, func
import logging
from sqlalchemy.orm import joinedload
import uuid
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta

bp = Blueprint('tenant_backups', __name__, url_prefix='/tenant/<tenant_slug>/backups')


def get_db_and_tenant(tenant_slug):
    """Valida acesso e retorna sessão do banco e tenant."""
    if session.get('user_role') != UserRole.SUPER_ADMIN.value and session.get('tenant_slug') != tenant_slug:
        abort(403)
    db = SessionLocal()
    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
    if not tenant:
        db.close()
    return db, tenant


def _bulk_status_refresh_min_interval_seconds() -> float:
    raw = str(os.getenv("BULK_STATUS_REFRESH_MIN_INTERVAL_SECONDS", "5")).strip()
    try:
        value = float(raw)
    except Exception:
        value = 2.5
    return max(1.0, min(value, 15.0))


def _refresh_bulk_task_meta(task_id: str, task_meta: dict) -> dict:
    child_task_ids = [str(tid) for tid in (task_meta.get("child_task_ids") or []) if tid]
    total_tasks = int(task_meta.get("total_tasks") or len(child_task_ids))
    prev_total_tasks = int(task_meta.get("total_tasks") or 0)
    prev_total_devices = int(task_meta.get("total_devices") or 0)
    prev_done_tasks = int(task_meta.get("done_tasks") or 0)
    prev_success_tasks = int(task_meta.get("success_tasks") or 0)
    prev_failed_tasks = int(task_meta.get("failed_tasks") or 0)
    prev_done_devices = int(task_meta.get("done_devices") or 0)
    prev_success_devices = int(task_meta.get("success_devices") or 0)
    prev_failed_devices = int(task_meta.get("failed_devices") or 0)
    prev_finished_task_ids = {
        str(tid)
        for tid in (task_meta.get("finished_task_ids") or [])
        if tid
    }
    prev_failure_category_counts = {
        str(k): int(v or 0)
        for k, v in (task_meta.get("failure_category_counts") or {}).items()
    }
    prev_no_ping = int(task_meta.get("no_ping_devices") or 0)
    prev_ping_ok_login_fail = int(task_meta.get("ping_ok_login_fail_devices") or 0)
    prev_ping_login_ok = int(task_meta.get("ping_login_ok_devices") or 0)
    child_task_device_count = {
        str(k): int(v)
        for k, v in (task_meta.get("child_task_device_count") or {}).items()
    }

    success_tasks = 0
    failed_tasks = 0
    done_tasks = 0
    running_tasks = 0
    queued_tasks = 0
    running_pending_devices = 0
    queued_pending_devices = 0
    done_devices = 0
    estimated_in_progress_devices = 0.0
    success_devices = 0
    failed_devices = 0
    finished_task_ids = set(prev_finished_task_ids)
    operation_kind = (task_meta.get("operation_kind") or "backup_bulk").strip().lower()
    no_ping_devices = 0
    ping_ok_login_fail_devices = 0
    ping_login_ok_devices = 0
    failure_category_counts = {
        "auth": 0,
        "timeout": 0,
        "port_refused": 0,
        "vpn": 0,
        "no_ping": 0,
        "connection": 0,
        "script": 0,
        "unknown": 0,
    }

    cancel_requested = bool(task_meta.get("cancel_requested"))
    force_cancelled_ids = {
        str(tid)
        for tid in (task_meta.get("force_cancelled_child_ids") or [])
        if tid
    }

    for child_id in child_task_ids:
        async_result = celery_app.AsyncResult(child_id)
        child_task_meta = get_task_meta(child_id) or {}
        state = (async_result.state or "").upper()
        child_meta_completed = bool(child_task_meta.get("completed"))
        child_meta_status = str(child_task_meta.get("status") or "").strip().lower()
        if state in {"PENDING", "RECEIVED"} and child_meta_completed:
            if child_meta_status in {"success", "completed"}:
                state = "SUCCESS"
            elif child_meta_status in {"failed", "failure", "error", "stopped", "revoked"}:
                state = "FAILURE"

        if state == "SUCCESS":
            done_tasks += 1
            finished_task_ids.add(child_id)
            result = async_result.result
            if not isinstance(result, dict):
                cached_result = child_task_meta.get("result")
                if isinstance(cached_result, dict):
                    result = cached_result
            device_total_for_task = child_task_device_count.get(child_id, 1)
            task_success = True
            task_success_devices = 0
            task_failed_devices = 0

            if isinstance(result, dict):
                handled_by_audit = False
                if (result.get("check_type") or "").strip().lower() == "connection_audit":
                    handled_by_audit = True
                    classification = (result.get("classification") or "").strip().lower()
                    ping_ok = bool(result.get("ping_ok"))
                    login_ok = bool(result.get("login_ok"))
                    if classification == "ready" or (ping_ok and login_ok):
                        classification = "ready"
                        ping_login_ok_devices += 1
                        task_success_devices = 1
                        task_failed_devices = 0
                        task_success = True
                    elif classification == "no_ping" or not ping_ok:
                        classification = "no_ping"
                        no_ping_devices += 1
                        task_success_devices = 0
                        task_failed_devices = 1
                        task_success = False
                    else:
                        classification = "ping_ok_login_fail"
                        ping_ok_login_fail_devices += 1
                        task_success_devices = 0
                        task_failed_devices = 1
                        task_success = False
                if handled_by_audit:
                    pass
                elif "total" in result and "success" in result and "failed" in result:
                    task_success_devices = int(result.get("success") or 0)
                    task_failed_devices = int(result.get("failed") or 0)
                    for item in (result.get("details") or []):
                        if not isinstance(item, dict):
                            continue
                        if bool(item.get("success")):
                            continue
                        cat = str(item.get("failure_category") or classify_failure(item.get("message") or "")).strip().lower() or "unknown"
                        if cat not in failure_category_counts:
                            cat = "unknown"
                        failure_category_counts[cat] += 1
                    device_total_for_task = int(result.get("total") or device_total_for_task or 0)
                    task_success = task_failed_devices == 0 and task_success_devices >= 0
                elif "success" in result:
                    if not bool(result.get("success")):
                        cat = str(result.get("failure_category") or classify_failure(result.get("message") or "")).strip().lower() or "unknown"
                        if cat not in failure_category_counts:
                            cat = "unknown"
                        failure_category_counts[cat] += 1
                    if bool(result.get("success")):
                        task_success_devices = 1
                        task_failed_devices = 0
                    else:
                        task_success_devices = 0
                        task_failed_devices = 1
                        task_success = False
                elif result.get("error"):
                    task_success = False
                    task_success_devices = 0
                    task_failed_devices = max(1, device_total_for_task)
                else:
                    task_success_devices = max(1, device_total_for_task)
                    task_failed_devices = 0
            else:
                task_success_devices = max(1, device_total_for_task)
                task_failed_devices = 0

            if task_success:
                success_tasks += 1
            else:
                failed_tasks += 1

            if task_success_devices + task_failed_devices <= 0:
                task_success_devices = max(1, device_total_for_task)
                task_failed_devices = 0
            elif device_total_for_task > (task_success_devices + task_failed_devices):
                # Mantém consistência caso venha contagem parcial no resultado.
                missing = device_total_for_task - (task_success_devices + task_failed_devices)
                task_success_devices += missing

            done_devices += task_success_devices + task_failed_devices
            success_devices += task_success_devices
            failed_devices += task_failed_devices
            continue

        if state in {"FAILURE", "REVOKED"}:
            failed_tasks += 1
            done_tasks += 1
            finished_task_ids.add(child_id)
            device_total_for_task = max(1, child_task_device_count.get(child_id, 1))
            child_done_devices = max(0, int(child_task_meta.get("done_devices") or child_task_meta.get("processed_devices") or 0))
            child_success_devices = max(0, int(child_task_meta.get("success_devices") or 0))
            child_failed_devices = max(0, int(child_task_meta.get("failed_devices") or 0))
            remaining_devices = max(0, device_total_for_task - child_done_devices)
            done_devices += child_done_devices + remaining_devices
            success_devices += child_success_devices
            failed_devices += child_failed_devices + remaining_devices
            failure_category_counts["unknown"] += max(1, remaining_devices)
            if operation_kind == "connection_audit":
                ping_ok_login_fail_devices += child_failed_devices + remaining_devices
            continue

        device_total_for_task = max(1, child_task_device_count.get(child_id, 1))
        child_progress = int(child_task_meta.get("progress") or 0)
        child_done_devices = max(0, int(child_task_meta.get("done_devices") or child_task_meta.get("processed_devices") or 0))
        child_success_devices = max(0, int(child_task_meta.get("success_devices") or 0))
        child_failed_devices = max(0, int(child_task_meta.get("failed_devices") or 0))
        if state in {"STARTED", "RETRY"} and device_total_for_task > 1:
            done_devices += min(device_total_for_task, child_done_devices)
            success_devices += child_success_devices
            failed_devices += child_failed_devices
            child_fraction = max(0.0, min(0.99, float(child_task_meta.get("current_device_fraction") or 0.0)))
            if child_done_devices > 0 or child_fraction > 0:
                estimated_partial = min(
                    max(0.0, float(device_total_for_task - child_done_devices) - 0.01),
                    child_fraction,
                )
            elif child_progress > 0:
                estimated_partial = min(
                    float(device_total_for_task) - 0.01,
                    max(0.0, ((child_progress / 100) * device_total_for_task) - child_done_devices),
                )
            else:
                estimated_partial = 0.0
            estimated_in_progress_devices += max(0.0, estimated_partial)

        if cancel_requested and (
            (child_id in force_cancelled_ids)
            or (not force_cancelled_ids)
        ) and state in {"PENDING", "RECEIVED", "RETRY", "STARTED"}:
            failed_tasks += 1
            done_tasks += 1
            finished_task_ids.add(child_id)
            remaining_devices = max(0, device_total_for_task - child_done_devices)
            done_devices += remaining_devices
            failed_devices += remaining_devices
            failure_category_counts["unknown"] += remaining_devices
            if operation_kind == "connection_audit":
                ping_ok_login_fail_devices += remaining_devices
            continue

        remaining_devices_for_task = max(0, device_total_for_task - child_done_devices)
        if state == "STARTED":
            running_tasks += 1
            running_pending_devices += max(1, remaining_devices_for_task)
        else:
            queued_tasks += 1
            queued_pending_devices += max(1, remaining_devices_for_task or device_total_for_task)

    # Mantem contadores monotônicos para evitar regressão quando o backend de
    # resultados do Celery expira e estados voltam para PENDING.
    total_tasks = max(total_tasks, prev_total_tasks)
    done_tasks = max(done_tasks, prev_done_tasks)
    success_tasks = max(success_tasks, prev_success_tasks)
    failed_tasks = max(failed_tasks, prev_failed_tasks)
    done_tasks = max(done_tasks, success_tasks + failed_tasks)

    done_devices = max(done_devices, prev_done_devices)
    success_devices = max(success_devices, prev_success_devices)
    failed_devices = max(failed_devices, prev_failed_devices)
    done_devices = max(done_devices, success_devices + failed_devices)

    no_ping_devices = max(no_ping_devices, prev_no_ping)
    ping_ok_login_fail_devices = max(ping_ok_login_fail_devices, prev_ping_ok_login_fail)
    ping_login_ok_devices = max(ping_login_ok_devices, prev_ping_login_ok)
    for cat, prev_value in prev_failure_category_counts.items():
        if cat not in failure_category_counts:
            failure_category_counts[cat] = int(prev_value or 0)
        else:
            failure_category_counts[cat] = max(int(failure_category_counts[cat] or 0), int(prev_value or 0))

    total_devices = int(task_meta.get("total_devices") or 0)
    if total_devices <= 0:
        total_devices = int(done_devices + running_tasks + queued_tasks)
    total_devices = max(total_devices, prev_total_devices)
    if done_devices > total_devices:
        total_devices = done_devices

    pending_devices = max(
        0,
        total_devices - done_devices,
        running_pending_devices + queued_pending_devices,
    )

    if total_tasks <= 0:
        progress = 100
        status = "stopped" if cancel_requested else "success"
        completed = True
        message = (
            "Lote interrompido pelo usuario."
            if cancel_requested
            else "Nenhuma task pendente para este lote."
        )
    else:
        progress_base = (done_devices + estimated_in_progress_devices) if total_devices > 0 else done_tasks
        progress_total = total_devices if total_devices > 0 else total_tasks
        progress = min(100, int((progress_base / max(1, progress_total)) * 100))
        completed = bool(task_meta.get("completed")) or (done_tasks >= total_tasks)
        if completed:
            if cancel_requested:
                status = "stopped"
                if operation_kind == "connection_audit":
                    message = (
                        f"Lote interrompido: aptos={ping_login_ok_devices}, sem ping={no_ping_devices}, "
                        f"ping sem login={ping_ok_login_fail_devices} ({total_devices} total)."
                    )
                else:
                    message = (
                        f"Lote interrompido: {success_devices} dispositivos com sucesso, "
                        f"{failed_devices} com falha ({total_devices} total)."
                    )
            else:
                if operation_kind == "connection_audit":
                    status = "success"
                else:
                    status = "failed" if failed_devices > 0 else "success"
                if operation_kind == "connection_audit":
                    message = (
                        f"Lote concluido: aptos={ping_login_ok_devices}, sem ping={no_ping_devices}, "
                        f"ping sem login={ping_ok_login_fail_devices} ({total_devices} total)."
                    )
                else:
                    message = (
                        f"Lote concluido: {success_devices} dispositivos com sucesso, "
                        f"{failed_devices} com falha ({total_devices} total)."
                    )
        else:
            status = "stopping" if cancel_requested else "running"
            if progress < 5:
                progress = 5
            if cancel_requested:
                message = (
                    f"Interrompendo lote: {done_devices}/{total_devices} concluidos "
                    f"({running_tasks} grupos ativos, {pending_devices} dispositivos pendentes)."
                )
            else:
                message = (
                    f"Processando lote: {done_devices}/{total_devices} dispositivos concluidos "
                    f"({running_tasks} grupos ativos, {pending_devices} dispositivos pendentes)."
                )

    return {
        "is_bulk": True,
        "operation_kind": operation_kind,
        "status": status,
        "progress": progress,
        "completed": completed,
        "message": message,
        "total_tasks": total_tasks,
        "done_tasks": done_tasks,
        "success_tasks": success_tasks,
        "failed_tasks": failed_tasks,
        "total_devices": total_devices,
        "done_devices": done_devices,
        "success_devices": success_devices,
        "failed_devices": failed_devices,
        "running_tasks": running_tasks,
        "queued_tasks": max(0, total_tasks - done_tasks - running_tasks),
        "pending_devices": pending_devices,
        "running_pending_devices": running_pending_devices,
        "queued_pending_devices": queued_pending_devices,
        "no_ping_devices": no_ping_devices,
        "ping_ok_login_fail_devices": ping_ok_login_fail_devices,
        "ping_login_ok_devices": ping_login_ok_devices,
        "failure_category_counts": failure_category_counts,
        "finished_task_ids": sorted(finished_task_ids),
        "cancel_requested": cancel_requested,
        "transient_followup_decided": bool(task_meta.get("transient_followup_decided")),
        "transient_followup_status": task_meta.get("transient_followup_status"),
        "transient_followup_task_id": task_meta.get("transient_followup_task_id"),
        "transient_followup_bulk_task_id": task_meta.get("transient_followup_bulk_task_id"),
        "transient_followup_candidate_count": int(task_meta.get("transient_followup_candidate_count") or 0),
        "transient_followup_delay_seconds": int(task_meta.get("transient_followup_delay_seconds") or 0),
        "transient_followup_scheduled_at": task_meta.get("transient_followup_scheduled_at"),
        "transient_followup_started_at": task_meta.get("transient_followup_started_at"),
        "transient_followup_blocked_by": task_meta.get("transient_followup_blocked_by"),
        "transient_followup_categories": task_meta.get("transient_followup_categories") or {},
    }


@bp.route('/')
@login_required
def list_backups(tenant_slug):
    """Lista todos os backups do tenant com filtros e paginação."""
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404
    
    # Parâmetros de filtro
    device_id = request.args.get('device_id')
    status_filter = request.args.get('status')
    page = request.args.get('page', 1, type=int) or 1
    if page < 1:
        page = 1
    per_page = request.args.get('per_page', 25, type=int) or 25
    if per_page not in {25, 50, 100}:
        per_page = 25
    
    # Query base
    query = db.query(Backup).join(Device).filter(
        Device.tenant_id == tenant.id
    ).options(joinedload(Backup.device))
    
    # Aplica filtros
    if device_id:
        try:
            query = query.filter(Backup.device_id == uuid.UUID(device_id))
        except (ValueError, TypeError):
            logging.getLogger(__name__).warning("invalid device_id filter")
    
    if status_filter:
        try:
            query = query.filter(Backup.status == BackupStatus(status_filter))
        except ValueError:
            logging.getLogger(__name__).warning("invalid status filter")
    
    # Contagem total antes de paginar
    total = query.count()
    total_pages = max(1, (total + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages
    
    # Paginação
    backups = query.order_by(desc(Backup.created_at)).offset((page - 1) * per_page).limit(per_page).all()

    # Timeline visual + marcação de restore recomendado (mais recente com sucesso por dispositivo).
    recommended_backup_ids = set()
    timeline_days = []
    if backups:
        page_device_ids = sorted({b.device_id for b in backups if b.device_id}, key=lambda x: str(x))
        if page_device_ids:
            latest_success_rows = (
                db.query(Backup.device_id, func.max(Backup.created_at))
                .join(Device)
                .filter(
                    Device.tenant_id == tenant.id,
                    Backup.device_id.in_(page_device_ids),
                    Backup.status == BackupStatus.SUCCESS,
                )
                .group_by(Backup.device_id)
                .all()
            )
            latest_success_by_device = {str(device_id): created_at for device_id, created_at in latest_success_rows}
            for b in backups:
                if (
                    str(getattr(b, "status_value", "") or "").lower() == BackupStatus.SUCCESS.value
                    and latest_success_by_device.get(str(b.device_id)) == b.created_at
                ):
                    recommended_backup_ids.add(str(b.id))

        grouped = defaultdict(list)
        for b in backups:
            day_key = b.created_at.date() if b.created_at else None
            grouped[day_key].append(b)
        ordered_days = sorted(
            grouped.keys(),
            key=lambda d: d.isoformat() if d else "",
            reverse=True,
        )
        for day in ordered_days:
            timeline_days.append(
                {
                    "day": day,
                    "label": day.strftime('%d/%m/%Y') if day else "Sem data",
                    "items": grouped[day],
                }
            )
    
    # Lista de dispositivos para o filtro
    devices = db.query(Device).filter(
        Device.tenant_id == tenant.id,
        Device.is_active == True
    ).order_by(Device.name).all()
    
    # Estatisticas do resumo: a tela anuncia "Ultimos 7 dias", entao os cards
    # nao devem mostrar o total historico acumulado do tenant.
    stats_since = datetime.utcnow() - timedelta(days=7)
    stats_base_query = db.query(Backup).join(Device).filter(
        Device.tenant_id == tenant.id,
        Backup.created_at >= stats_since,
    )
    stats = {
        'total': stats_base_query.count(),
        'success': stats_base_query.filter(Backup.status == BackupStatus.SUCCESS).count(),
        'failed': stats_base_query.filter(Backup.status == BackupStatus.FAILED).count(),
        'days': 7,
    }
    
    db.close()
    return render_template(
        'tenant/backups/list.html',
        tenant=tenant,
        backups=backups,
        devices=devices,
        stats=stats,
        timeline_days=timeline_days,
        recommended_backup_ids=[str(i) for i in sorted(recommended_backup_ids)],
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages,
        current_device_id=device_id,
        current_status=status_filter
    )


@bp.route('/<backup_id>')
@login_required
def view_backup(tenant_slug, backup_id):
    """Exibe detalhes de um backup específico."""
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404
    
    try:
        backup_uuid = uuid.UUID(backup_id)
    except ValueError:
        db.close()
        return "Invalid backup ID", 400
    
    backup = db.query(Backup).options(
        joinedload(Backup.device).joinedload(Device.type)
    ).filter(Backup.id == backup_uuid).first()
    
    if not backup or str(backup.device.tenant_id) != str(tenant.id):
        db.close()
        return "Backup not found", 404
    
    db.close()
    return render_template(
        'tenant/backups/view.html',
        tenant=tenant,
        backup=backup
    )


@bp.route('/<backup_id>/download')
@login_required
def download_backup(tenant_slug, backup_id):
    """Faz download do arquivo de backup."""
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404
    PlanLimitsService.ensure_schema()
    
    try:
        backup_uuid = uuid.UUID(backup_id)
    except ValueError:
        db.close()
        return "Invalid backup ID", 400
    
    backup = db.query(Backup).options(
        joinedload(Backup.device).joinedload(Device.type)
    ).filter(Backup.id == backup_uuid).first()
    
    if not backup or str(backup.device.tenant_id) != str(tenant.id):
        db.close()
        return "Backup not found", 404
    
    # Build absolute file path from relative path stored in DB
    STORAGE_BASE = '/app/storage/backups'
    if backup.file_path:
        if os.path.isabs(backup.file_path):
            absolute_path = backup.file_path
        else:
            absolute_path = os.path.join(STORAGE_BASE, backup.file_path)
    else:
        absolute_path = None
    
    if not absolute_path or not os.path.exists(absolute_path):
        db.close()
        flash('Arquivo de backup não encontrado no servidor.', 'error')
        return redirect(url_for('tenant_backups.list_backups', tenant_slug=tenant_slug))

    file_size_bytes = int(backup.file_size_bytes or 0)
    if file_size_bytes <= 0:
        try:
            file_size_bytes = int(os.path.getsize(absolute_path) or 0)
        except Exception:
            file_size_bytes = 0

    quota_check = PlanLimitsService.consume_download_bytes(db, tenant, file_size_bytes)
    if not quota_check.allowed:
        db.rollback()
        db.close()
        flash(quota_check.reason, 'error')
        return redirect(url_for('tenant_backups.list_backups', tenant_slug=tenant_slug))

    db.commit()

    # Gera nome de download amigável preservando a extensao real do arquivo
    device_name = backup.device.name.replace(' ', '_')
    timestamp = backup.created_at.strftime('%Y%m%d_%H%M%S') if backup.created_at else 'unknown'
    _, source_ext = os.path.splitext(absolute_path or "")
    source_ext = (source_ext or "").strip().lower()
    if not source_ext:
        source_ext = ".rsc"
    download_name = f"{device_name}_{timestamp}{source_ext}"
    download_rate_mbps = int(getattr(getattr(tenant, "plan", None), "max_download_rate_mbps", 0) or 0)

    db.close()

    if download_rate_mbps > 0:
        bytes_per_second = max(int((download_rate_mbps * 1024 * 1024) / 8), 16 * 1024)
        chunk_size = min(256 * 1024, bytes_per_second)

        def _throttled_stream():
            with open(absolute_path, 'rb') as fh:
                while True:
                    chunk = fh.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
                    time.sleep(max(len(chunk) / bytes_per_second, 0.0))

        response = Response(stream_with_context(_throttled_stream()), mimetype='application/octet-stream')
        response.headers['Content-Disposition'] = f'attachment; filename="{download_name}"'
        response.headers['Content-Length'] = str(file_size_bytes or os.path.getsize(absolute_path))
        response.headers['X-Plan-Download-Limit-Mbps'] = str(download_rate_mbps)
        return response

    return send_file(absolute_path, as_attachment=True, download_name=download_name)


@bp.route('/tasks/<task_id>/status')
@login_required
def task_status(tenant_slug, task_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return jsonify({"ok": False, "error": "Tenant not found"}), 404

    task_meta = get_task_meta(task_id)
    db.close()

    if not task_meta:
        return jsonify({"ok": False, "error": "Task not found"}), 404

    if task_meta.get("tenant_id") and str(task_meta.get("tenant_id")) != str(tenant.id):
        return jsonify({"ok": False, "error": "Forbidden"}), 403

    async_result = celery_app.AsyncResult(task_id)
    celery_state = async_result.state

    # Se não houver atualização final no meta, inferimos do estado Celery.
    status = task_meta.get("status") or "queued"
    progress = int(task_meta.get("progress") or 0)
    message = task_meta.get("message") or "Aguardando atualizacao..."
    completed = bool(task_meta.get("completed"))

    if celery_state == "STARTED" and progress < 5:
        progress = 5
        status = "running"
        message = "Task iniciada no worker."
    elif celery_state == "SUCCESS" and not completed:
        result = async_result.result
        result_failed = isinstance(result, dict) and (
            result.get("success") is False or bool(result.get("error"))
        )
        if result_failed:
            status = "failed"
            message = (
                str(result.get("message") or result.get("error"))
                if isinstance(result, dict)
                else "Task finalizada com erro."
            )
        else:
            status = "success"
            message = message or "Task concluida com sucesso."
        progress = 100
        completed = True
    elif celery_state == "FAILURE":
        status = "failed"
        progress = 100
        completed = True
        if not task_meta.get("error"):
            message = "Task finalizada com erro."

    return jsonify({
        "ok": True,
        "task_id": task_id,
        "status": status,
        "progress": max(0, min(progress, 100)),
        "message": message,
        "completed": completed,
        "celery_state": celery_state,
        "device_name": task_meta.get("device_name"),
        "updated_at": task_meta.get("updated_at"),
        # Campos necessários para o botão de stop no modal funcionar para tasks individuais
        "is_bulk": False,
        "cancel_url": url_for('tenant_backups.cancel_task', tenant_slug=tenant_slug, task_id=task_id)
            if not completed and celery_state not in {"SUCCESS", "FAILURE", "REVOKED"}
            else None,
    })


@bp.route('/tasks/<task_id>/cancel', methods=['POST'])
@login_required
def cancel_task(tenant_slug, task_id):
    """Cancela um backup individual em execução ou na fila."""
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return jsonify({"ok": False, "error": "Tenant not found"}), 404

    task_meta = get_task_meta(task_id)
    db.close()
    if not task_meta:
        return jsonify({"ok": False, "error": "Task not found"}), 404
    if task_meta.get("tenant_id") and str(task_meta.get("tenant_id")) != str(tenant.id):
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    if task_meta.get("is_bulk"):
        return jsonify({"ok": False, "error": "Use /bulk/<task_id>/cancel para lotes"}), 400

    revoke_requested = 0
    try:
        async_result = celery_app.AsyncResult(task_id)
        if async_result.state not in {"SUCCESS", "FAILURE", "REVOKED"}:
            # SIGTERM primeiro — se o worker cooperar, termina limpo
            celery_app.control.revoke(task_id, terminate=True, signal='SIGTERM')
            revoke_requested = 1
    except Exception:
        logging.getLogger(__name__).exception("Falha ao revogar task individual %s", task_id)

    # Flag global com TTL maior — garante que a task perceba o stop mesmo se o
    # pexpect demorar para retornar do expect() atual (ex: OLT ZTE com config de 17MB)
    try:
        r = get_redis_client()
        if r:
            r.setex("backup_center:force_stop_backups", 60 * 30, "1")
    except Exception:
        pass

    update_task_meta(
        task_id,
        status="stopped",
        completed=True,
        progress=100,
        message="Backup interrompido pelo operador.",
    )
    append_task_log(task_id, task_meta.get("device_name") or "Sistema",
                    "Parada solicitada pelo operador. Revogação enviada.", "warning")

    return jsonify({
        "ok": True,
        "task_id": task_id,
        "status": "stopped",
        "revoke_requested": revoke_requested,
    })


@bp.route('/tasks/<task_id>/logs')
@login_required
def task_logs(tenant_slug, task_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return jsonify({"ok": False, "error": "Tenant not found"}), 404

    task_meta = get_task_meta(task_id)
    db.close()

    if not task_meta:
        return jsonify({"ok": False, "error": "Task not found"}), 404

    if task_meta.get("tenant_id") and str(task_meta.get("tenant_id")) != str(tenant.id):
        return jsonify({"ok": False, "error": "Forbidden"}), 403

    try:
        after_seq = int(request.args.get("after", 0))
    except (TypeError, ValueError):
        after_seq = 0

    logs = get_task_logs(task_id, after_seq=after_seq, limit=150)
    return jsonify({
        "ok": True,
        "task_id": task_id,
        "entries": logs["entries"],
        "last_seq": logs["last_seq"],
    })


@bp.route('/bulk/<task_id>/status')
@login_required
def bulk_task_status(tenant_slug, task_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return jsonify({"ok": False, "error": "Tenant not found"}), 404

    task_meta = get_task_meta(task_id)
    db.close()

    if not task_meta:
        return jsonify({"ok": False, "error": "Task not found"}), 404

    if task_meta.get("tenant_id") and str(task_meta.get("tenant_id")) != str(tenant.id):
        return jsonify({"ok": False, "error": "Forbidden"}), 403

    if not task_meta.get("is_bulk"):
        return jsonify({"ok": False, "error": "Task is not a bulk operation"}), 400

    now_ts = time.time()
    current = dict(task_meta or {})
    should_refresh = False
    if not bool(current.get("completed")):
        last_refresh = float(current.get("bulk_last_refresh_ts") or 0.0)
        should_refresh = (now_ts - last_refresh) >= _bulk_status_refresh_min_interval_seconds()
    elif not current.get("status"):
        should_refresh = True

    if should_refresh:
        refreshed = _refresh_bulk_task_meta(task_id, current)
        refreshed["bulk_last_refresh_ts"] = now_ts
        update_task_meta(task_id, **refreshed)
        current.update(refreshed)

    return jsonify({
        "ok": True,
        "task_id": task_id,
        "is_bulk": True,
        "operation_kind": current.get("operation_kind") or "backup_bulk",
        "status": current.get("status"),
        "progress": int(current.get("progress") or 0),
        "message": current.get("message"),
        "completed": bool(current.get("completed")),
        "total_devices": int(current.get("total_devices") or 0),
        "queued_direct": int(current.get("queued_direct") or 0),
        "queued_vpn_groups": int(current.get("queued_vpn_groups") or 0),
        "skipped_not_ready": int(current.get("skipped_not_ready") or 0),
        "skipped_jump_unreachable": int(current.get("skipped_jump_unreachable") or 0),
        "skipped_jump_device_ids": current.get("skipped_jump_device_ids") or [],
        "skipped_mass_excluded": int(current.get("skipped_mass_excluded") or 0),
        "total_tasks": int(current.get("total_tasks") or 0),
        "done_tasks": int(current.get("done_tasks") or 0),
        "success_tasks": int(current.get("success_tasks") or 0),
        "failed_tasks": int(current.get("failed_tasks") or 0),
        "done_devices": int(current.get("done_devices") or 0),
        "success_devices": int(current.get("success_devices") or 0),
        "failed_devices": int(current.get("failed_devices") or 0),
        "running_tasks": int(current.get("running_tasks") or 0),
        "queued_tasks": int(current.get("queued_tasks") or 0),
        "pending_devices": int(current.get("pending_devices") or 0),
        "running_pending_devices": int(current.get("running_pending_devices") or 0),
        "queued_pending_devices": int(current.get("queued_pending_devices") or 0),
        "no_ping_devices": int(current.get("no_ping_devices") or 0),
        "ping_ok_login_fail_devices": int(current.get("ping_ok_login_fail_devices") or 0),
        "ping_login_ok_devices": int(current.get("ping_login_ok_devices") or 0),
        "failure_category_counts": current.get("failure_category_counts") or {},
        "transient_followup_decided": bool(current.get("transient_followup_decided")),
        "transient_followup_status": current.get("transient_followup_status"),
        "transient_followup_task_id": current.get("transient_followup_task_id"),
        "transient_followup_bulk_task_id": current.get("transient_followup_bulk_task_id"),
        "transient_followup_candidate_count": int(current.get("transient_followup_candidate_count") or 0),
        "transient_followup_delay_seconds": int(current.get("transient_followup_delay_seconds") or 0),
        "transient_followup_scheduled_at": current.get("transient_followup_scheduled_at"),
        "transient_followup_started_at": current.get("transient_followup_started_at"),
        "transient_followup_blocked_by": current.get("transient_followup_blocked_by"),
        "transient_followup_categories": current.get("transient_followup_categories") or {},
        "group_summary": current.get("group_summary") or [],
        "cancel_requested": bool(current.get("cancel_requested")),
        "cancel_url": url_for('tenant_backups.cancel_bulk_task', tenant_slug=tenant_slug, task_id=task_id),
        "updated_at": current.get("updated_at"),
    })


@bp.route('/bulk/<task_id>/cancel', methods=['POST'])
@login_required
def cancel_bulk_task(tenant_slug, task_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return jsonify({"ok": False, "error": "Tenant not found"}), 404

    task_meta = get_task_meta(task_id)
    db.close()
    if not task_meta:
        return jsonify({"ok": False, "error": "Task not found"}), 404
    if task_meta.get("tenant_id") and str(task_meta.get("tenant_id")) != str(tenant.id):
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    if not task_meta.get("is_bulk"):
        return jsonify({"ok": False, "error": "Task is not a bulk operation"}), 400

    child_task_ids = [str(tid) for tid in (task_meta.get("child_task_ids") or []) if tid]
    revoke_requested = 0
    force_cancelled_child_ids = []
    operation_kind = str(task_meta.get("operation_kind") or "").strip().lower()
    revoke_signal = "SIGKILL" if operation_kind == "connection_audit" else "SIGTERM"
    for child_id in child_task_ids:
        async_result = celery_app.AsyncResult(child_id)
        if async_result.state in {"SUCCESS", "FAILURE", "REVOKED"}:
            continue
        try:
            celery_app.control.revoke(child_id, terminate=True, signal=revoke_signal)
            revoke_requested += 1
            force_cancelled_child_ids.append(child_id)
        except Exception:
            logging.getLogger(__name__).exception("Falha ao revogar child task %s", child_id)

    try:
        r = get_redis_client()
        if r:
            # TTL curto para que tasks em execucao percebam a parada mesmo quando a
            # revogacao do Celery nao interrompe imediatamente a task ativa.
            r.setex("backup_center:force_stop_backups", 60 * 30, "1")
    except Exception:
        logging.getLogger(__name__).exception("Falha ao definir bloqueio global temporario ao cancelar lote %s", task_id)

    update_task_meta(
        task_id,
        cancel_requested=True,
        status="stopping",
        completed=False,
        message="Solicitacao de parada recebida. Interrompendo tasks em andamento...",
        force_cancelled_child_ids=force_cancelled_child_ids,
        cancel_requested_at=int(time.time()),
    )
    append_task_log(
        task_id,
        "Backup em massa",
        f"Parada solicitada pelo usuario. Revogacao enviada para {revoke_requested} task(s).",
        "warning",
    )
    return jsonify({
        "ok": True,
        "task_id": task_id,
        "status": "stopping",
        "revoke_requested": revoke_requested,
    })


@bp.route('/bulk/<task_id>/logs')
@login_required
def bulk_task_logs(tenant_slug, task_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return jsonify({"ok": False, "error": "Tenant not found"}), 404

    task_meta = get_task_meta(task_id)
    db.close()

    if not task_meta:
        return jsonify({"ok": False, "error": "Task not found"}), 404

    if task_meta.get("tenant_id") and str(task_meta.get("tenant_id")) != str(tenant.id):
        return jsonify({"ok": False, "error": "Forbidden"}), 403

    if not task_meta.get("is_bulk"):
        return jsonify({"ok": False, "error": "Task is not a bulk operation"}), 400

    try:
        after_seq = int(request.args.get("after", 0))
    except (TypeError, ValueError):
        after_seq = 0

    child_task_ids = [str(tid) for tid in (task_meta.get("child_task_ids") or []) if tid]
    allowed_task_ids = set(child_task_ids + [str(task_id)])

    # Keep payloads bounded; large responses under frequent polling can saturate uvicorn.
    global_logs = get_global_logs(after_seq=after_seq, limit=100, tenant_id=str(tenant.id))
    entries = [
        entry
        for entry in (global_logs.get("entries") or [])
        if str(entry.get("task_id") or "") in allowed_task_ids
    ]

    return jsonify({
        "ok": True,
        "task_id": task_id,
        "entries": entries,
        "last_seq": int(global_logs.get("last_seq") or after_seq),
    })


@bp.route('/logs/global')
@login_required
def global_backup_logs(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return jsonify({"ok": False, "error": "Tenant not found"}), 404
    db.close()

    try:
        after_seq = int(request.args.get("after", 0))
    except (TypeError, ValueError):
        after_seq = 0

    logs = get_global_logs(after_seq=after_seq, limit=120, tenant_id=str(tenant.id))
    return jsonify({
        "ok": True,
        "entries": logs["entries"],
        "last_seq": logs["last_seq"],
    })


def _classify_backup_error(message: str) -> str:
    category = classify_failure(message or "")
    if category == "auth":
        return "auth"
    if category in {"timeout", "port_refused", "vpn", "no_ping", "connection"}:
        return "conn"
    return "other"


@bp.route('/failed/clear', methods=['POST'])
@login_required
@tenant_admin_required
def clear_failed_backups(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404

    return_to = (request.form.get('return_to') or 'backups').strip().lower()
    STORAGE_BASE = '/app/storage/backups'
    deleted = 0
    files_removed = 0

    try:
        failed_backups = (
            db.query(Backup)
            .join(Device)
            .filter(
                Device.tenant_id == tenant.id,
                Backup.status == BackupStatus.FAILED,
            )
            .all()
        )

        for backup in failed_backups:
            file_path = (backup.file_path or "").strip()
            absolute_path = None
            if file_path:
                absolute_path = file_path if os.path.isabs(file_path) else os.path.join(STORAGE_BASE, file_path)
            if absolute_path and os.path.exists(absolute_path):
                try:
                    os.remove(absolute_path)
                    files_removed += 1
                except OSError:
                    logging.getLogger(__name__).warning("Falha ao remover arquivo de backup failed: %s", absolute_path)
            db.delete(backup)
            deleted += 1

        user_id = session.get('user_id')
        details = f"Limpeza manual de backups failed: removidos={deleted}, arquivos={files_removed}."
        from app.services.activity_service import ActivityService
        ActivityService.log_action(
            db,
            tenant.id,
            user_id,
            "CLEAR_FAILED_BACKUPS",
            details,
            request.remote_addr,
        )
    finally:
        db.close()

    is_ajax = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in (request.headers.get('Accept') or '')
    )
    if is_ajax:
        return jsonify({"ok": True, "deleted": deleted, "files_removed": files_removed})

    flash(f"Backups com status failed removidos: {deleted} (arquivos removidos: {files_removed}).", 'success')
    if return_to == 'schedules':
        return redirect(url_for('tenant_schedules.list_schedules', tenant_slug=tenant_slug))
    return redirect(url_for('tenant_backups.list_backups', tenant_slug=tenant_slug, status='failed'))


@bp.route('/issues')
@login_required
def failed_devices(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404

    latest_per_device = (
        db.query(
            Backup.device_id.label("device_id"),
            func.max(Backup.created_at).label("max_created_at"),
        )
        .join(Device, Device.id == Backup.device_id)
        .filter(Device.tenant_id == tenant.id)
        .group_by(Backup.device_id)
        .subquery()
    )

    rows = (
        db.query(Backup)
        .join(Device, Device.id == Backup.device_id)
        .join(
            latest_per_device,
            (Backup.device_id == latest_per_device.c.device_id)
            & (Backup.created_at == latest_per_device.c.max_created_at),
        )
        .options(joinedload(Backup.device).joinedload(Device.group), joinedload(Backup.device).joinedload(Device.type))
        .filter(Device.tenant_id == tenant.id, Backup.status == BackupStatus.FAILED)
        .order_by(desc(Backup.created_at))
        .all()
    )

    auth_errors = []
    conn_errors = []
    other_errors = []
    detailed_counts = defaultdict(int)
    for backup in rows:
        detailed_category = classify_failure(backup.error_message or "")
        detailed_counts[detailed_category] += 1
        setattr(backup, "_failure_category", detailed_category)
        setattr(backup, "_failure_label", failure_label(detailed_category))
        category = _classify_backup_error(backup.error_message or "")
        if category == "auth":
            auth_errors.append(backup)
        elif category == "conn":
            conn_errors.append(backup)
        else:
            other_errors.append(backup)

    detailed_breakdown = [
        {"category": cat, "label": failure_label(cat), "count": int(count)}
        for cat, count in sorted(detailed_counts.items(), key=lambda item: (-item[1], item[0]))
    ]

    db.close()
    return render_template(
        'tenant/backups/issues.html',
        tenant=tenant,
        auth_errors=auth_errors,
        conn_errors=conn_errors,
        other_errors=other_errors,
        detailed_breakdown=detailed_breakdown,
    )
