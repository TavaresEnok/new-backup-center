from datetime import datetime
import re
from collections import Counter
import json

from flask import Blueprint, render_template, request, session, abort, redirect, url_for, flash, jsonify
from app.web.auth.decorators import login_required, tenant_admin_required
from app.core.database import SessionLocal
from app.models.tenant import Tenant
from app.models.schedule import Schedule, ScheduleFrequency
from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.models.user import UserRole
from sqlalchemy import or_
from sqlalchemy.orm import joinedload
from app.services.activity_service import ActivityService
from app.celery_app import celery_app
from app.services.realtime_backup_logs import get_redis_client, release_tenant_bulk_lock
from app.services.schedule_utils import compute_next_daily_run_at, sanitize_daily_time
from app.services.device_service import DeviceService
from app.services.mass_backup_scope import resolve_mass_backup_excluded_type_ids

bp = Blueprint('tenant_schedules', __name__, url_prefix='/tenant/<tenant_slug>/schedules')

def get_db_and_tenant(tenant_slug):
    if session.get('user_role') != UserRole.SUPER_ADMIN.value and session.get('tenant_slug') != tenant_slug:
        abort(403)
    db = SessionLocal()
    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
    if not tenant:
        db.close()
    return db, tenant


def _next_daily_run(time_str: str, now: datetime | None = None) -> datetime:
    return compute_next_daily_run_at(time_str=time_str, reference_utc=now)


def _is_valid_time(value: str) -> bool:
    return bool(re.match(r"^([01]\d|2[0-3]):([0-5]\d)$", value or ""))


def _resolve_return_url(tenant_slug: str, return_to: str | None):
    if (return_to or "").strip() == "operations":
        return url_for("tenant_operations.index", tenant_slug=tenant_slug)
    return url_for("tenant_schedules.list_schedules", tenant_slug=tenant_slug)


def _apply_daily_to_devices(db, devices, time_str: str, apply_scope: str) -> int:
    if not devices:
        return 0

    device_ids = [d.id for d in devices]
    existing = db.query(Schedule).filter(Schedule.device_id.in_(device_ids)).all()
    schedules_by_device = {}
    active_schedule_device_ids = set()
    for schedule in existing:
        current = schedules_by_device.get(schedule.device_id)
        if not current or (not current.is_active and schedule.is_active):
            schedules_by_device[schedule.device_id] = schedule
        if schedule.is_active:
            active_schedule_device_ids.add(schedule.device_id)

    if apply_scope == "missing":
        target_devices = [
            device for device in devices
            if not (device.backup_scheduled and device.id in active_schedule_device_ids)
        ]
    else:
        target_devices = devices

    for device in target_devices:
        device.backup_scheduled = True
        schedule = schedules_by_device.get(device.id)
        if not schedule:
            schedule = Schedule(device_id=device.id)
            db.add(schedule)

        schedule.frequency = ScheduleFrequency.DAILY
        schedule.time = sanitize_daily_time(time_str)
        schedule.day_of_week = None
        schedule.day_of_month = None
        schedule.is_active = True
        schedule.next_run_at = _next_daily_run(time_str)

    return len(target_devices)


@bp.route('/')
@login_required
def list_schedules(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404
        
    show_details = request.args.get('details') == '1'
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 25, type=int)
    missing_page = request.args.get('missing_page', 1, type=int)
    missing_per_page = request.args.get('missing_per_page', 20, type=int)
    page = max(page, 1)
    per_page = max(10, min(per_page, 100))
    missing_page = max(missing_page, 1)
    missing_per_page = max(10, min(missing_per_page, 100))

    schedules = []
    total_pages = 1
    start_idx = 0
    end_idx = 0

    operational_group_filter = or_(Device.group_id.is_(None), DeviceGroup.is_active.is_(True))

    active_devices = db.query(Device).outerjoin(
        DeviceGroup,
        Device.group_id == DeviceGroup.id,
    ).filter(
        Device.tenant_id == tenant.id,
        Device.is_active == True,
        operational_group_filter,
    ).options(
        joinedload(Device.group)
    ).all()

    inactive_group_devices = db.query(Device).join(
        DeviceGroup,
        Device.group_id == DeviceGroup.id,
    ).filter(
        Device.tenant_id == tenant.id,
        Device.is_active == True,
        DeviceGroup.is_active == False,
    ).count()

    active_groups = db.query(DeviceGroup).filter(
        DeviceGroup.tenant_id == tenant.id,
        DeviceGroup.is_active == True
    ).order_by(DeviceGroup.name.asc()).all()

    active_schedule_rows = (
        db.query(Schedule.device_id, Schedule.frequency, Schedule.time)
        .join(Device)
        .outerjoin(DeviceGroup, Device.group_id == DeviceGroup.id)
        .filter(
            Device.tenant_id == tenant.id,
            Device.is_active == True,
            operational_group_filter,
            Schedule.is_active == True,
        )
        .all()
    )

    active_schedule_device_ids = {row.device_id for row in active_schedule_rows}
    mass_excluded_type_ids = resolve_mass_backup_excluded_type_ids(db)
    mass_excluded_devices = 0
    mass_backup_eligible_devices = 0

    with_schedule = 0
    without_schedule = 0
    group_overview_map = {}
    for group in active_groups:
        group_overview_map[str(group.id)] = {
            "group_id": str(group.id),
            "name": group.name,
            "connection_type": group.connection_type or "direct",
            "uses_jump_host": bool(getattr(group, "uses_jump_host", False)),
            "is_active": bool(getattr(group, "is_active", True)),
            "total": 0,
            "with_schedule": 0,
            "without_schedule": 0,
            "auto_disabled": 0,
            "coverage_pct": 0,
        }

    group_overview_map["__ungrouped__"] = {
        "group_id": None,
        "name": "Sem grupo",
        "connection_type": "direct",
        "uses_jump_host": False,
        "is_active": True,
        "total": 0,
        "with_schedule": 0,
        "without_schedule": 0,
        "auto_disabled": 0,
        "coverage_pct": 0,
    }

    for device in active_devices:
        if getattr(device, "device_type_id", None) in mass_excluded_type_ids:
            mass_excluded_devices += 1
        else:
            mass_backup_eligible_devices += 1

        auto_enabled = bool(device.backup_scheduled)
        in_global_routine = auto_enabled and device.id in active_schedule_device_ids
        if in_global_routine:
            with_schedule += 1
        else:
            without_schedule += 1

        if device.group_id:
            group_key = str(device.group_id)
            if group_key not in group_overview_map:
                group_overview_map[group_key] = {
                    "group_id": str(device.group_id),
                    "name": (device.group.name if device.group else "Grupo removido"),
                    "connection_type": (device.group.connection_type if device.group else "direct"),
                    "uses_jump_host": bool(getattr(device.group, "uses_jump_host", False)),
                    "is_active": bool(getattr(device.group, "is_active", True)),
                    "total": 0,
                    "with_schedule": 0,
                    "without_schedule": 0,
                    "auto_disabled": 0,
                    "coverage_pct": 0,
                }
        else:
            group_key = "__ungrouped__"

        bucket = group_overview_map[group_key]
        bucket["total"] += 1
        if in_global_routine:
            bucket["with_schedule"] += 1
        else:
            bucket["without_schedule"] += 1
        if not auto_enabled:
            bucket["auto_disabled"] += 1

    daily_times = []
    for row in active_schedule_rows:
        frequency_val = row.frequency.value if hasattr(row.frequency, "value") else str(row.frequency)
        if frequency_val == "daily" and row.time:
            daily_times.append(sanitize_daily_time(row.time))

    default_daily_time = Counter(daily_times).most_common(1)[0][0] if daily_times else "02:00"

    schedule_overview = {
        "total_active_devices": len(active_devices),
        "with_schedule": with_schedule,
        "without_schedule": without_schedule,
        "mass_backup_eligible_devices": mass_backup_eligible_devices,
        "mass_backup_excluded_devices": mass_excluded_devices,
        "inactive_group_devices": inactive_group_devices,
        "queue_disabled": 0,
        "default_daily_time": default_daily_time,
    }

    group_overview = []
    for group_data in group_overview_map.values():
        if group_data["total"] == 0:
            continue
        group_data["coverage_pct"] = int(round((group_data["with_schedule"] / group_data["total"]) * 100))
        group_overview.append(group_data)
    group_overview.sort(key=lambda g: (g["name"] == "Sem grupo", g["name"].lower()))

    missing_auto_device_ids = [
        device.id
        for device in active_devices
        if not (bool(device.backup_scheduled) and device.id in active_schedule_device_ids)
    ]
    missing_auto_total = len(missing_auto_device_ids)
    schedule_overview["queue_disabled"] = missing_auto_total
    missing_auto_total_pages = (missing_auto_total + missing_per_page - 1) // missing_per_page if missing_auto_total > 0 else 1
    if missing_page > missing_auto_total_pages:
        missing_page = missing_auto_total_pages
    if missing_auto_device_ids:
        missing_auto_devices = (
            db.query(Device)
            .options(joinedload(Device.group))
            .filter(Device.id.in_(missing_auto_device_ids))
            .order_by(Device.name.asc())
            .offset((missing_page - 1) * missing_per_page)
            .limit(missing_per_page)
            .all()
        )
    else:
        missing_auto_devices = []
    missing_auto_start = ((missing_page - 1) * missing_per_page) + 1 if missing_auto_total > 0 else 0
    missing_auto_end = min(missing_page * missing_per_page, missing_auto_total)
        
    db.close()
    return render_template(
        'tenant/schedules/list.html',
        tenant=tenant,
        schedules=schedules,
        schedule_overview=schedule_overview,
        show_details=show_details,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        start_idx=start_idx,
        end_idx=end_idx,
        group_overview=group_overview,
        missing_auto_devices=missing_auto_devices,
        missing_auto_total=missing_auto_total,
        missing_auto_page=missing_page,
        missing_auto_per_page=missing_per_page,
        missing_auto_total_pages=missing_auto_total_pages,
        missing_auto_start=missing_auto_start,
        missing_auto_end=missing_auto_end,
    )


@bp.route('/apply-daily', methods=['POST'])
@login_required
@tenant_admin_required
def apply_daily_schedule(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404

    time_str = (request.form.get('daily_time') or '').strip()
    apply_scope = (request.form.get('apply_scope') or 'missing').strip()
    return_to = (request.form.get('return_to') or '').strip()
    if apply_scope not in {'missing', 'all'}:
        apply_scope = 'missing'

    if not _is_valid_time(time_str):
        flash('Horario invalido. Use o formato HH:MM.', 'error')
        db.close()
        return redirect(_resolve_return_url(tenant_slug, return_to))

    devices = db.query(Device).outerjoin(
        DeviceGroup,
        Device.group_id == DeviceGroup.id,
    ).filter(
        Device.tenant_id == tenant.id,
        Device.is_active == True,
        or_(Device.group_id.is_(None), DeviceGroup.is_active.is_(True)),
    ).all()

    if not devices:
        flash('Nenhum dispositivo ativo encontrado para aplicar agendamento.', 'warning')
        db.close()
        return redirect(_resolve_return_url(tenant_slug, return_to))

    affected = _apply_daily_to_devices(db, devices, time_str, apply_scope)

    if affected == 0:
        flash('Nenhum dispositivo precisa de sincronizacao no modo selecionado.', 'info')
        db.close()
        return redirect(_resolve_return_url(tenant_slug, return_to))

    user_id = session.get('user_id')
    ActivityService.log_action(
        db,
        tenant.id,
        user_id,
        "BULK_SCHEDULE_UPDATE",
        f"Aplicado agendamento diario {time_str} para {affected} dispositivos (modo={apply_scope}).",
        request.remote_addr,
    )

    db.commit()
    db.close()

    if apply_scope == 'missing':
        flash(f'Rotina diaria {time_str} sincronizada para {affected} dispositivos pendentes.', 'success')
    else:
        flash(f'Rotina diaria {time_str} regravada para {affected} dispositivos ativos.', 'success')
    return redirect(_resolve_return_url(tenant_slug, return_to))


@bp.route('/enable-backup-queue', methods=['POST'])
@login_required
@tenant_admin_required
def enable_backup_queue_all(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404

    return_to = (request.form.get('return_to') or '').strip()

    devices = db.query(Device).outerjoin(
        DeviceGroup,
        Device.group_id == DeviceGroup.id,
    ).filter(
        Device.tenant_id == tenant.id,
        Device.is_active == True,
        or_(Device.group_id.is_(None), DeviceGroup.is_active.is_(True)),
    ).all()

    if not devices:
        db.close()
        flash('Todos os dispositivos ativos ja estao com backup automatico habilitado e rotina sincronizada.', 'info')
        return redirect(_resolve_return_url(tenant_slug, return_to))

    daily_time = DeviceService._infer_tenant_daily_schedule_time(db, tenant.id)
    affected = _apply_daily_to_devices(db, devices, daily_time, "missing")
    if affected == 0:
        db.close()
        flash('Todos os dispositivos ativos ja estao com backup automatico habilitado e rotina sincronizada.', 'info')
        return redirect(_resolve_return_url(tenant_slug, return_to))

    user_id = session.get('user_id')
    ActivityService.log_action(
        db,
        tenant.id,
        user_id,
        "BULK_BACKUP_QUEUE_ENABLE",
        f"Backup automatico habilitado e rotina sincronizada para {affected} dispositivos ativos.",
        request.remote_addr,
    )

    db.commit()
    db.close()
    flash(f'Backup automatico habilitado e rotina sincronizada para {affected} dispositivos ativos.', 'success')
    return redirect(_resolve_return_url(tenant_slug, return_to))


def _is_backup_task_name(task_name: str) -> bool:
    name = str(task_name or '')
    if name.startswith('app.tasks.backups.'):
        return True
    # Inclui testes de conexao em massa para que "Parar tudo" atue neles tambem.
    if name.startswith('app.tasks.monitoring.run_device_connection_audit_task'):
        return True
    if name.startswith('app.tasks.monitoring.run_connection_test_task'):
        return True
    return False


def _stop_backup_tasks_globally() -> dict:
    """
    Interrompe tasks de backup ativas/pendentes e marca lotes bulk em aberto como interrompidos.
    """
    inspect = celery_app.control.inspect(timeout=1.0)
    matched = 0
    revoked = 0

    for getter_name in ('active', 'reserved', 'scheduled'):
        getter = getattr(inspect, getter_name, None)
        if not getter:
            continue
        data = getter() or {}
        for _worker, tasks in data.items():
            for item in (tasks or []):
                task_name = item.get('name') if isinstance(item, dict) else None
                req = item.get('request') if isinstance(item, dict) else None
                if not task_name and isinstance(req, dict):
                    task_name = req.get('name')
                if not _is_backup_task_name(task_name):
                    continue
                task_id = item.get('id') if isinstance(item, dict) else None
                if not task_id and isinstance(req, dict):
                    task_id = req.get('id')
                if not task_id:
                    continue
                matched += 1
                try:
                    is_running = getter_name == 'active'
                    is_vpn_group_task = str(task_name or '').endswith('run_vpn_group_backups_task')
                    # Evita SIGKILL/SIGTERM em task VPN ativa (nmcli em network_mode host),
                    # reduzindo risco de derrubar conectividade da VM.
                    if is_running and not is_vpn_group_task:
                        celery_app.control.revoke(str(task_id), terminate=True, signal='SIGTERM')
                    else:
                        celery_app.control.revoke(str(task_id))
                    revoked += 1
                except Exception:
                    pass

    queue_removed = 0
    bulk_marked = 0
    r = get_redis_client()
    if r:
        # Trava global temporaria para impedir novas execucoes enquanto o operador estabiliza o ambiente.
        try:
            r.setex('backup_center:force_stop_backups', 60 * 30, '1')
        except Exception:
            pass

        for queue_name in ('celery', 'vpn_queue'):
            try:
                queue_len = int(r.llen(queue_name) or 0)
                if queue_len > 0:
                    r.delete(queue_name)
                    queue_removed += queue_len
            except Exception:
                pass

        try:
            for key in r.scan_iter('backup_center:task_meta:*'):
                raw = r.get(key)
                if not raw:
                    continue
                try:
                    meta = json.loads(raw)
                except Exception:
                    continue
                if meta.get('is_bulk') and not meta.get('completed'):
                    meta['cancel_requested'] = True
                    meta['status'] = 'stopped'
                    meta['completed'] = True
                    meta['progress'] = 100
                    meta['message'] = 'Lote interrompido manualmente pela central de agendamentos.'
                    r.setex(key, 60 * 60 * 48, json.dumps(meta, ensure_ascii=False))
                    release_tenant_bulk_lock(meta.get('tenant_id'), meta.get('task_id'))
                    bulk_marked += 1
        except Exception:
            pass

    return {
        'matched_runtime_tasks': matched,
        'revoked_runtime_tasks': revoked,
        'removed_queued_tasks': queue_removed,
        'bulk_marked_stopped': bulk_marked,
    }


@bp.route('/stop-all-backups', methods=['POST'])
@login_required
@tenant_admin_required
def stop_all_backups(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return 'Tenant not found', 404

    stats = _stop_backup_tasks_globally()

    user_id = session.get('user_id')
    details = (
        f"Stop all backups requested: revoked={stats['revoked_runtime_tasks']} "
        f"queued_removed={stats['removed_queued_tasks']} bulk_marked={stats['bulk_marked_stopped']}"
    )
    ActivityService.log_action(db, tenant.id, user_id, 'BACKUP_STOP_ALL', details, request.remote_addr)
    db.close()

    is_ajax = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in (request.headers.get('Accept') or '')
    )
    if is_ajax:
        return jsonify({'ok': True, **stats})

    flash(
        'Parada global executada. '
        f"Revogadas: {stats['revoked_runtime_tasks']} | "
        f"Fila removida: {stats['removed_queued_tasks']} | "
        f"Lotes finalizados: {stats['bulk_marked_stopped']}.",
        'warning',
    )
    return redirect(url_for('tenant_schedules.list_schedules', tenant_slug=tenant_slug))
