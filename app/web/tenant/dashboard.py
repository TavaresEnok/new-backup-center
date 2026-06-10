from flask import Blueprint, render_template, session, redirect, url_for, flash, abort
from app.web.auth.decorators import login_required
from app.core.database import SessionLocal
from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.core.config import settings
from app.models.device_type import DeviceType
from app.models.backup import Backup, BackupStatus
from app.models.schedule import Schedule
from app.models.tenant import Tenant
from app.models.user import UserRole
from app.services.plan_limits_service import PlanLimitsService
from app.services.mass_backup_scope import resolve_mass_backup_excluded_type_ids
from sqlalchemy import func, or_
from sqlalchemy.orm import joinedload
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import json
import psutil
from flask import jsonify

bp = Blueprint('tenant', __name__, url_prefix='/tenant')

@bp.route('/<tenant_slug>/server-metrics')
@login_required
def server_metrics(tenant_slug):
    # Cross-tenant check
    if session.get('user_role') != UserRole.SUPER_ADMIN.value and session.get('tenant_slug') != tenant_slug:
        abort(403)

    import time as _time

    # CPU: sample over 1 second using cpu_times_percent (same as top/htop)
    cpu_times = psutil.cpu_times_percent(interval=1)
    cpu_percent = round(cpu_times.user + cpu_times.system, 1)

    # RAM
    ram = psutil.virtual_memory()

    # Disk usage (space)
    disk = psutil.disk_usage('/')

    # Disk I/O: two snapshots 1s apart for accurate per-second rates
    io1 = psutil.disk_io_counters()
    _time.sleep(1)
    io2 = psutil.disk_io_counters()

    elapsed = 1.0  # seconds between snapshots

    read_bytes_per_sec  = max(0, io2.read_bytes  - io1.read_bytes)  / elapsed
    write_bytes_per_sec = max(0, io2.write_bytes - io1.write_bytes) / elapsed
    read_mbps  = round(read_bytes_per_sec  / (1024 * 1024), 2)
    write_mbps = round(write_bytes_per_sec / (1024 * 1024), 2)

    busy_diff_ms = max(0, getattr(io2, 'busy_time', 0) - getattr(io1, 'busy_time', 0))
    io_busy_percent = round(min(100.0, (busy_diff_ms / (elapsed * 1000)) * 100), 1)

    return jsonify({
        'cpu_percent': cpu_percent,
        'ram_percent': round(ram.percent, 1),
        'ram_used_gb': round(ram.used  / (1024**3), 2),
        'ram_total_gb': round(ram.total / (1024**3), 2),
        'disk_percent': round(disk.percent, 1),
        'disk_used_gb': round(disk.used  / (1024**3), 2),
        'disk_total_gb': round(disk.total / (1024**3), 2),
        'io_read_mbps':    read_mbps,
        'io_write_mbps':   write_mbps,
        'io_busy_percent': io_busy_percent,
    })


@bp.route('/<tenant_slug>/dashboard')
@login_required
def dashboard(tenant_slug):
    # Cross-tenant check
    if session.get('user_role') != UserRole.SUPER_ADMIN.value and session.get('tenant_slug') != tenant_slug:
        flash('Voce nao tem permissao para acessar este painel.', 'error')
        return redirect(url_for('auth.login'))

    db = SessionLocal()
    try:
        PlanLimitsService.ensure_schema()
        tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
        if not tenant:
            return "Tenant not found", 404

        def _format_bytes(value):
            size = float(value or 0)
            for unit in ["B", "KB", "MB", "GB", "TB"]:
                if size < 1024:
                    return f"{size:.1f} {unit}"
                size /= 1024
            return f"{size:.1f} PB"

        def _rate(success, failed):
            total = (success or 0) + (failed or 0)
            if total <= 0:
                return 0.0
            return round(((success or 0) / total) * 100.0, 1)

        def _sparkline_points(values, width=140, height=36, pad=2):
            vals = [float(v or 0) for v in (values or [])]
            if not vals:
                return ""
            min_v = min(vals)
            max_v = max(vals)
            span = max(max_v - min_v, 1.0)
            points = []
            n = len(vals)
            for i, v in enumerate(vals):
                x = pad + ((width - (pad * 2)) * (i / max(1, n - 1)))
                y = pad + ((height - (pad * 2)) * (1 - ((v - min_v) / span)))
                points.append(f"{x:.1f},{y:.1f}")
            return " ".join(points)

        # Real data
        operational_group_filter = or_(
            Device.group_id.is_(None),
            Device.group.has(DeviceGroup.is_active.is_(True)),
        )
        active_device_filter = [
            Device.tenant_id == tenant.id,
            Device.is_active.isnot(False),
            operational_group_filter,
        ]

        total_devices = db.query(Device).filter(*active_device_filter).count()
        usage_snapshot = PlanLimitsService.build_usage_snapshot(db, tenant)
        storage_bytes = int(usage_snapshot.get("storage_used_bytes") or 0)
        
        recent_backups = (
            db.query(Backup)
            .join(Device)
            .filter(*active_device_filter)
            .options(joinedload(Backup.device).joinedload(Device.type))
            .order_by(Backup.started_at.desc())
            .limit(5)
            .all()
        )

        stats = {
            'total_devices': total_devices,
            'storage_used': usage_snapshot.get("storage_used_label") or _format_bytes(storage_bytes)
        }

        mass_excluded_type_ids = resolve_mass_backup_excluded_type_ids(db)
        backup_eligible_filter = [
            *active_device_filter,
            Device.backup_scheduled == True,
        ]
        if mass_excluded_type_ids:
            backup_eligible_filter.append(
                or_(
                    Device.device_type_id.is_(None),
                    Device.device_type_id.notin_(list(mass_excluded_type_ids)),
                )
            )

        # Backup metrics (fuso local do tenant/operacao).
        local_tz = ZoneInfo(settings.APP_TIMEZONE)
        now_utc = datetime.utcnow()
        now_local = datetime.now(local_tz)
        today = now_local.date()
        start_of_day_local = datetime.combine(today, datetime.min.time(), tzinfo=local_tz)
        end_of_day_local = datetime.combine(today, datetime.max.time(), tzinfo=local_tz)
        start_of_day = start_of_day_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
        end_of_day = end_of_day_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
        last_24h_start = now_utc - timedelta(hours=24)

        success_today_count = db.query(Backup).join(Device).filter(
            Device.tenant_id == tenant.id,
            *backup_eligible_filter[1:],
            Backup.started_at >= start_of_day,
            Backup.started_at <= end_of_day,
            Backup.status == BackupStatus.SUCCESS.value
        ).count()
        failed_today_count = db.query(Backup).join(Device).filter(
            Device.tenant_id == tenant.id,
            *backup_eligible_filter[1:],
            Backup.started_at >= start_of_day,
            Backup.started_at <= end_of_day,
            Backup.status == BackupStatus.FAILED.value
        ).count()
        backups_today = success_today_count + failed_today_count

        success_24h = db.query(Backup).join(Device).filter(
            Device.tenant_id == tenant.id,
            *backup_eligible_filter[1:],
            Backup.started_at >= last_24h_start,
            Backup.status == BackupStatus.SUCCESS.value
        ).count()
        failed_24h = db.query(Backup).join(Device).filter(
            Device.tenant_id == tenant.id,
            *backup_eligible_filter[1:],
            Backup.started_at >= last_24h_start,
            Backup.status == BackupStatus.FAILED.value
        ).count()
        backups_24h = success_24h + failed_24h

        total_scheduled = db.query(Device).filter(
            *backup_eligible_filter,
        ).count()
        pending_backups = db.query(Schedule).join(Device).filter(
            Device.tenant_id == tenant.id,
            *backup_eligible_filter[1:],
            Schedule.is_active == True,
            Schedule.next_run_at.isnot(None),
            Schedule.next_run_at <= now_utc
        ).count()
        success_rate = round((success_today_count / backups_today) * 100) if backups_today else 0
        success_count = db.query(Device).filter(
            *backup_eligible_filter,
            Device.last_backup_status == 'success'
        ).count()
        failed_count = db.query(Device).filter(
            *backup_eligible_filter,
            Device.last_backup_status == 'failure'
        ).count()
        no_history_count = db.query(Device).filter(
            *backup_eligible_filter,
            or_(
                Device.last_backup_status.is_(None),
                Device.last_backup_status.in_(['never', 'unknown'])
            )
        ).count()
        processed_backups = success_count + failed_count
        completed_backups = success_count
        # Círculo principal: sucesso entre os dispositivos já processados.
        backup_progress = round((success_count / processed_backups) * 100) if processed_backups else 0
        backup_progress = max(0, min(backup_progress, 100))
        coverage_progress = round((processed_backups / total_scheduled) * 100) if total_scheduled else 0
        pending_progress = round((pending_backups / total_scheduled) * 100) if total_scheduled else 0

        next_backup_time = db.query(func.min(Schedule.next_run_at)).join(Device).filter(
            Device.tenant_id == tenant.id,
            *backup_eligible_filter[1:],
            Schedule.is_active == True
        ).scalar()
        if next_backup_time:
            next_backup_time_str = (
                next_backup_time.replace(tzinfo=ZoneInfo("UTC")).astimezone(local_tz).strftime('%H:%M')
            )
        else:
            next_backup_time_str = '-'

        # Chart Data Integration (Last 7 Days) - single query
        start_range = datetime.combine(today - timedelta(days=6), datetime.min.time())
        grouped = db.query(
            func.date(Backup.started_at).label('day'),
            Backup.status,
            func.count(Backup.id)
        ).join(Device).filter(
            *active_device_filter,
            Backup.started_at >= start_range
        ).group_by(func.date(Backup.started_at), Backup.status).all()

        counts_by_day = {}
        for day, status, count in grouped:
            counts_by_day.setdefault(day, {'success': 0, 'failed': 0})
            status_val = status.value if hasattr(status, 'value') else str(status)
            if status_val == BackupStatus.SUCCESS.value:
                counts_by_day[day]['success'] = count
            elif status_val == BackupStatus.FAILED.value:
                counts_by_day[day]['failed'] = count

        date_labels = []
        success_data = []
        failed_data = []
        for i in range(6, -1, -1):
            day = today - timedelta(days=i)
            day_label = day.strftime('%d/%m')
            date_labels.append(day_label)
            day_counts = counts_by_day.get(day, {'success': 0, 'failed': 0})
            success_data.append(day_counts['success'])
            failed_data.append(day_counts['failed'])

        chart_data = {
            'dates': date_labels,
            'success': success_data,
            'failed': failed_data
        }

        # Contexto operacional para o donut: meta + delta semanal + tendência.
        weekly_success_rate = _rate(sum(success_data), sum(failed_data))
        backup_target_rate = 90.0

        # Semana anterior (7 dias anteriores ao range atual).
        prev_start = datetime.combine(today - timedelta(days=13), datetime.min.time())
        grouped_14d = db.query(
            func.date(Backup.started_at).label('day'),
            Backup.status,
            func.count(Backup.id)
        ).join(Device).filter(
            *active_device_filter,
            Backup.started_at >= prev_start
        ).group_by(func.date(Backup.started_at), Backup.status).all()

        counts_14d = {}
        for day, status, count in grouped_14d:
            counts_14d.setdefault(day, {'success': 0, 'failed': 0})
            status_val = status.value if hasattr(status, 'value') else str(status)
            if status_val == BackupStatus.SUCCESS.value:
                counts_14d[day]['success'] = count
            elif status_val == BackupStatus.FAILED.value:
                counts_14d[day]['failed'] = count

        success_14d = []
        failed_14d = []
        for i in range(13, -1, -1):
            day = today - timedelta(days=i)
            day_counts = counts_14d.get(day, {'success': 0, 'failed': 0})
            success_14d.append(day_counts['success'])
            failed_14d.append(day_counts['failed'])

        prev_success = sum(success_14d[:7])
        prev_failed = sum(failed_14d[:7])
        weekly_prev_rate = _rate(prev_success, prev_failed)
        weekly_delta_rate = round(weekly_success_rate - weekly_prev_rate, 1)

        success_rate_series_7d = [
            _rate(s, f) for s, f in zip(success_data, failed_data)
        ]
        success_rate_trend_points = _sparkline_points(success_rate_series_7d)
        
        # Device type counts - dynamic
        device_type_stats = db.query(
            DeviceType.category,
            func.count(Device.id).label('count')
        ).join(Device, Device.device_type_id == DeviceType.id).filter(
            *active_device_filter
        ).group_by(DeviceType.category).all()
        
        type_counts = {'router': 0, 'olt': 0, 'switch': 0, 'other': 0}
        for category, count in device_type_stats:
            if category in type_counts:
                type_counts[category] = count
            else:
                type_counts['other'] += count
        untyped_count = db.query(Device).filter(
            *active_device_filter,
            Device.device_type_id.is_(None)
        ).count()
        type_counts['other'] += untyped_count
        
        # Monthly chart data (last 12 months)
        start_of_year = datetime.combine((today.replace(day=1) - timedelta(days=365)), datetime.min.time())
        monthly_grouped = db.query(
            func.date_trunc('month', Backup.started_at).label('month'),
            func.count(Backup.id).label('count')
        ).join(Device).filter(
            *active_device_filter,
            Backup.started_at >= start_of_year,
            Backup.status == BackupStatus.SUCCESS.value
        ).group_by(func.date_trunc('month', Backup.started_at)).order_by('month').all()
        
        monthly_data = {m: c for m, c in monthly_grouped}
        monthly_labels = []
        monthly_values = []
        base_month = today.replace(day=1)
        for i in range(11, -1, -1):
            month = base_month.month - i
            year = base_month.year
            while month <= 0:
                month += 12
                year -= 1
            month_date = datetime(year, month, 1).date()
            monthly_labels.append(month_date.strftime('%b'))
            # Find matching month in data
            matching = [c for m, c in monthly_grouped if m and m.month == month_date.month and m.year == month_date.year]
            monthly_values.append(matching[0] if matching else 0)
        
        # Storage total
        storage_total_bytes = storage_bytes if storage_bytes else 0

        # "Pede atenção" — até 4 dispositivos com falha recente, p/ o painel do dashboard
        attention_devices = db.query(Device).filter(
            *backup_eligible_filter,
            Device.last_backup_status == 'failure'
        ).order_by(Device.last_backup_at.desc()).limit(4).all()
        attention_items = []
        for d in attention_devices:
            conn = (d.last_connection_status or '').lower()
            if conn in ('offline', 'error'):
                reason = 'Dispositivo inacessível — sem resposta na última tentativa'
                icon = 'plug-zap'
            else:
                reason = 'Falha no último backup — verifique credenciais e conexão'
                icon = 'key'
            attention_items.append({
                'id': str(d.id),
                'name': d.name,
                'group': (d.group.name if d.group else (d.type.name if d.type else 'Sem grupo')),
                'reason': reason,
                'icon': icon,
            })

        return render_template('tenant/dashboard.html',
                             attention_items=attention_items,
                             tenant=tenant, 
                             tenant_slug=tenant_slug, 
                             stats=stats, 
                             recent_backups=recent_backups,
                             chart_data=json.dumps(chart_data),
                             pending_backups=pending_backups,
                             failed_today=failed_today_count,
                             backups_today=backups_today,
                             success_rate=success_rate,
                             backup_progress=backup_progress,
                             pending_progress=pending_progress,
                             completed_backups=completed_backups,
                             processed_backups=processed_backups,
                             coverage_progress=coverage_progress,
                             no_history_count=no_history_count,
                             total_scheduled=total_scheduled,
                             next_backup_time=next_backup_time_str,
                             success_count=success_count,
                             failed_count=failed_count,
                             success_24h=success_24h,
                             failed_24h=failed_24h,
                             backups_24h=backups_24h,
                             weekly_success_rate=weekly_success_rate,
                             weekly_prev_rate=weekly_prev_rate,
                             weekly_delta_rate=weekly_delta_rate,
                             backup_target_rate=backup_target_rate,
                             success_rate_trend_points=success_rate_trend_points,
                             success_rate_series_7d=json.dumps(success_rate_series_7d),
                             pending_count=pending_backups,
                             mikrotik_count=type_counts['router'],
                             olt_count=type_counts['olt'],
                             switch_count=type_counts['switch'],
                             type_counts=type_counts,
                             monthly_labels=json.dumps(monthly_labels),
                             monthly_values=json.dumps(monthly_values),
                             storage_total_bytes=storage_total_bytes,
                             usage_snapshot=usage_snapshot,
                             current_time=now_local
                             )
    finally:
        db.close()


@bp.route('/<tenant_slug>/refresh-status', methods=['POST'])
@login_required
def refresh_status(tenant_slug):
    # Endpoint mantido apenas para compatibilidade com navegadores que ainda
    # estejam com HTML em cache. O monitoramento automatico por ping foi removido.
    if session.get('user_role') != UserRole.SUPER_ADMIN.value and session.get('tenant_slug') != tenant_slug:
        abort(403)

    flash(
        "A checagem automatica de ping foi removida. Use a validacao manual em Agendamentos quando precisar.",
        "info",
    )
    return redirect(url_for('tenant.dashboard', tenant_slug=tenant_slug))
