from collections import Counter
from datetime import datetime, timedelta

from flask import Blueprint, abort, render_template, request, session
from sqlalchemy import func
from sqlalchemy.orm import joinedload

from app.core.database import SessionLocal
from app.models.backup import Backup, BackupStatus
from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.models.schedule import Schedule
from app.models.tenant import Tenant
from app.models.user import UserRole
from app.web.auth.decorators import login_required
from app.services.backup_diagnostics import classify_failure
from app.services.mass_backup_scope import resolve_mass_backup_excluded_type_ids

bp = Blueprint("tenant_operations", __name__, url_prefix="/tenant/<tenant_slug>/operations")


def _get_db_and_tenant(tenant_slug):
    if session.get("user_role") != UserRole.SUPER_ADMIN.value and session.get("tenant_slug") != tenant_slug:
        abort(403)
    db = SessionLocal()
    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
    return db, tenant


@bp.route("/")
@login_required
def index(tenant_slug):
    db, tenant = _get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404

    try:
        focus_mode = request.args.get("focus") == "1"
        view_mode = (request.args.get("view") or "cards").strip().lower()
        if view_mode not in {"cards", "table"}:
            view_mode = "cards"
        role = session.get("user_role")
        can_manage_admin = role in {
            UserRole.SUPER_ADMIN.value,
            UserRole.TENANT_OWNER.value,
            UserRole.TENANT_ADMIN.value,
        }
        group_filter = (request.args.get("group_filter") or "all").strip().lower()
        if group_filter not in {"all", "vpn", "jump", "no_vpn"}:
            group_filter = "all"
        now_utc = datetime.utcnow()
        last_24h = now_utc - timedelta(hours=24)
        last_7d = now_utc - timedelta(days=7)
        last_14d = now_utc - timedelta(days=14)
        last_30d = now_utc - timedelta(days=30)
        mass_excluded_type_ids = resolve_mass_backup_excluded_type_ids(db)

        device_scope_filter = [
            Device.tenant_id == tenant.id,
            Device.is_active == True,
        ]
        if mass_excluded_type_ids:
            device_scope_filter.append(
                (Device.device_type_id.is_(None) | Device.device_type_id.notin_(list(mass_excluded_type_ids)))
            )

        groups = (
            db.query(DeviceGroup)
            .filter(
                DeviceGroup.tenant_id == tenant.id,
            )
            .order_by(DeviceGroup.name.asc())
            .all()
        )
        group_lookup = {str(group.id): group for group in groups}

        devices = (
            db.query(Device)
            .options(joinedload(Device.group))
            .filter(*device_scope_filter)
            .all()
        )

        active_schedule_rows = (
            db.query(Schedule.device_id, Schedule.time)
            .join(Device)
            .filter(
                Device.tenant_id == tenant.id,
                *device_scope_filter[1:],
                Schedule.is_active == True,
            )
            .all()
        )
        active_schedule_device_ids = {row.device_id for row in active_schedule_rows}
        daily_times = [row.time for row in active_schedule_rows if row.time]
        default_daily_time = Counter(daily_times).most_common(1)[0][0] if daily_times else "02:00"

        device_ids_with_backups = {
            row[0]
            for row in (
                db.query(Backup.device_id)
                .join(Device)
                .filter(Device.tenant_id == tenant.id, *device_scope_filter[1:])
                .distinct()
                .all()
            )
        }

        last_backup_rows = (
            db.query(Backup.device_id, func.max(Backup.started_at))
            .join(Device)
            .filter(Device.tenant_id == tenant.id, *device_scope_filter[1:])
            .group_by(Backup.device_id)
            .all()
        )
        last_backup_by_device = {row[0]: row[1] for row in last_backup_rows}

        recent_rows = (
            db.query(Backup.device_id, Backup.status, func.count(Backup.id))
            .join(Device)
            .filter(
                Device.tenant_id == tenant.id,
                *device_scope_filter[1:],
                Backup.started_at >= last_24h,
            )
            .group_by(Backup.device_id, Backup.status)
            .all()
        )
        failed_24h_by_device = {}
        success_24h_by_device = {}
        for device_id, status, count in recent_rows:
            status_val = status.value if hasattr(status, "value") else str(status)
            if status_val == BackupStatus.FAILED.value:
                failed_24h_by_device[device_id] = int(count)
            elif status_val == BackupStatus.SUCCESS.value:
                success_24h_by_device[device_id] = int(count)

        group_buckets = {}
        for group in groups:
            group_buckets[str(group.id)] = {
                "id": str(group.id),
                "name": group.name,
                "connection_type": group.connection_type or "direct",
                "uses_vpn": bool(group.uses_vpn),
                "uses_jump_host": bool(group.uses_jump_host),
                "is_active": bool(getattr(group, "is_active", True)),
                "total_devices": 0,
                "fully_configured": 0,
                "auto_disabled": 0,
                "missing_schedule": 0,
                "without_any_backup": 0,
                "failed_24h": 0,
                "success_24h": 0,
                "devices_success": 0,
                "devices_failed": 0,
                "devices_unknown": 0,
                "last_backup_at": None,
                "coverage_pct": 0,
                "attention_score": 0,
                "sla_success_7d": 0,
                "sla_failed_7d": 0,
                "sla_success_prev7d": 0,
                "sla_failed_prev7d": 0,
                "sla_rate_7d": 0.0,
                "sla_prev_rate_7d": 0.0,
                "sla_delta_7d": 0.0,
                "sla_target": 95.0,
                "sla_below_target": False,
                "jump_host_state": None,
                "jump_host_access_failed": 0,
                "jump_host_no_route": 0,
                "device_auth_failed": 0,
                "timeout": 0,
                "connectivity_failed": 0,
            }

        group_buckets["__ungrouped__"] = {
            "id": None,
            "name": "Sem grupo",
            "connection_type": "direct",
            "uses_vpn": False,
            "uses_jump_host": False,
            "is_active": True,
            "total_devices": 0,
            "fully_configured": 0,
            "auto_disabled": 0,
            "missing_schedule": 0,
            "without_any_backup": 0,
            "failed_24h": 0,
            "success_24h": 0,
            "devices_success": 0,
            "devices_failed": 0,
            "devices_unknown": 0,
            "last_backup_at": None,
            "coverage_pct": 0,
            "attention_score": 0,
            "sla_success_7d": 0,
            "sla_failed_7d": 0,
            "sla_success_prev7d": 0,
            "sla_failed_prev7d": 0,
            "sla_rate_7d": 0.0,
            "sla_prev_rate_7d": 0.0,
            "sla_delta_7d": 0.0,
            "sla_target": 95.0,
            "sla_below_target": False,
            "jump_host_state": None,
            "jump_host_access_failed": 0,
            "jump_host_no_route": 0,
            "device_auth_failed": 0,
            "timeout": 0,
            "connectivity_failed": 0,
        }

        sla_rows_7d = (
            db.query(Device.group_id, Backup.status, func.count(Backup.id))
            .join(Device, Device.id == Backup.device_id)
            .filter(
                Device.tenant_id == tenant.id,
                *device_scope_filter[1:],
                Backup.started_at >= last_7d,
            )
            .group_by(Device.group_id, Backup.status)
            .all()
        )
        sla_rows_prev_7d = (
            db.query(Device.group_id, Backup.status, func.count(Backup.id))
            .join(Device, Device.id == Backup.device_id)
            .filter(
                Device.tenant_id == tenant.id,
                *device_scope_filter[1:],
                Backup.started_at >= last_14d,
                Backup.started_at < last_7d,
            )
            .group_by(Device.group_id, Backup.status)
            .all()
        )
        for group_id, status, count in sla_rows_7d:
            key = str(group_id) if group_id else "__ungrouped__"
            bucket = group_buckets.get(key)
            if not bucket:
                continue
            status_val = status.value if hasattr(status, "value") else str(status)
            if status_val == BackupStatus.SUCCESS.value:
                bucket["sla_success_7d"] += int(count or 0)
            elif status_val == BackupStatus.FAILED.value:
                bucket["sla_failed_7d"] += int(count or 0)
        for group_id, status, count in sla_rows_prev_7d:
            key = str(group_id) if group_id else "__ungrouped__"
            bucket = group_buckets.get(key)
            if not bucket:
                continue
            status_val = status.value if hasattr(status, "value") else str(status)
            if status_val == BackupStatus.SUCCESS.value:
                bucket["sla_success_prev7d"] += int(count or 0)
            elif status_val == BackupStatus.FAILED.value:
                bucket["sla_failed_prev7d"] += int(count or 0)

        attention_devices = []
        for device in devices:
            group_key = str(device.group_id) if device.group_id else "__ungrouped__"
            bucket = group_buckets.get(group_key)
            if not bucket:
                # Grupo pode ter sido removido no meio da transacao.
                continue

            has_auto = bool(device.backup_scheduled)
            has_active_schedule = device.id in active_schedule_device_ids
            has_history = device.id in device_ids_with_backups
            failed_24h = failed_24h_by_device.get(device.id, 0)
            success_24h = success_24h_by_device.get(device.id, 0)
            fully_configured = has_auto and has_active_schedule

            bucket["total_devices"] += 1
            if fully_configured:
                bucket["fully_configured"] += 1
            if not has_auto:
                bucket["auto_disabled"] += 1
            if has_auto and not has_active_schedule:
                bucket["missing_schedule"] += 1
            if not has_history:
                bucket["without_any_backup"] += 1
            bucket["failed_24h"] += failed_24h
            bucket["success_24h"] += success_24h
            last_status = str(device.last_backup_status or "").strip().lower()
            if last_status == 'success':
                bucket["devices_success"] += 1
            elif last_status in ('failure', 'failed'):
                bucket["devices_failed"] += 1
            else:
                bucket["devices_unknown"] += 1

            device_last_backup = last_backup_by_device.get(device.id)
            if device_last_backup and (not bucket["last_backup_at"] or device_last_backup > bucket["last_backup_at"]):
                bucket["last_backup_at"] = device_last_backup

            reasons = []
            extra = device.extra_parameters or {}
            failure_category = str(extra.get("connection_test_failure_category") or "").strip().lower()
            if failure_category in {"jump_host_access_failed", "jump_host_no_route", "device_auth_failed", "timeout", "connectivity_failed"}:
                bucket[failure_category] += 1
            if not has_auto:
                reasons.append("auto_off")
            if has_auto and not has_active_schedule:
                reasons.append("schedule_missing")
            if not has_history:
                reasons.append("no_history")
            if failed_24h > 0:
                reasons.append("failed_24h")

            if reasons:
                attention_devices.append(
                    {
                        "id": str(device.id),
                        "name": device.name,
                        "ip_address": device.ip_address,
                        "port": device.port,
                        "group_name": (device.group.name if device.group else "Sem grupo"),
                        "last_backup_at": device_last_backup,
                        "last_backup_status": device.last_backup_status or "unknown",
                        "failed_24h": failed_24h,
                        "reasons": reasons,
                    }
                )

        group_rows = []
        for bucket in group_buckets.values():
            # Exibe grupos recem-criados mesmo sem dispositivos.
            # Oculta apenas o pseudo-grupo "Sem grupo" quando ele estiver vazio.
            if bucket["id"] is None and bucket["total_devices"] == 0:
                continue
            if bucket["total_devices"] > 0:
                bucket["coverage_pct"] = int(round((bucket["fully_configured"] / bucket["total_devices"]) * 100))
            else:
                bucket["coverage_pct"] = 0
            bucket["attention_score"] = (
                (bucket["auto_disabled"] * 3)
                + (bucket["missing_schedule"] * 2)
                + (bucket["without_any_backup"] * 3)
                + (bucket["failed_24h"] * 4)
            )
            sla_total = bucket["sla_success_7d"] + bucket["sla_failed_7d"]
            sla_prev_total = bucket["sla_success_prev7d"] + bucket["sla_failed_prev7d"]
            if sla_total > 0:
                bucket["sla_rate_7d"] = round((bucket["sla_success_7d"] / sla_total) * 100.0, 1)
            else:
                bucket["sla_rate_7d"] = 0.0
            if sla_prev_total > 0:
                bucket["sla_prev_rate_7d"] = round((bucket["sla_success_prev7d"] / sla_prev_total) * 100.0, 1)
            else:
                bucket["sla_prev_rate_7d"] = 0.0
            bucket["sla_delta_7d"] = round(bucket["sla_rate_7d"] - bucket["sla_prev_rate_7d"], 1)
            bucket["sla_below_target"] = bool(sla_total > 0 and bucket["sla_rate_7d"] < bucket["sla_target"])
            bucket["jump_issue_total"] = (
                bucket["jump_host_access_failed"]
                + bucket["jump_host_no_route"]
                + bucket["device_auth_failed"]
                + bucket["timeout"]
                + bucket["connectivity_failed"]
            )
            group_rows.append(bucket)

        group_rows.sort(key=lambda row: (-row["attention_score"], row["name"].lower()))
        all_group_rows = list(group_rows)

        attention_devices.sort(
            key=lambda row: (
                -int("failed_24h" in row["reasons"]),
                -len(row["reasons"]),
                row["name"].lower(),
            )
        )
        all_attention_devices = list(attention_devices)

        critical_group_rows = [
            row for row in all_group_rows
            if row["failed_24h"] > 0 or row["without_any_backup"] > 0 or row["auto_disabled"] > 0
        ]

        auth_fail_rows = (
            db.query(Backup.device_id, Backup.error_message, Backup.created_at)
            .join(Device, Device.id == Backup.device_id)
            .filter(
                Device.tenant_id == tenant.id,
                *device_scope_filter[1:],
                Backup.status == BackupStatus.FAILED,
                Backup.created_at >= last_30d,
            )
            .all()
        )
        auth_fail_by_device = {}
        for device_id, error_message, created_at in auth_fail_rows:
            category = classify_failure(error_message or "")
            if category != "auth":
                continue
            key = str(device_id)
            row = auth_fail_by_device.setdefault(
                key,
                {"count": 0, "last_at": None},
            )
            row["count"] += 1
            if created_at and (row["last_at"] is None or created_at > row["last_at"]):
                row["last_at"] = created_at

        credential_risk_rows = []
        for device in devices:
            key = str(device.id)
            auth_info = auth_fail_by_device.get(key, {"count": 0, "last_at": None})
            auth_count = int(auth_info.get("count") or 0)
            extra = device.extra_parameters or {}
            conn_group = str(extra.get("connection_test_group") or "").strip().lower()
            ping_ok_login_fail = conn_group == "ping_ok_login_fail"
            last_failure_category = str(extra.get("last_backup_failure_category") or "").strip().lower()

            if auth_count <= 0 and not ping_ok_login_fail and last_failure_category != "auth":
                continue

            score = (auth_count * 3) + (2 if ping_ok_login_fail else 0) + (2 if last_failure_category == "auth" else 0)
            if auth_count >= 5:
                recommendation = "Revisar usuario/senha imediatamente"
            elif ping_ok_login_fail:
                recommendation = "Conectividade OK, revisar credenciais"
            else:
                recommendation = "Monitorar e validar credenciais"

            credential_risk_rows.append(
                {
                    "device_id": str(device.id),
                    "device_name": device.name,
                    "group_name": device.group.name if device.group else "Sem grupo",
                    "ip_address": device.ip_address,
                    "auth_fail_count_30d": auth_count,
                    "ping_ok_login_fail": bool(ping_ok_login_fail),
                    "last_auth_fail_at": auth_info.get("last_at"),
                    "last_profile_update_at": getattr(device, "updated_at", None),
                    "score": score,
                    "recommendation": recommendation,
                }
            )
        credential_risk_rows.sort(key=lambda row: (-row["score"], -row["auth_fail_count_30d"], row["device_name"].lower()))
        credential_risk_rows = credential_risk_rows[:20]

        if focus_mode:
            # Mesmo no modo foco, manter grupos vazios visiveis para nao "sumirem"
            # logo apos o cadastro (antes de ter dispositivos vinculados).
            group_rows = [
                row for row in all_group_rows
                if row["attention_score"] > 0 or int(row.get("total_devices") or 0) == 0
            ]
            attention_devices = all_attention_devices
        else:
            group_rows = all_group_rows
            attention_devices = all_attention_devices[:40]

        if group_filter == "vpn":
            group_rows = [row for row in group_rows if row["uses_vpn"]]
        elif group_filter == "jump":
            group_rows = [row for row in group_rows if row["uses_jump_host"]]
        elif group_filter == "no_vpn":
            group_rows = [row for row in group_rows if not row["uses_vpn"]]

        critical_devices = sum(
            1
            for row in all_attention_devices
            if ("failed_24h" in row["reasons"] or "no_history" in row["reasons"])
        )
        attention_only_devices = max(len(all_attention_devices) - critical_devices, 0)
        healthy_devices = max(len(devices) - len(all_attention_devices), 0)

        summary = {
            "total_groups": len(all_group_rows),
            "active_groups": sum(1 for g in all_group_rows if g["is_active"]),
            "inactive_groups": sum(1 for g in all_group_rows if not g["is_active"]),
            "vpn_groups": sum(1 for g in all_group_rows if g["uses_vpn"]),
            "jump_groups": sum(1 for g in all_group_rows if g["uses_jump_host"]),
            "no_vpn_groups": sum(1 for g in all_group_rows if not g["uses_vpn"]),
            "total_devices": len(devices),
            "fully_configured": sum(g["fully_configured"] for g in all_group_rows),
            "auto_disabled": sum(g["auto_disabled"] for g in all_group_rows),
            "missing_schedule": sum(g["missing_schedule"] for g in all_group_rows),
            "without_any_backup": sum(g["without_any_backup"] for g in all_group_rows),
            "failed_24h": sum(g["failed_24h"] for g in all_group_rows),
            "success_24h": sum(g["success_24h"] for g in all_group_rows),
            "attention_devices": len(all_attention_devices),
            "critical_devices": critical_devices,
            "attention_only_devices": attention_only_devices,
            "healthy_devices": healthy_devices,
            "critical_groups": len(critical_group_rows),
            "groups_below_sla": sum(1 for g in all_group_rows if g["sla_below_target"]),
        }

        return render_template(
            "tenant/operations/index.html",
            tenant=tenant,
            summary=summary,
            group_rows=group_rows,
            critical_group_rows=critical_group_rows[:8],
            attention_devices=attention_devices,
            credential_risk_rows=credential_risk_rows,
            default_daily_time=default_daily_time,
            now_utc=now_utc,
            can_manage_admin=can_manage_admin,
            focus_mode=focus_mode,
            view_mode=view_mode,
            group_filter=group_filter,
        )
    finally:
        db.close()
