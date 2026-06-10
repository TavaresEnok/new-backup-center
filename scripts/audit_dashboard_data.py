#!/usr/bin/env python3
"""Audit dashboard/device data consistency per tenant."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, time

from sqlalchemy import func, or_

from app.core.database import SessionLocal
from app.models.backup import Backup, BackupStatus
from app.models.device import Device
from app.models.tenant import Tenant


def _count_backups(db, tenant_id, start_dt, end_dt, status: str | None = None) -> int:
    q = db.query(func.count(Backup.id)).join(Device).filter(
        Device.tenant_id == tenant_id,
        Backup.started_at >= start_dt,
        Backup.started_at <= end_dt,
    )
    if status:
        q = q.filter(Backup.status == status)
    return int(q.scalar() or 0)


def _build_tenant_report(db, tenant: Tenant) -> dict:
    active_filter = [Device.tenant_id == tenant.id, Device.is_active.isnot(False)]

    total_active = int(db.query(func.count(Device.id)).filter(*active_filter).scalar() or 0)
    online = int(db.query(func.count(Device.id)).filter(*active_filter, Device.last_connection_status == 'online').scalar() or 0)
    unknown = int(
        db.query(func.count(Device.id)).filter(
            *active_filter,
            or_(Device.last_connection_status == 'unknown', Device.last_connection_status.is_(None)),
        ).scalar()
        or 0
    )
    offline = int(
        db.query(func.count(Device.id)).filter(
            *active_filter,
            or_(
                Device.last_connection_status.in_(['offline', 'error']),
                Device.last_connection_status == 'unknown',
                Device.last_connection_status.is_(None),
            ),
        ).scalar()
        or 0
    )

    scheduled = int(
        db.query(func.count(Device.id)).filter(*active_filter, Device.backup_scheduled == True).scalar() or 0
    )

    today = datetime.utcnow().date()
    day_start = datetime.combine(today, time.min)
    day_end = datetime.combine(today, time.max)
    h24_start = datetime.utcnow() - timedelta(hours=24)

    success_today = _count_backups(db, tenant.id, day_start, day_end, BackupStatus.SUCCESS.value)
    failed_today = _count_backups(db, tenant.id, day_start, day_end, BackupStatus.FAILED.value)
    success_24h = _count_backups(db, tenant.id, h24_start, day_end, BackupStatus.SUCCESS.value)
    failed_24h = _count_backups(db, tenant.id, h24_start, day_end, BackupStatus.FAILED.value)

    no_backup_devices = db.query(Device.name, Device.ip_address).filter(
        *active_filter,
        Device.last_backup_at.is_(None),
    ).order_by(Device.name).all()

    duplicate_name_rows = (
        db.query(Device.name, func.count(Device.id).label('qty'))
        .filter(*active_filter)
        .group_by(Device.name)
        .having(func.count(Device.id) > 1)
        .order_by(func.count(Device.id).desc(), Device.name)
        .all()
    )

    duplicate_ip_rows = (
        db.query(Device.ip_address, func.count(Device.id).label('qty'))
        .filter(*active_filter)
        .group_by(Device.ip_address)
        .having(func.count(Device.id) > 1)
        .order_by(func.count(Device.id).desc(), Device.ip_address)
        .all()
    )

    anomalies = []
    if total_active > 0 and online == 0 and offline == 0:
        anomalies.append('Nenhum dispositivo online/offline apesar de haver ativos (possível status não atualizado).')
    if scheduled > 0 and (success_today + failed_today) == 0:
        anomalies.append('Há dispositivos agendados, mas nenhum backup registrado hoje.')
    if unknown == total_active and total_active > 0:
        anomalies.append('Todos os dispositivos estão como unknown/não monitorado.')

    return {
        'tenant': {'id': str(tenant.id), 'slug': tenant.slug, 'name': tenant.name},
        'devices': {
            'total_active': total_active,
            'online': online,
            'offline_or_unknown': offline,
            'unknown_only': unknown,
            'scheduled': scheduled,
            'without_backup_history': len(no_backup_devices),
        },
        'backups': {
            'today': {'success': success_today, 'failed': failed_today, 'total': success_today + failed_today},
            'last_24h': {'success': success_24h, 'failed': failed_24h, 'total': success_24h + failed_24h},
        },
        'duplicates': {
            'by_name': [{'name': name, 'count': int(qty)} for name, qty in duplicate_name_rows],
            'by_ip': [{'ip_address': ip, 'count': int(qty)} for ip, qty in duplicate_ip_rows],
        },
        'devices_without_backup_history': [
            {'name': name, 'ip_address': ip} for name, ip in no_backup_devices
        ],
        'anomalies': anomalies,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='Audit dashboard/device data consistency.')
    parser.add_argument('--tenant-slug', help='Audit only one tenant slug.')
    parser.add_argument('--output', choices=['json', 'pretty'], default='pretty')
    args = parser.parse_args()

    db = SessionLocal()
    try:
        tenants_q = db.query(Tenant)
        if args.tenant_slug:
            tenants_q = tenants_q.filter(Tenant.slug == args.tenant_slug)
        tenants = tenants_q.order_by(Tenant.slug).all()

        reports = [_build_tenant_report(db, t) for t in tenants]

        if args.output == 'json':
            print(json.dumps({'generated_at': datetime.utcnow().isoformat(), 'tenants': reports}, ensure_ascii=False))
        else:
            for report in reports:
                t = report['tenant']
                d = report['devices']
                b = report['backups']
                print(f"\n=== {t['slug']} ({t['name']}) ===")
                print(
                    f"Dispositivos: ativos={d['total_active']} online={d['online']} "
                    f"offline/unknown={d['offline_or_unknown']} unknown={d['unknown_only']} agendados={d['scheduled']}"
                )
                print(
                    f"Backups hoje: total={b['today']['total']} sucesso={b['today']['success']} falha={b['today']['failed']}"
                )
                print(
                    f"Backups 24h: total={b['last_24h']['total']} sucesso={b['last_24h']['success']} falha={b['last_24h']['failed']}"
                )
                print(f"Sem histórico de backup: {d['without_backup_history']}")
                print(f"Duplicados por nome: {len(report['duplicates']['by_name'])}")
                print(f"Duplicados por IP: {len(report['duplicates']['by_ip'])}")
                if report['anomalies']:
                    print('Anomalias:')
                    for item in report['anomalies']:
                        print(f"- {item}")
                else:
                    print('Anomalias: nenhuma')

    finally:
        db.close()

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
