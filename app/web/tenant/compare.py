from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort
from app.web.auth.decorators import login_required
from app.core.database import SessionLocal
from app.models.tenant import Tenant
from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.models.backup import Backup, BackupStatus
from app.services.diff_service import DiffService
from app.models.user import UserRole
from sqlalchemy import func
import uuid

bp = Blueprint('tenant_compare', __name__, url_prefix='/tenant/<tenant_slug>/compare')

@bp.route('/')
@login_required
def select_device(tenant_slug):
    """Tela para selecionar qual dispositivo comparar backups."""
    if session.get('user_role') != UserRole.SUPER_ADMIN.value and session.get('tenant_slug') != tenant_slug:
        abort(403)
    db = SessionLocal()
    tenant = db.query(Tenant).filter_by(slug=tenant_slug).first()
    if not tenant:
        db.close()
        return "Tenant not found", 404
    
    selected_group_raw = (request.args.get('group') or '').strip()

    # Novo fluxo: ao escolher grupo/provedor, redireciona para a página
    # de dispositivos do cliente já filtrada para escolher o equipamento lá.
    if selected_group_raw and selected_group_raw != 'ungrouped':
        try:
            selected_group_uuid = uuid.UUID(selected_group_raw)
        except ValueError:
            selected_group_uuid = None
        if selected_group_uuid:
            selected_group_exists = (
                db.query(DeviceGroup)
                .filter(
                    DeviceGroup.id == selected_group_uuid,
                    DeviceGroup.tenant_id == tenant.id,
                    DeviceGroup.is_active == True,
                )
                .first()
            )
            if selected_group_exists:
                db.close()
                return redirect(
                    url_for(
                        'tenant_devices.list_devices',
                        tenant_slug=tenant_slug,
                        group_id=str(selected_group_uuid),
                        compare='1',
                    )
                )
    selected_group_key = ''

    groups = (
        db.query(DeviceGroup)
        .filter(
            DeviceGroup.tenant_id == tenant.id,
            DeviceGroup.is_active == True
        )
        .order_by(DeviceGroup.name.asc())
        .all()
    )

    device_count_rows = (
        db.query(Device.group_id, func.count(Device.id))
        .filter(
            Device.tenant_id == tenant.id,
            Device.is_active == True
        )
        .group_by(Device.group_id)
        .all()
    )
    device_count_by_group = {str(group_id): int(count) for group_id, count in device_count_rows if group_id}
    ungrouped_count = next((int(count) for group_id, count in device_count_rows if group_id is None), 0)

    group_cards = [
        {
            'id': str(group.id),
            'name': group.name,
            'connection_type': group.connection_type or 'direct',
            'device_count': device_count_by_group.get(str(group.id), 0),
        }
        for group in groups
    ]
    group_cards.append(
        {
            'id': 'ungrouped',
            'name': 'Sem grupo',
            'connection_type': 'direct',
            'device_count': ungrouped_count,
        }
    )

    devices = []
    selected_group_name = None
    if selected_group_raw:
        if selected_group_raw == 'ungrouped':
            selected_group_key = 'ungrouped'
            selected_group_name = 'Sem grupo'
            devices = (
                db.query(Device)
                .filter(
                    Device.tenant_id == tenant.id,
                    Device.is_active == True,
                    Device.group_id.is_(None)
                )
                .order_by(Device.name.asc())
                .all()
            )
        else:
            try:
                selected_group_uuid = uuid.UUID(selected_group_raw)
                selected_group = (
                    db.query(DeviceGroup)
                    .filter(
                        DeviceGroup.id == selected_group_uuid,
                        DeviceGroup.tenant_id == tenant.id
                    )
                    .first()
                )
                if selected_group:
                    selected_group_key = str(selected_group.id)
                    selected_group_name = selected_group.name
                    devices = (
                        db.query(Device)
                        .filter(
                            Device.tenant_id == tenant.id,
                            Device.is_active == True,
                            Device.group_id == selected_group.id
                        )
                        .order_by(Device.name.asc())
                        .all()
                    )
            except ValueError:
                selected_group_key = ''

    total_backup_count_by_device = {}
    comparable_backup_count_by_device = {}
    if devices:
        device_ids = [dev.id for dev in devices]
        total_backup_count_rows = (
            db.query(Backup.device_id, func.count(Backup.id))
            .filter(Backup.device_id.in_(device_ids))
            .group_by(Backup.device_id)
            .all()
        )
        comparable_backup_count_rows = (
            db.query(Backup.device_id, func.count(Backup.id))
            .filter(
                Backup.device_id.in_(device_ids),
                Backup.file_path.isnot(None),
                Backup.status == BackupStatus.SUCCESS,
            )
            .group_by(Backup.device_id)
            .all()
        )
        total_backup_count_by_device = {str(device_id): int(count) for device_id, count in total_backup_count_rows}
        comparable_backup_count_by_device = {str(device_id): int(count) for device_id, count in comparable_backup_count_rows}

    devices_data = []
    for dev in devices:
        total_count = total_backup_count_by_device.get(str(dev.id), 0)
        comparable_count = comparable_backup_count_by_device.get(str(dev.id), 0)
        devices_data.append(
            {
                'device': dev,
                'backup_count': comparable_count,
                'comparable_backup_count': comparable_count,
                'total_backup_count': total_count,
            }
        )

    db.close()
    return render_template(
        'tenant/compare/select_device.html',
        tenant=tenant,
        devices=devices_data,
        group_cards=group_cards,
        selected_group_key=selected_group_key,
        selected_group_name=selected_group_name,
    )

@bp.route('/<device_id>', methods=['GET', 'POST'])
@login_required
def compare_backups(tenant_slug, device_id):
    """Tela de comparação de backups de um dispositivo específico."""
    if session.get('user_role') != UserRole.SUPER_ADMIN.value and session.get('tenant_slug') != tenant_slug:
        abort(403)
    db = SessionLocal()
    tenant = db.query(Tenant).filter_by(slug=tenant_slug).first()
    if not tenant:
        db.close()
        return "Tenant not found", 404
    
    device = db.query(Device).filter_by(id=device_id, tenant_id=tenant.id).first()
    
    if not device:
        db.close()
        flash('Dispositivo não encontrado.', 'error')
        return redirect(url_for('tenant_compare.select_device', tenant_slug=tenant_slug))

    total_backups_count = db.query(func.count(Backup.id)).filter(Backup.device_id == device.id).scalar() or 0
    # Buscar apenas backups válidos para comparação (com arquivo salvo no storage atual)
    backups = DiffService.get_device_backups_for_compare(db, str(device.id), limit=200)
    comparable_backups_count = len(backups)
    
    diff_result = None
    backup_old = None
    backup_new = None
    
    if request.method == 'POST':
        id_old = request.form.get('backup_old')
        id_new = request.form.get('backup_new')
        
        if id_old and id_new:
            try:
                old_uuid = uuid.UUID(id_old)
                new_uuid = uuid.UUID(id_new)
            except ValueError:
                diff_result = {'error': 'IDs de backup inválidos.'}
            else:
                if old_uuid == new_uuid:
                    diff_result = {
                        'has_changes': False,
                        'added_lines': 0,
                        'removed_lines': 0,
                        'hunks': [],
                        'error': 'Selecione dois backups diferentes para comparar.'
                    }
                else:
                    backup_old = (
                        db.query(Backup)
                        .filter(
                            Backup.id == old_uuid,
                            Backup.device_id == device.id,
                            Backup.file_path.isnot(None),
                            Backup.status == BackupStatus.SUCCESS,
                        )
                        .first()
                    )
                    backup_new = (
                        db.query(Backup)
                        .filter(
                            Backup.id == new_uuid,
                            Backup.device_id == device.id,
                            Backup.file_path.isnot(None),
                            Backup.status == BackupStatus.SUCCESS,
                        )
                        .first()
                    )

                    if not backup_old or not backup_new:
                        diff_result = {
                            'has_changes': False,
                            'added_lines': 0,
                            'removed_lines': 0,
                            'hunks': [],
                            'error': 'Um ou ambos os backups selecionados não são válidos para este dispositivo.'
                        }
                    else:
                        # Garante a direção temporal da comparação (antigo -> novo)
                        if backup_old.created_at and backup_new.created_at and backup_old.created_at > backup_new.created_at:
                            backup_old, backup_new = backup_new, backup_old
                            flash('Ordem temporal ajustada automaticamente: versão mais antiga comparada com a mais nova.', 'info')
                        # Usar DiffService
                        try:
                            diff_result = DiffService.compare_backups(backup_old, backup_new)
                        except Exception as e:
                            diff_result = {'error': str(e)}
    
    db.close()
    return render_template('tenant/compare/result.html', 
                         tenant=tenant, 
                         device=device, 
                         backups=backups,
                         total_backups_count=total_backups_count,
                         comparable_backups_count=comparable_backups_count,
                         diff_result=diff_result,
                         backup_new=backup_new,
                         backup_old=backup_old)
