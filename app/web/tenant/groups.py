from flask import Blueprint, render_template, redirect, url_for, request, flash, session, abort, jsonify
from app.web.auth.decorators import login_required, tenant_admin_required, tenant_operator_required
from app.core.database import SessionLocal
from app.services.device_service import DeviceGroupService, DeviceService
from app.services.connection_mode import uses_jump_host, uses_vpn_tunnel
from app.services.jump_host_service import jump_host_service
from app.services.realtime_backup_logs import register_task, append_task_log
from app.services.activity_service import ActivityService
from app.tasks.monitoring import run_group_vpn_test_task, run_group_jump_host_diagnostic_task
from app.models.device import Device
from app.models.tenant import Tenant
from app.models.user import User, UserRole
from app.core.security import decrypt_password
import uuid
import re
import logging

bp = Blueprint('tenant_groups', __name__, url_prefix='/tenant/<tenant_slug>/groups')


def _can_view_saved_credentials(db=None) -> bool:
    role = session.get('user_role')
    if role == UserRole.TENANT_OWNER.value:
        return True

    if db is None:
        return False

    raw_user_id = session.get('user_id')
    if not raw_user_id:
        return False

    try:
        user_uuid = uuid.UUID(str(raw_user_id))
    except (TypeError, ValueError):
        return False

    user = db.query(User).filter(User.id == user_uuid, User.is_active.is_(True)).first()
    if not user:
        return False

    current_role = getattr(user.role, 'value', user.role)
    if current_role and current_role != role:
        session['user_role'] = current_role

    return current_role == UserRole.TENANT_OWNER.value


def _safe_decrypt_secret(encrypted_value, *, context_label: str, entity_id) -> str | None:
    if not encrypted_value:
        return None
    try:
        return decrypt_password(encrypted_value)
    except Exception:
        logging.getLogger(__name__).warning(
            'Falha ao descriptografar segredo salvo em %s para entidade %s',
            context_label,
            entity_id,
            exc_info=True,
        )
        return None


def _current_saved_secret_if_owner(db, encrypted_value, *, context_label: str, entity_id) -> str | None:
    if not _can_view_saved_credentials(db):
        return None
    return _safe_decrypt_secret(
        encrypted_value,
        context_label=context_label,
        entity_id=entity_id,
    )


def get_db_and_tenant(tenant_slug):
    # Cross-tenant check
    if session.get('user_role') != UserRole.SUPER_ADMIN.value and session.get('tenant_slug') != tenant_slug:
        abort(403)
        
    db = SessionLocal()
    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
    if not tenant:
        db.close()
    return db, tenant


def _clear_global_force_stop_flag() -> bool:
    """Remove a trava global de parada forcada ao iniciar novo backup manual."""
    try:
        from app.services.realtime_backup_logs import get_redis_client
        r = get_redis_client()
        if not r:
            return False
        key = "backup_center:force_stop_backups"
        had_flag = str(r.get(key) or "").strip() == "1"
        if had_flag:
            r.delete(key)
            logging.getLogger(__name__).warning("Flag global de stop removida para backup de grupo.")
        return had_flag
    except Exception:
        logging.getLogger(__name__).exception("Falha ao limpar flag global de stop no backup de grupo")
        return False


def _value_bool(raw_value, default: bool = False) -> bool:
    if raw_value is None:
        return bool(default)
    return str(raw_value).strip().lower() in {"1", "true", "on", "yes"}


def slugify(text):
    """Gera slug a partir do texto."""
    slug = text.lower().strip()
    slug = re.sub(r'[^\w\s-]', '', slug)
    slug = re.sub(r'[-\s]+', '-', slug)
    return slug


def _log_activity_safe(db, tenant_id, action, details=None):
    user_id = session.get('user_id')
    if not user_id:
        return
    try:
        ActivityService.log_action(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            action=action,
            details=details,
            ip_address=request.headers.get('X-Forwarded-For', request.remote_addr),
        )
    except Exception:
        logging.getLogger(__name__).exception('Falha ao registrar atividade %s', action)


@bp.route('/')
@login_required
def list_groups(tenant_slug):
    # Hub unificado: grupos/provedores agora fazem parte da Central de Operacao.
    return redirect(url_for('tenant_operations.index', tenant_slug=tenant_slug))


@bp.route('/add', methods=['GET', 'POST'])
@login_required
@tenant_admin_required
def add_group(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404
    
    if request.method == 'POST':
        try:
            name = (request.form.get('name') or '').strip()
            if not name:
                raise ValueError('Informe o nome do grupo.')
            connection_type = request.form.get('connection_type', 'direct')
            
            data = {
                'name': name,
                'slug': slugify(name),
                'description': request.form.get('description'),
                'connection_type': connection_type,
                # VPN fields
                'uses_vpn': connection_type == 'vpn',
                'vpn_type': request.form.get('vpn_type', 'l2tp'),
                'vpn_server': request.form.get('vpn_server'),
                'vpn_username': request.form.get('vpn_username'),
                'vpn_password': request.form.get('vpn_password'),
                'vpn_ipsec_secret': request.form.get('vpn_ipsec_secret'),
                # Jump Host fields
                'uses_jump_host': connection_type == 'jump_host',
                'jump_host': request.form.get('jump_host'),
                'jump_port': int(request.form.get('jump_port', 22) or 22),
                'jump_username': request.form.get('jump_username'),
                'jump_password': request.form.get('jump_password'),
                'jump_key': request.form.get('jump_key'),
            }
            DeviceGroupService.create_group(db, tenant.id, data)
            flash('Grupo criado com sucesso!', 'success')
            return redirect(url_for('tenant_groups.list_groups', tenant_slug=tenant_slug))
        except Exception as e:
            flash(f'Erro ao criar grupo: {str(e)}', 'error')
        finally:
            db.close()
    
    return render_template('tenant/groups/add.html', tenant=tenant)


@bp.route('/<group_id>')
@login_required
def view_group(tenant_slug, group_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404
    
    try:
        group_uuid = uuid.UUID(group_id)
    except ValueError:
        return "Invalid group ID", 400
    
    group = DeviceGroupService.get_group(db, group_uuid)
    if not group or str(group.tenant_id) != str(tenant.id):
        db.close()
        return "Group not found", 404
    
    # A visualizacao dedicada de grupo foi removida; redireciona para a lista
    # de dispositivos filtrada pelo grupo para manter compatibilidade com links antigos.
    db.close()
    return redirect(
        url_for('tenant_devices.list_devices', tenant_slug=tenant_slug, group_id=str(group_uuid))
    )


@bp.route('/<group_id>/edit', methods=['GET', 'POST'])
@login_required
@tenant_admin_required
def edit_group(tenant_slug, group_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404
    
    try:
        group_uuid = uuid.UUID(group_id)
    except ValueError:
        return "Invalid group ID", 400
    
    group = DeviceGroupService.get_group(db, group_uuid)
    if not group or str(group.tenant_id) != str(tenant.id):
        db.close()
        return "Group not found", 404
    
    if request.method == 'POST':
        try:
            connection_type = request.form.get('connection_type', 'direct')
            current_vpn_password = _current_saved_secret_if_owner(
                db,
                getattr(group, 'vpn_password_encrypted', None),
                context_label='tenant_groups.edit_group.vpn_password',
                entity_id=group.id,
            )
            current_vpn_ipsec_secret = _current_saved_secret_if_owner(
                db,
                getattr(group, 'vpn_ipsec_secret_encrypted', None),
                context_label='tenant_groups.edit_group.vpn_ipsec_secret',
                entity_id=group.id,
            )
            current_jump_password = _current_saved_secret_if_owner(
                db,
                getattr(group, 'jump_password_encrypted', None),
                context_label='tenant_groups.edit_group.jump_password',
                entity_id=group.id,
            )
            current_jump_key = _current_saved_secret_if_owner(
                db,
                getattr(group, 'jump_key_encrypted', None),
                context_label='tenant_groups.edit_group.jump_key',
                entity_id=group.id,
            )
            
            data = {
                'name': request.form.get('name'),
                'description': request.form.get('description'),
                'connection_type': connection_type,
                # VPN fields
                'uses_vpn': connection_type == 'vpn',
                'vpn_type': request.form.get('vpn_type', 'l2tp'),
                'vpn_server': request.form.get('vpn_server'),
                'vpn_username': request.form.get('vpn_username'),
                # Jump Host fields
                'uses_jump_host': connection_type == 'jump_host',
                'jump_host': request.form.get('jump_host'),
                'jump_port': int(request.form.get('jump_port', 22) or 22),
                'jump_username': request.form.get('jump_username'),
            }
            
            # Só atualiza senhas se foram fornecidas
            if request.form.get('vpn_password') and request.form.get('vpn_password') != current_vpn_password:
                data['vpn_password'] = request.form.get('vpn_password')
            if request.form.get('vpn_ipsec_secret') and request.form.get('vpn_ipsec_secret') != current_vpn_ipsec_secret:
                data['vpn_ipsec_secret'] = request.form.get('vpn_ipsec_secret')
            if request.form.get('jump_password') and request.form.get('jump_password') != current_jump_password:
                data['jump_password'] = request.form.get('jump_password')
            if request.form.get('jump_key') and request.form.get('jump_key') != current_jump_key:
                data['jump_key'] = request.form.get('jump_key')
            
            DeviceGroupService.update_group(db, group_uuid, data)
            if ('jump_password' in data) or ('jump_key' in data):
                jump_host_service.mark_credentials_rotated(str(tenant.id), group)
            flash('Grupo atualizado com sucesso!', 'success')
            return redirect(url_for('tenant_groups.list_groups', tenant_slug=tenant_slug))
        except Exception as e:
            flash(f'Erro ao atualizar grupo: {str(e)}', 'error')

    group_devices = (
        db.query(Device)
        .filter(Device.group_id == group.id, Device.tenant_id == tenant.id, Device.is_active == True)
        .order_by(Device.name.asc())
        .all()
    )
    sample_device = group_devices[0] if group_devices else None
    can_view_saved_credentials = _can_view_saved_credentials(db)
    group_current_vpn_password = None
    group_current_vpn_ipsec_secret = None
    group_current_jump_password = None
    group_current_jump_key = None
    if can_view_saved_credentials:
        group_current_vpn_password = _safe_decrypt_secret(
            getattr(group, 'vpn_password_encrypted', None),
            context_label='tenant_groups.edit_group.vpn_password',
            entity_id=group.id,
        )
        group_current_vpn_ipsec_secret = _safe_decrypt_secret(
            getattr(group, 'vpn_ipsec_secret_encrypted', None),
            context_label='tenant_groups.edit_group.vpn_ipsec_secret',
            entity_id=group.id,
        )
        group_current_jump_password = _safe_decrypt_secret(
            getattr(group, 'jump_password_encrypted', None),
            context_label='tenant_groups.edit_group.jump_password',
            entity_id=group.id,
        )
        group_current_jump_key = _safe_decrypt_secret(
            getattr(group, 'jump_key_encrypted', None),
            context_label='tenant_groups.edit_group.jump_key',
            entity_id=group.id,
        )
    db.close()
    return render_template(
        'tenant/groups/edit.html',
        tenant=tenant,
        group=group,
        sample_device=sample_device,
        can_view_saved_credentials=can_view_saved_credentials,
        group_current_vpn_password=group_current_vpn_password,
        group_current_vpn_ipsec_secret=group_current_vpn_ipsec_secret,
        group_current_jump_password=group_current_jump_password,
        group_current_jump_key=group_current_jump_key,
    )


@bp.route('/<group_id>/delete', methods=['POST'])
@login_required
@tenant_admin_required
def delete_group(tenant_slug, group_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404
    
    try:
        group_uuid = uuid.UUID(group_id)
    except ValueError:
        flash('ID de grupo inválido', 'error')
        return redirect(url_for('tenant_groups.list_groups', tenant_slug=tenant_slug))
    
    if DeviceGroupService.delete_group(db, group_uuid):
        flash('Grupo removido com sucesso!', 'success')
    else:
        flash('Erro ao remover grupo', 'error')
    
    db.close()
    return redirect(url_for('tenant_groups.list_groups', tenant_slug=tenant_slug))


@bp.route('/<group_id>/run-all', methods=['POST'])
@login_required
def run_backup_all(tenant_slug, group_id):
    """Executa backup de todos os dispositivos de um grupo."""
    from app.tasks.backups import run_backup_task, run_vpn_group_backups_task
    
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404

    force_stop_cleared = _clear_global_force_stop_flag()
    
    return_to = (request.form.get('return_to') or '').strip().lower()

    def _redirect_target():
        if return_to == 'operations':
            return redirect(url_for('tenant_operations.index', tenant_slug=tenant_slug))
        return redirect(url_for('tenant_groups.view_group', tenant_slug=tenant_slug, group_id=group_id))

    try:
        group_uuid = uuid.UUID(group_id)
    except ValueError:
        db.close()
        flash('ID de grupo inválido', 'error')
        return redirect(url_for('tenant_operations.index', tenant_slug=tenant_slug))
    
    group = DeviceGroupService.get_group(db, group_uuid)
    if not group or str(group.tenant_id) != str(tenant.id):
        db.close()
        flash('Grupo não encontrado', 'error')
        return redirect(url_for('tenant_operations.index', tenant_slug=tenant_slug))
    if not bool(getattr(group, 'is_active', True)):
        db.close()
        flash('Grupo inativo. Reative o grupo para executar backups.', 'warning')
        return redirect(url_for('tenant_operations.index', tenant_slug=tenant_slug))
    
    devices = DeviceService.get_devices_by_group(db, group_uuid)
    include_unscheduled = _value_bool(request.form.get("include_unscheduled"), default=True)
    eligible_devices = devices if include_unscheduled else [d for d in devices if d.backup_scheduled]

    if uses_vpn_tunnel(group) and eligible_devices:
        task = run_vpn_group_backups_task.apply_async(
            args=[str(group.id), str(tenant.id), [str(d.id) for d in eligible_devices]],
            queue='vpn_queue'
        )
        db.close()
        if force_stop_cleared:
            flash('Bloqueio global de parada foi removido automaticamente para iniciar este backup.', 'warning')
        flash(
            f'Backup do grupo "{group.name}" enfileirado em VPN ({len(eligible_devices)} dispositivos). Task: {task.id}',
            'success'
        )
        return _redirect_target()

    queued = 0
    for device in eligible_devices:
        target_queue = 'vpn_queue' if (device.group and uses_vpn_tunnel(device.group, device=device)) else 'celery'
        run_backup_task.apply_async(args=[str(device.id)], queue=target_queue)
        queued += 1

    if queued == 0 and not (uses_vpn_tunnel(group) and eligible_devices):
        db.close()
        if include_unscheduled:
            flash('Nenhum dispositivo ativo elegivel para backup neste grupo.', 'warning')
        else:
            flash('Nenhum dispositivo agendado para backup neste grupo.', 'warning')
        return _redirect_target()
    
    db.close()
    if force_stop_cleared:
        flash('Bloqueio global de parada foi removido automaticamente para iniciar este backup.', 'warning')
    flash(f'Backup do grupo "{group.name}" enfileirado: {queued} dispositivos.', 'success')
    return _redirect_target()


@bp.route('/<group_id>/toggle-active', methods=['POST'])
@login_required
@tenant_admin_required
def toggle_group_active(tenant_slug, group_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404

    return_to = (request.form.get('return_to') or '').strip().lower()
    action = (request.form.get('action') or '').strip().lower()
    if action not in {'activate', 'deactivate'}:
        action = 'toggle'

    try:
        group_uuid = uuid.UUID(group_id)
    except ValueError:
        db.close()
        flash('ID de grupo inválido', 'error')
        return redirect(url_for('tenant_operations.index', tenant_slug=tenant_slug))

    group = DeviceGroupService.get_group(db, group_uuid)
    if not group or str(group.tenant_id) != str(tenant.id):
        db.close()
        flash('Grupo não encontrado', 'error')
        return redirect(url_for('tenant_operations.index', tenant_slug=tenant_slug))

    current_active = bool(getattr(group, 'is_active', True))
    if action == 'activate':
        target_active = True
    elif action == 'deactivate':
        target_active = False
    else:
        target_active = not current_active

    if target_active == current_active:
        db.close()
        flash(
            f'Grupo "{group.name}" já está {"ativo" if current_active else "inativo"}.',
            'warning',
        )
    else:
        DeviceGroupService.update_group(db, group_uuid, {'is_active': target_active})
        db.close()
        flash(
            f'Grupo "{group.name}" {"reativado" if target_active else "desativado"} com sucesso.',
            'success',
        )

    if return_to == 'edit':
        return redirect(url_for('tenant_groups.edit_group', tenant_slug=tenant_slug, group_id=group_id))
    if return_to == 'groups':
        return redirect(url_for('tenant_groups.list_groups', tenant_slug=tenant_slug))
    return redirect(url_for('tenant_operations.index', tenant_slug=tenant_slug))


@bp.route('/<group_id>/test-vpn', methods=['POST'])
@login_required
def test_group_vpn(tenant_slug, group_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404

    is_ajax = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in (request.headers.get('Accept') or '')
    )

    try:
        group_uuid = uuid.UUID(group_id)
    except ValueError:
        db.close()
        if is_ajax:
            return jsonify({"ok": False, "error": "ID de grupo invalido."}), 400
        flash("ID de grupo invalido.", "error")
        return redirect(url_for('tenant_groups.list_groups', tenant_slug=tenant_slug))

    group = DeviceGroupService.get_group(db, group_uuid)
    if not group or str(group.tenant_id) != str(tenant.id):
        db.close()
        if is_ajax:
            return jsonify({"ok": False, "error": "Grupo nao encontrado."}), 404
        flash("Grupo nao encontrado.", "error")
        return redirect(url_for('tenant_groups.list_groups', tenant_slug=tenant_slug))
    if not bool(getattr(group, "is_active", True)):
        db.close()
        if is_ajax:
            return jsonify({"ok": False, "error": "Grupo inativo. Reative para testar VPN."}), 400
        flash("Grupo inativo. Reative para testar VPN.", "warning")
        return redirect(url_for('tenant_groups.edit_group', tenant_slug=tenant_slug, group_id=group_id))

    if not group.uses_vpn:
        db.close()
        if is_ajax:
            return jsonify({"ok": False, "error": "Este grupo nao usa VPN."}), 400
        flash("Este grupo nao usa VPN.", "warning")
        return redirect(url_for('tenant_groups.edit_group', tenant_slug=tenant_slug, group_id=group_id))

    task = run_group_vpn_test_task.apply_async(args=[str(group.id)], queue='vpn_queue')
    task_id = str(task.id)
    register_task(
        task_id=task_id,
        tenant_id=str(tenant.id),
        device_name=f"Teste VPN - {group.name}",
        group_id=str(group.id),
    )
    append_task_log(
        task_id,
        group.name,
        "Task criada na fila vpn_queue. Aguardando worker iniciar.",
        "info",
    )

    db.close()
    if is_ajax:
        return jsonify({
            "ok": True,
            "task_id": task_id,
            "queue": "vpn_queue",
            "device_name": f"Teste VPN - {group.name}",
            "status_url": url_for('tenant_backups.task_status', tenant_slug=tenant_slug, task_id=task_id),
            "logs_url": url_for('tenant_backups.task_logs', tenant_slug=tenant_slug, task_id=task_id),
        }), 202

    flash(f"Teste VPN enfileirado com sucesso! Task: {task_id}", "success")
    return redirect(url_for('tenant_groups.edit_group', tenant_slug=tenant_slug, group_id=group_id))


@bp.route('/<group_id>/diagnose-jump', methods=['POST'])
@login_required
@tenant_operator_required
def diagnose_group_jump(tenant_slug, group_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404

    is_ajax = (
        request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in (request.headers.get('Accept') or '')
    )

    try:
        group_uuid = uuid.UUID(group_id)
    except ValueError:
        db.close()
        if is_ajax:
            return jsonify({"ok": False, "error": "ID de grupo invalido."}), 400
        flash("ID de grupo invalido.", "error")
        return redirect(url_for('tenant_groups.edit_group', tenant_slug=tenant_slug, group_id=group_id))

    group = DeviceGroupService.get_group(db, group_uuid)
    if not group or str(group.tenant_id) != str(tenant.id):
        db.close()
        if is_ajax:
            return jsonify({"ok": False, "error": "Grupo nao encontrado."}), 404
        flash("Grupo nao encontrado.", "error")
        return redirect(url_for('tenant_groups.list_groups', tenant_slug=tenant_slug))

    if not uses_jump_host(group):
        db.close()
        if is_ajax:
            return jsonify({"ok": False, "error": "Este grupo nao usa Jump Host."}), 400
        flash("Este grupo nao usa Jump Host.", "warning")
        return redirect(url_for('tenant_groups.edit_group', tenant_slug=tenant_slug, group_id=group_id))

    task = run_group_jump_host_diagnostic_task.apply_async(args=[str(group.id)], queue='vpn_queue')
    task_id = str(task.id)
    register_task(
        task_id=task_id,
        tenant_id=str(tenant.id),
        device_name=f"Teste Jump Host - {group.name}",
        group_id=str(group.id),
    )
    append_task_log(
        task_id,
        group.name,
        "Task de teste criada. Validando alcance, login SSH e shell do Jump Host.",
        "info",
    )
    _log_activity_safe(db, tenant.id, "GROUP_JUMP_DIAG_START", f"Grupo={group.name}; task={task_id}")
    db.close()

    if is_ajax:
        return jsonify({
            "ok": True,
            "task_id": task_id,
            "queue": "vpn_queue",
            "device_name": f"Teste Jump Host - {group.name}",
            "status_url": url_for('tenant_backups.task_status', tenant_slug=tenant_slug, task_id=task_id),
            "logs_url": url_for('tenant_backups.task_logs', tenant_slug=tenant_slug, task_id=task_id),
        }), 202

    flash(f"Teste do Jump Host enfileirado com sucesso! Task: {task_id}", "success")
    return redirect(url_for('tenant_groups.edit_group', tenant_slug=tenant_slug, group_id=group_id))


@bp.route('/<group_id>/collect-jump-diagnostics', methods=['POST'])
@login_required
@tenant_operator_required
def collect_jump_diagnostics(tenant_slug, group_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        return "Tenant not found", 404

    try:
        group_uuid = uuid.UUID(group_id)
    except ValueError:
        db.close()
        return jsonify({"ok": False, "error": "ID de grupo invalido."}), 400

    group = DeviceGroupService.get_group(db, group_uuid)
    if not group or str(group.tenant_id) != str(tenant.id):
        db.close()
        return jsonify({"ok": False, "error": "Grupo nao encontrado."}), 404

    device = None
    raw_device_id = (request.form.get('device_id') or '').strip()
    if raw_device_id:
        try:
            device_uuid = uuid.UUID(raw_device_id)
            device = db.query(Device).filter(Device.id == device_uuid, Device.group_id == group.id).first()
        except ValueError:
            device = None

    result = jump_host_service.collect_remote_diagnostics(str(tenant.id), group, device=device)
    _log_activity_safe(db, tenant.id, "GROUP_JUMP_DIAG_COLLECT", f"Grupo={group.name}; device={getattr(device, 'name', '-')}")
    db.close()
    return jsonify(result)
