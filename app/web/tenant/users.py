from flask import Blueprint, render_template, redirect, url_for, request, flash, session, abort
from app.web.auth.decorators import login_required, tenant_admin_required
from app.core.database import SessionLocal
from app.models.tenant import Tenant
from app.models.user import User, UserRole
from app.core.security import get_password_hash, validate_password_strength
from app.services.plan_limits_service import PlanLimitsService
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from sqlalchemy import or_
import uuid

bp = Blueprint('tenant_users', __name__, url_prefix='/tenant/<tenant_slug>/users')


def get_db_and_tenant(tenant_slug):
    # Cross-tenant check
    if session.get('user_role') != UserRole.SUPER_ADMIN.value and session.get('tenant_slug') != tenant_slug:
        abort(403)
        
    db = SessionLocal()
    PlanLimitsService.ensure_schema()
    tenant = db.query(Tenant).options(joinedload(Tenant.plan)).filter(Tenant.slug == tenant_slug).first()
    if not tenant:
        db.close()
    return db, tenant


@bp.route('/')
@login_required
def list_users(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404
    
    status_filter = (request.args.get('status') or 'active').strip().lower()
    search_query = (request.args.get('q') or '').strip()
    users_query = db.query(User).filter(User.tenant_id == tenant.id)
    if status_filter == 'inactive':
        users_query = users_query.filter(User.is_active == False)
    elif status_filter != 'all':
        status_filter = 'active'
        users_query = users_query.filter(User.is_active == True)

    if search_query:
        like_query = f"%{search_query}%"
        users_query = users_query.filter(
            or_(
                User.full_name.ilike(like_query),
                User.email.ilike(like_query),
            )
        )

    users = users_query.order_by(User.full_name).all()

    users_all = db.query(User).filter(User.tenant_id == tenant.id).all()
    
    # Estatísticas
    stats = {
        'total': len(users_all),
        'admins': sum(1 for u in users_all if u.role in [UserRole.TENANT_OWNER, UserRole.TENANT_ADMIN]),
        'technicians': sum(1 for u in users_all if u.role == UserRole.TENANT_TECHNICIAN),
        'active': sum(1 for u in users_all if u.is_active),
        'inactive': sum(1 for u in users_all if not u.is_active),
        'filtered_total': len(users),
    }
    
    db.close()
    return render_template(
        'tenant/users/list.html',
        tenant=tenant,
        users=users,
        stats=stats,
        UserRole=UserRole,
        status_filter=status_filter,
        search_query=search_query,
    )


@bp.route('/add', methods=['GET', 'POST'])
@login_required
@tenant_admin_required
def add_user(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404
    
    if request.method == 'POST':
        try:
            limit_check = PlanLimitsService.check_can_add_user(db, tenant)
            if not limit_check.allowed:
                flash(limit_check.reason, 'error')
                db.close()
                return redirect(url_for('tenant_users.list_users', tenant_slug=tenant_slug))

            email = request.form.get('email')
            password = request.form.get('password')
            password_error = validate_password_strength(password)
            if password_error:
                flash(password_error, 'error')
                db.close()
                return redirect(url_for('tenant_users.add_user', tenant_slug=tenant_slug))
            
            # Verifica se email já existe
            existing = db.query(User).filter_by(email=email).first()
            if existing:
                flash('Este e-mail já está em uso.', 'error')
                db.close()
                return redirect(url_for('tenant_users.add_user', tenant_slug=tenant_slug))
            
            role_str = request.form.get('role', 'TENANT_TECHNICIAN')
            if role_str not in UserRole.__members__:
                flash('Perfil de acesso inválido.', 'error')
                db.close()
                return redirect(url_for('tenant_users.add_user', tenant_slug=tenant_slug))
            role = UserRole[role_str]
            
            user = User(
                tenant_id=tenant.id,
                email=email,
                full_name=request.form.get('full_name'),
                password_hash=get_password_hash(password),
                role=role,
                is_active=True,
                must_change_password=True,
                password_changed_at=None,
            )
            db.add(user)
            db.commit()
            flash('Usuário criado com sucesso!', 'success')
            db.close()
            return redirect(url_for('tenant_users.list_users', tenant_slug=tenant_slug))
        except Exception as e:
            flash(f'Erro ao criar usuário: {str(e)}', 'error')
            db.rollback()
            db.close()
            return redirect(url_for('tenant_users.add_user', tenant_slug=tenant_slug))
        finally:
            pass
    
    db.close()
    return render_template(
        'tenant/users/add.html',
        tenant=tenant,
        UserRole=UserRole
    )


@bp.route('/<user_id>/edit', methods=['GET', 'POST'])
@login_required
@tenant_admin_required
def edit_user(tenant_slug, user_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404
    
    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError:
        db.close()
        return "Invalid user ID", 400
    
    user = db.query(User).filter_by(id=user_uuid).first()
    if not user or str(user.tenant_id) != str(tenant.id):
        db.close()
        return "User not found", 404
    
    if request.method == 'POST':
        try:
            was_active = bool(user.is_active)
            new_is_active = request.form.get('is_active') == 'on'
            if new_is_active and not was_active:
                limit_check = PlanLimitsService.check_can_add_user(db, tenant)
                if not limit_check.allowed:
                    flash(limit_check.reason, 'error')
                    db.close()
                    return render_template(
                        'tenant/users/edit.html',
                        tenant=tenant,
                        user=user,
                        UserRole=UserRole
                    )

            user.full_name = request.form.get('full_name')
            user.email = request.form.get('email')
            user.is_active = new_is_active
            
            role_str = request.form.get('role')
            if role_str:
                if role_str not in UserRole.__members__:
                    flash('Perfil de acesso inválido.', 'error')
                    db.close()
                    return redirect(url_for('tenant_users.edit_user', tenant_slug=tenant_slug, user_id=user_id))
                user.role = UserRole[role_str]
            
            password = request.form.get('password')
            if password:
                password_error = validate_password_strength(password)
                if password_error:
                    flash(password_error, 'error')
                    db.close()
                    return render_template(
                        'tenant/users/edit.html',
                        tenant=tenant,
                        user=user,
                        UserRole=UserRole
                    )
                user.password_hash = get_password_hash(password)
                user.must_change_password = True
                user.password_changed_at = None
            
            db.commit()
            flash('Usuário atualizado com sucesso!', 'success')
            db.close()
            return redirect(url_for('tenant_users.list_users', tenant_slug=tenant_slug))
        except IntegrityError:
            db.rollback()
            flash('Este e-mail já está em uso por outro usuário.', 'error')
            db.close()
            return redirect(url_for('tenant_users.edit_user', tenant_slug=tenant_slug, user_id=user_id))
        except Exception as e:
            flash(f'Erro ao atualizar: {str(e)}', 'error')
            db.rollback()
            db.close()
            return redirect(url_for('tenant_users.edit_user', tenant_slug=tenant_slug, user_id=user_id))
    
    db.close()
    return render_template(
        'tenant/users/edit.html',
        tenant=tenant,
        user=user,
        UserRole=UserRole
    )


@bp.route('/<user_id>/delete', methods=['POST'])
@login_required
@tenant_admin_required
def delete_user(tenant_slug, user_id):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404
    
    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError:
        flash('ID de usuário inválido', 'error')
        return redirect(url_for('tenant_users.list_users', tenant_slug=tenant_slug))
    
    user = db.query(User).filter_by(id=user_uuid).first()
    if not user or str(user.tenant_id) != str(tenant.id):
        flash('Usuário não encontrado', 'error')
        db.close()
        return redirect(url_for('tenant_users.list_users', tenant_slug=tenant_slug))

    current_user_id = session.get('user_id')
    if current_user_id and str(user.id) == str(current_user_id):
        flash('Não é permitido remover o usuário logado.', 'error')
        db.close()
        return redirect(url_for('tenant_users.list_users', tenant_slug=tenant_slug))

    try:
        db.delete(user)
        db.commit()
        flash('Usuário removido com sucesso!', 'success')
    except IntegrityError:
        db.rollback()
        user.is_active = False
        db.commit()
        flash('Usuário possui histórico vinculado. Foi desativado em vez de removido.', 'warning')
    
    db.close()
    return redirect(url_for('tenant_users.list_users', tenant_slug=tenant_slug))
