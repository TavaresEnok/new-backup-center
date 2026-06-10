from flask import Blueprint, render_template, redirect, url_for, request, flash, session, abort
from app.web.auth.decorators import login_required
from app.core.database import SessionLocal
from app.models.user import User, UserRole
from app.core.security import verify_password
from app.models.tenant import Tenant
import uuid

bp = Blueprint('tenant_settings', __name__, url_prefix='/tenant/<tenant_slug>/settings')

def _get_session_user_uuid():
    user_id = session.get('user_id')
    if not user_id:
        return None
    try:
        return uuid.UUID(user_id)
    except (TypeError, ValueError):
        return None

def get_db_and_tenant(tenant_slug):
    # Cross-tenant check
    if session.get('user_role') != UserRole.SUPER_ADMIN.value and session.get('tenant_slug') != tenant_slug:
        abort(403)
        
    db = SessionLocal()
    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
    if not tenant:
        db.close()
    return db, tenant

@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404
        
    user_uuid = _get_session_user_uuid()
    if not user_uuid:
        db.close()
        flash('Sessao invalida. Faca login novamente.', 'error')
        return redirect(url_for('auth.login'))

    user = db.query(User).filter_by(id=user_uuid).first()
    if not user:
        db.close()
        flash('Usuario nao encontrado.', 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        try:
            from app.services.auth_service import AuthService
            
            full_name = request.form.get('full_name')
            password = request.form.get('password')
            current_password = request.form.get('current_password') # Optional security check
            
            if full_name:
                user.full_name = full_name
            
            if password:
                if not current_password or not verify_password(current_password, user.password_hash):
                    flash('Senha atual invalida.', 'error')
                    db.close()
                    return redirect(url_for('tenant_settings.profile', tenant_slug=tenant_slug))
                user.password_hash = AuthService.get_password_hash(password)
                
            db.commit()
            
            # Update session
            session['user_name'] = user.full_name
            
            # Log Activity
            from app.services.activity_service import ActivityService
            ActivityService.log_action(db, tenant.id, user.id, "UPDATE_PROFILE", "User updated profile", request.remote_addr)
            
            flash('Perfil atualizado com sucesso!', 'success')
            return redirect(url_for('tenant_settings.profile', tenant_slug=tenant_slug))
        except Exception as e:
            db.rollback()
            flash(f'Erro ao atualizar perfil: {str(e)}', 'error')
    
    db.close()
    return render_template('tenant/settings/profile.html', tenant=tenant, user=user)

@bp.route('/notifications')
@login_required
def notifications(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404

    from app.models.notification import Notification
    user_id = _get_session_user_uuid()
    notifications_list = []
    if user_id:
        notifications_list = db.query(Notification).filter(
            Notification.user_id == user_id
        ).order_by(Notification.created_at.desc()).limit(50).all()

    db.close()
    return render_template('tenant/settings/notifications.html', tenant=tenant, notifications=notifications_list)

@bp.route('/general', methods=['GET', 'POST'])
@login_required
def general_settings(tenant_slug):
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404
    
    # Check if admin
    if session.get('user_role') not in [
        UserRole.SUPER_ADMIN.value,
        UserRole.TENANT_OWNER.value,
        UserRole.TENANT_ADMIN.value,
    ]:
        flash('Apenas administradores podem alterar configuracoes da empresa.', 'error')
        db.close()
        return redirect(url_for('tenant.dashboard', tenant_slug=tenant_slug))

    if request.method == 'POST':
        try:
            name = request.form.get('name')
            email = request.form.get('email')
            # slug = request.form.get('slug') # Changing slug is dangerous, let's avoid for now
            
            if name:
                tenant.name = name
            if email is not None:
                tenant.email = email
                
            db.commit()
            
            # Log Activity
            from app.services.activity_service import ActivityService
            user_id = _get_session_user_uuid()
            ActivityService.log_action(db, tenant.id, user_id, "UPDATE_TENANT", f"Updated tenant settings: {name}", request.remote_addr)
            
            flash('Configuracoes da empresa atualizadas!', 'success')
            return redirect(url_for('tenant_settings.general_settings', tenant_slug=tenant_slug))
        except Exception as e:
            db.rollback()
            flash(f'Erro ao atualizar empresa: {str(e)}', 'error')

    db.close()
    return render_template('tenant/settings/general.html', tenant=tenant)


@bp.route('/reports')
@login_required
def reports(tenant_slug):
    from app.services.report_service import ReportService
    
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404
    
    reports_list = ReportService.get_tenant_reports(db, tenant.id)
    
    db.close()
    return render_template('tenant/settings/reports.html', tenant=tenant, reports=reports_list)


@bp.route('/reports/create', methods=['POST'])
@login_required
def create_report(tenant_slug):
    from app.services.report_service import ReportService
    
    db, tenant = get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404
    
    try:
        recipients_str = request.form.get('recipients', '')
        recipients = [e.strip() for e in recipients_str.split(',') if e.strip()]
        
        data = {
            'name': request.form.get('name'),
            'report_type': request.form.get('report_type', 'daily_summary'),
            'schedule': request.form.get('schedule', 'daily'),
            'recipients': recipients
        }
        
        ReportService.create_report(db, tenant.id, data)
        flash('Relatorio criado com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao criar relatorio: {str(e)}', 'error')
    finally:
        db.close()
    
    return redirect(url_for('tenant_settings.reports', tenant_slug=tenant_slug))


