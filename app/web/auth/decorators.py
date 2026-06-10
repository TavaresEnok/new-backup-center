from functools import wraps
from flask import session, redirect, url_for, flash, request, abort
from app.models.user import UserRole
import uuid

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def tenant_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login', next=request.url))
        
        role = session.get('user_role')
        if role not in [UserRole.SUPER_ADMIN.value, UserRole.TENANT_OWNER.value, UserRole.TENANT_ADMIN.value]:
            flash('Você não tem permissão para acessar esta área.', 'error')
            return redirect(url_for('tenant.dashboard', tenant_slug=kwargs.get('tenant_slug')))
        return f(*args, **kwargs)
    return decorated_function


def tenant_operator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login', next=request.url))

        role = session.get('user_role')
        if role not in [
            UserRole.SUPER_ADMIN.value,
            UserRole.TENANT_OWNER.value,
            UserRole.TENANT_ADMIN.value,
            UserRole.TENANT_TECHNICIAN.value,
        ]:
            flash('Você não tem permissão para executar esta operação.', 'error')
            return redirect(url_for('tenant.dashboard', tenant_slug=kwargs.get('tenant_slug')))
        return f(*args, **kwargs)
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login', next=request.url))
            
        if session.get('user_role') != UserRole.SUPER_ADMIN.value:
            flash('Acesso restrito a super administradores.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


def tenant_owner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login', next=request.url))

        role = session.get('user_role')
        if role not in [UserRole.SUPER_ADMIN.value, UserRole.TENANT_OWNER.value]:
            flash('Acesso restrito ao Administrador Master.', 'error')
            return redirect(url_for('tenant.dashboard', tenant_slug=kwargs.get('tenant_slug')))
        return f(*args, **kwargs)
    return decorated_function
