"""
Blueprint Flask para gerenciamento de API Tokens do tenant.

Rotas:
  GET  /tenant/<slug>/settings/api-tokens          → lista tokens
  POST /tenant/<slug>/settings/api-tokens/create   → cria token
  POST /tenant/<slug>/settings/api-tokens/<id>/revoke → revoga token
"""

from flask import Blueprint, render_template, redirect, url_for, request, flash, session, abort
from app.web.auth.decorators import login_required
from app.core.database import SessionLocal
from app.models.user import User, UserRole
from app.models.tenant import Tenant
from app.services.api_token_service import ApiTokenService
import uuid

bp = Blueprint('api_tokens', __name__, url_prefix='/tenant/<tenant_slug>/settings/api-tokens')


def _get_db_and_tenant(tenant_slug):
    if session.get('user_role') != UserRole.SUPER_ADMIN.value and session.get('tenant_slug') != tenant_slug:
        abort(403)
    db = SessionLocal()
    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
    return db, tenant


def _require_admin(redirect_slug):
    if session.get('user_role') not in [
        UserRole.SUPER_ADMIN.value,
        UserRole.TENANT_OWNER.value,
        UserRole.TENANT_ADMIN.value,
    ]:
        flash('Apenas administradores podem gerenciar tokens de API.', 'error')
        return redirect(url_for('tenant.dashboard', tenant_slug=redirect_slug))
    return None


@bp.route('/', methods=['GET'])
@login_required
def list_tokens(tenant_slug):
    """Lista todos os tokens de API do tenant."""
    guard = _require_admin(tenant_slug)
    if guard:
        return guard

    db, tenant = _get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404

    tokens = ApiTokenService.list_tokens(db, tenant.id)
    db.close()

    return render_template(
        'tenant/settings/api_tokens.html',
        tenant=tenant,
        tokens=tokens,
        new_token=None,
    )


@bp.route('/create', methods=['POST'])
@login_required
def create_token(tenant_slug):
    """Cria um novo API token."""
    guard = _require_admin(tenant_slug)
    if guard:
        return guard

    db, tenant = _get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404

    name = request.form.get('name', '').strip()
    if not name:
        flash('Informe um nome para o token.', 'error')
        db.close()
        return redirect(url_for('api_tokens.list_tokens', tenant_slug=tenant_slug))

    user_id_str = session.get('user_id')
    try:
        user_id = uuid.UUID(user_id_str)
    except (TypeError, ValueError):
        flash('Sessão inválida.', 'error')
        db.close()
        return redirect(url_for('api_tokens.list_tokens', tenant_slug=tenant_slug))

    try:
        token_obj, raw_token = ApiTokenService.create_token(
            db=db,
            tenant_id=tenant.id,
            user_id=user_id,
            name=name,
        )
        tokens = ApiTokenService.list_tokens(db, tenant.id)
        db.close()

        # Renderiza a página com o token raw visível (apenas desta vez)
        return render_template(
            'tenant/settings/api_tokens.html',
            tenant=tenant,
            tokens=tokens,
            new_token=raw_token,
            new_token_name=name,
        )
    except Exception as e:
        db.rollback()
        db.close()
        flash(f'Erro ao criar token: {str(e)}', 'error')
        return redirect(url_for('api_tokens.list_tokens', tenant_slug=tenant_slug))


@bp.route('/<token_id>/revoke', methods=['POST'])
@login_required
def revoke_token(tenant_slug, token_id):
    """Revoga (desativa) um token."""
    guard = _require_admin(tenant_slug)
    if guard:
        return guard

    db, tenant = _get_db_and_tenant(tenant_slug)
    if not tenant:
        db.close()
        return "Tenant not found", 404

    try:
        tid = uuid.UUID(token_id)
    except ValueError:
        flash('Token inválido.', 'error')
        db.close()
        return redirect(url_for('api_tokens.list_tokens', tenant_slug=tenant_slug))

    success = ApiTokenService.revoke_token(db, tid, tenant.id)
    db.close()

    if success:
        flash('Token revogado com sucesso.', 'success')
    else:
        flash('Token não encontrado.', 'error')

    return redirect(url_for('api_tokens.list_tokens', tenant_slug=tenant_slug))
