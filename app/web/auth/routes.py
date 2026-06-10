from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from app.services.auth_service import AuthService
from app.models.user import UserRole
from app.models.plan import Plan
from app.core.database import SessionLocal
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import logging
from app.core.config import settings
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import smtplib
from email.message import EmailMessage
import redis
import uuid
from urllib.parse import quote
from sqlalchemy import func
from app.core.totp import generate_totp_secret, verify_totp
from app.core.security import validate_password_strength

MAX_LOGIN_ATTEMPTS_PER_IP = 20
MAX_LOGIN_ATTEMPTS_PER_EMAIL = 8
LOGIN_WINDOW_SECONDS = 900
LOGIN_LOCKOUT_SECONDS = 900
MAX_FORGOT_PASSWORD_PER_IP = 8
FORGOT_PASSWORD_WINDOW_SECONDS = 3600
FORGOT_PASSWORD_LOCKOUT_SECONDS = 1800
PENDING_2FA_SESSION_KEY = "pending_2fa_login"
PENDING_2FA_SETUP_SECRET_KEY = "pending_2fa_setup_secret"
PENDING_2FA_TTL_SECONDS = 600
PASSWORD_CHANGE_SESSION_KEY = 'password_change_required'

_login_attempts_ip = {}
_login_attempts_email = {}
_login_blocks_ip = {}
_login_blocks_email = {}
_forgot_attempts_ip = {}
_forgot_blocks_ip = {}
_redis_client = None

try:
    _redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    _redis_client.ping()
except Exception:
    _redis_client = None


def _get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


def _normalize_email(email: str | None) -> str:
    return (email or "").strip().lower()


def _prune_attempts(attempts, now, window_seconds):
    return [ts for ts in attempts if (now - ts).total_seconds() < window_seconds]


def _redis_get_int(key: str) -> int:
    if not _redis_client:
        return 0
    try:
        value = _redis_client.get(key)
        return int(value) if value else 0
    except Exception:
        return 0


def _login_ip_attempt_key(client_ip: str) -> str:
    return f"auth:login:attempts:ip:{client_ip}"


def _login_email_attempt_key(email: str) -> str:
    return f"auth:login:attempts:email:{email}"


def _login_ip_block_key(client_ip: str) -> str:
    return f"auth:login:block:ip:{client_ip}"


def _login_email_block_key(email: str) -> str:
    return f"auth:login:block:email:{email}"


def _forgot_ip_attempt_key(client_ip: str) -> str:
    return f"auth:forgot:attempts:ip:{client_ip}"


def _forgot_ip_block_key(client_ip: str) -> str:
    return f"auth:forgot:block:ip:{client_ip}"


def _is_login_blocked(client_ip: str, email: str, now: datetime) -> tuple[bool, int]:
    if _redis_client:
        ip_ttl = _redis_client.ttl(_login_ip_block_key(client_ip))
        email_ttl = _redis_client.ttl(_login_email_block_key(email)) if email else -2
        ttl = max(ip_ttl if ip_ttl > 0 else 0, email_ttl if email_ttl > 0 else 0)
        return ttl > 0, ttl
    ip_until = _login_blocks_ip.get(client_ip)
    if ip_until and ip_until > now:
        return True, int((ip_until - now).total_seconds())
    email_until = _login_blocks_email.get(email) if email else None
    if email_until and email_until > now:
        return True, int((email_until - now).total_seconds())
    return False, 0


def _record_failed_login_attempt(client_ip: str, email: str, now: datetime):
    if _redis_client:
        ip_key = _login_ip_attempt_key(client_ip)
        ip_count = _redis_client.incr(ip_key)
        if ip_count == 1:
            _redis_client.expire(ip_key, LOGIN_WINDOW_SECONDS)
        if ip_count >= MAX_LOGIN_ATTEMPTS_PER_IP:
            _redis_client.setex(_login_ip_block_key(client_ip), LOGIN_LOCKOUT_SECONDS, "1")

        if email:
            email_key = _login_email_attempt_key(email)
            email_count = _redis_client.incr(email_key)
            if email_count == 1:
                _redis_client.expire(email_key, LOGIN_WINDOW_SECONDS)
            if email_count >= MAX_LOGIN_ATTEMPTS_PER_EMAIL:
                _redis_client.setex(_login_email_block_key(email), LOGIN_LOCKOUT_SECONDS, "1")
        return

    ip_attempts = _login_attempts_ip.get(client_ip, [])
    ip_attempts = _prune_attempts(ip_attempts, now, LOGIN_WINDOW_SECONDS)
    ip_attempts.append(now)
    _login_attempts_ip[client_ip] = ip_attempts
    if len(ip_attempts) >= MAX_LOGIN_ATTEMPTS_PER_IP:
        _login_blocks_ip[client_ip] = now + timedelta(seconds=LOGIN_LOCKOUT_SECONDS)

    if email:
        email_attempts = _login_attempts_email.get(email, [])
        email_attempts = _prune_attempts(email_attempts, now, LOGIN_WINDOW_SECONDS)
        email_attempts.append(now)
        _login_attempts_email[email] = email_attempts
        if len(email_attempts) >= MAX_LOGIN_ATTEMPTS_PER_EMAIL:
            _login_blocks_email[email] = now + timedelta(seconds=LOGIN_LOCKOUT_SECONDS)


def _clear_login_attempts(client_ip: str, email: str):
    if _redis_client:
        keys = [_login_ip_attempt_key(client_ip), _login_ip_block_key(client_ip)]
        if email:
            keys.extend([_login_email_attempt_key(email), _login_email_block_key(email)])
        _redis_client.delete(*keys)
        return
    _login_attempts_ip.pop(client_ip, None)
    _login_blocks_ip.pop(client_ip, None)
    if email:
        _login_attempts_email.pop(email, None)
        _login_blocks_email.pop(email, None)


def _consume_forgot_password_attempt(client_ip: str, now: datetime) -> tuple[bool, int]:
    if _redis_client:
        block_ttl = _redis_client.ttl(_forgot_ip_block_key(client_ip))
        if block_ttl > 0:
            return False, int(block_ttl)
        key = _forgot_ip_attempt_key(client_ip)
        count = _redis_client.incr(key)
        if count == 1:
            _redis_client.expire(key, FORGOT_PASSWORD_WINDOW_SECONDS)
        if count > MAX_FORGOT_PASSWORD_PER_IP:
            _redis_client.setex(_forgot_ip_block_key(client_ip), FORGOT_PASSWORD_LOCKOUT_SECONDS, "1")
            return False, FORGOT_PASSWORD_LOCKOUT_SECONDS
        return True, 0

    until = _forgot_blocks_ip.get(client_ip)
    if until and until > now:
        return False, int((until - now).total_seconds())
    attempts = _forgot_attempts_ip.get(client_ip, [])
    attempts = _prune_attempts(attempts, now, FORGOT_PASSWORD_WINDOW_SECONDS)
    attempts.append(now)
    _forgot_attempts_ip[client_ip] = attempts
    if len(attempts) > MAX_FORGOT_PASSWORD_PER_IP:
        _forgot_blocks_ip[client_ip] = now + timedelta(seconds=FORGOT_PASSWORD_LOCKOUT_SECONDS)
        return False, FORGOT_PASSWORD_LOCKOUT_SECONDS
    return True, 0


def _get_serializer():
    return URLSafeTimedSerializer(settings.SECRET_KEY)


def _send_reset_email(to_email: str, reset_url: str):
    if not settings.SMTP_USERNAME or not settings.SMTP_PASSWORD:
        logging.getLogger(__name__).info("reset link: %s", reset_url)
        return

    msg = EmailMessage()
    msg["Subject"] = "Reset de senha - Backup Center"
    msg["From"] = settings.MAIL_FROM
    msg["To"] = to_email
    msg.set_content(
        "Acesse o link para redefinir sua senha:\n\n"
        f"{reset_url}\n\n"
        "Se voce nao solicitou, ignore este email."
    )

    with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as smtp:
        smtp.starttls()
        smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        smtp.send_message(msg)


def _is_role_2fa_required(role) -> bool:
    try:
        _parsed_role = role if isinstance(role, UserRole) else UserRole(role)
    except Exception:
        return False
    if _parsed_role is None:
        return False
    # Super admin nao exige 2FA obrigatorio (pode configurar voluntariamente)
    if _parsed_role == UserRole.SUPER_ADMIN:
        return False
    return True


def _build_totp_uri(email: str, secret: str) -> str:
    issuer = "Backup Center"
    label = quote(f"{issuer}:{email}")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        "&algorithm=SHA1&digits=6&period=30"
    )


def _clear_pending_2fa_session():
    session.pop(PENDING_2FA_SESSION_KEY, None)
    session.pop(PENDING_2FA_SETUP_SECRET_KEY, None)


def _store_password_change_requirement(user):
    session[PASSWORD_CHANGE_SESSION_KEY] = {
        'user_id': str(user.id),
        'email': _normalize_email(user.email),
        'issued_at': int(datetime.utcnow().timestamp()),
    }


def _clear_password_change_requirement():
    session.pop(PASSWORD_CHANGE_SESSION_KEY, None)


def _is_password_change_required(user) -> bool:
    return bool(getattr(user, 'must_change_password', False))


def _redirect_after_auth_success(user):
    if _is_password_change_required(user):
        _store_password_change_requirement(user)
        flash('Defina uma nova senha para concluir o primeiro acesso.', 'warning')
        return redirect(url_for('auth.force_password_change'))
    return _redirect_after_login(user)


def _store_pending_2fa_login(user, client_ip: str):
    session[PENDING_2FA_SESSION_KEY] = {
        "user_id": str(user.id),
        "email": _normalize_email(user.email),
        "ip": client_ip,
        "issued_at": int(datetime.utcnow().timestamp()),
    }


def _load_pending_2fa_user(db, client_ip: str):
    pending = session.get(PENDING_2FA_SESSION_KEY)
    if not isinstance(pending, dict):
        return None

    issued_at = int(pending.get("issued_at") or 0)
    if not issued_at or int(datetime.utcnow().timestamp()) - issued_at > PENDING_2FA_TTL_SECONDS:
        _clear_pending_2fa_session()
        return None

    stored_ip = (pending.get("ip") or "").strip()
    if stored_ip and stored_ip != client_ip:
        logging.getLogger(__name__).warning(
            "2fa pending session ip mismatch expected=%s got=%s", stored_ip, client_ip
        )
        _clear_pending_2fa_session()
        return None

    try:
        user_uuid = uuid.UUID(str(pending.get("user_id") or ""))
    except (TypeError, ValueError):
        _clear_pending_2fa_session()
        return None

    from app.models.user import User

    user = db.query(User).filter(User.id == user_uuid, User.is_active.is_(True)).first()
    if not user:
        _clear_pending_2fa_session()
        return None

    if _normalize_email(user.email) != _normalize_email(pending.get("email")):
        _clear_pending_2fa_session()
        return None

    return user


def _finalize_authenticated_session(db, user, client_ip: str):
    _clear_pending_2fa_session()
    session.permanent = True
    session["user_id"] = str(user.id)
    session["user_name"] = user.full_name
    session["user_role"] = user.role.value
    session["tenant_slug"] = user.tenant.slug if user.tenant else "admin"

    from app.services.activity_service import ActivityService

    tenant_id = user.tenant_id if user.tenant else None
    ActivityService.log_action(
        db,
        tenant_id,
        user.id,
        "LOGIN",
        f"User logged in from IP {client_ip}",
        client_ip,
    )


def _redirect_after_login(user):
    if user.role == UserRole.SUPER_ADMIN:
        logging.getLogger(__name__).info("superadmin login")
        return redirect(url_for("superadmin_dashboard.dashboard"))
    if user.tenant:
        logging.getLogger(__name__).info("tenant login: %s", user.tenant.slug)
        return redirect(url_for("tenant.dashboard", tenant_slug=user.tenant.slug))
    logging.getLogger(__name__).warning("user without tenant")
    flash("Sua conta nao possui uma empresa associada.", "error")
    return redirect(url_for("auth.login"))

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        normalized_email = _normalize_email(email)
        password = request.form.get('password')
        now = datetime.utcnow()
        client_ip = _get_client_ip()
        blocked, retry_after = _is_login_blocked(client_ip, normalized_email, now)
        if blocked:
            logging.getLogger(__name__).warning(
                "auth login blocked ip=%s email=%s retry_after=%ss",
                client_ip,
                normalized_email or "empty",
                retry_after,
            )
            flash('Muitas tentativas. Tente novamente em alguns minutos.', 'error')
            return render_template('auth/login.html')
        
        db = SessionLocal()
        try:
            user = AuthService.authenticate_user(db, email, password)
            if user:
                if user.role != UserRole.SUPER_ADMIN and user.tenant and not user.tenant.is_active:
                    if getattr(user.tenant, "deleted_at", None):
                        flash('Este cliente foi movido para a lixeira e nao esta disponivel.', 'error')
                    elif getattr(user.tenant, "billing_blocked_at", None):
                        flash('Cliente bloqueado por inadimplencia. Entre em contato com o suporte para reativacao.', 'error')
                    else:
                        flash('Este cliente esta desativado. Entre em contato com o suporte.', 'error')
                    return render_template('auth/login.html')

                logging.getLogger(__name__).info("user authenticated: %s", user.email)
                _clear_login_attempts(client_ip, normalized_email)

                if _is_role_2fa_required(user.role):
                    _store_pending_2fa_login(user, client_ip)
                    if getattr(user, "totp_secret", None):
                        flash('Digite o codigo de autenticacao para concluir o login.', 'info')
                        return redirect(url_for('auth.two_factor_verify'))
                    session[PENDING_2FA_SETUP_SECRET_KEY] = generate_totp_secret()
                    logging.getLogger(__name__).warning(
                        "account without 2fa user=%s role=%s ip=%s",
                        user.email,
                        user.role.value,
                        client_ip,
                    )
                    flash('Configure o 2FA para concluir o acesso.', 'warning')
                    return redirect(url_for('auth.two_factor_setup'))

                _finalize_authenticated_session(db, user, client_ip)
                flash('Login realizado com sucesso!', 'success')
                return _redirect_after_auth_success(user)
            else:
                logging.getLogger(__name__).warning("authentication failed")
                flash('Email ou senha invalidos.', 'error')
                _record_failed_login_attempt(client_ip, normalized_email, now)
                now_blocked, now_retry_after = _is_login_blocked(client_ip, normalized_email, now)
                if now_blocked:
                    logging.getLogger(__name__).warning(
                        "auth lockout triggered ip=%s email=%s retry_after=%ss",
                        client_ip,
                        normalized_email or "empty",
                        now_retry_after,
                    )
                from app.services.activity_service import ActivityService
                from app.models.user import User
                existing_user = db.query(User).filter(User.email == email).first()
                if existing_user:
                    ActivityService.log_action(db, existing_user.tenant_id, existing_user.id, 'LOGIN_FAILED', f'Failed login from IP {client_ip}', client_ip)
                # LOG ACTIVITY: Login Failed could be logged if we had the tenant/user context, 
                # but since auth failed, we might only log if we found the user by email but pass was wrong.
                # For now, let's skip anonymous failed login logging to avoid DB span without tenant context.
        except Exception as e:
            logging.getLogger(__name__).exception("error during login process")
            flash(f"Erro interno: {str(e)}", "error")
        finally:
            db.close()
            
    return render_template('auth/login.html')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    db = SessionLocal()
    plans = (
        db.query(Plan)
        .filter(Plan.is_active.is_(True))
        .order_by(Plan.price_monthly.asc(), Plan.created_at.asc())
        .all()
    )
    from app.web.billing.controller import BillingController
    from app.services.platform_settings_service import PlatformSettingsService

    payment_ready = BillingController.is_checkout_available()

    if request.method == 'POST':
        full_name = (request.form.get('full_name') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        company_name = (request.form.get('company_name') or '').strip()
        password = request.form.get('password')
        plan_id = (request.form.get('plan_id') or '').strip()
        billing_cycle = (request.form.get('billing_cycle') or 'monthly').strip().lower()
        try:
            password_error = validate_password_strength(password)
            if password_error:
                flash(password_error, 'error')
                return render_template('auth/register.html', plans=plans, payment_ready=payment_ready)
            from app.models.user import User
            if not plan_id:
                flash('Selecione um plano para continuar.', 'error')
                return render_template('auth/register.html', plans=plans, payment_ready=payment_ready)
            if db.query(User).filter(User.email == email).first():
                flash('Este email ja esta cadastrado.', 'error')
                return render_template('auth/register.html', plans=plans, payment_ready=payment_ready)

            user = AuthService.register_tenant(
                db,
                email=email,
                password=password,
                full_name=full_name,
                company_name=company_name,
                plan_id=plan_id,
                activate_trial=not payment_ready,
                require_password_change=False,
            )

            from app.services.activity_service import ActivityService
            ActivityService.log_action(
                db,
                user.tenant.id,
                user.id,
                "REGISTER",
                f"Tenant registered: {company_name}",
                request.remote_addr,
            )

            if payment_ready:
                base_url = (PlatformSettingsService.get_payment_config().get("app_public_url") or request.url_root).rstrip("/")
                checkout = BillingController.create_checkout_for_plan(
                    tenant_id=user.tenant.id,
                    tenant_slug=user.tenant.slug,
                    plan_id=plan_id,
                    payer_email=email,
                    base_url=base_url,
                    billing_cycle=billing_cycle,
                )
                flash('Conta criada! Agora finalize o pagamento para liberar seu plano.', 'success')
                return redirect(checkout["checkout_url"])

            flash('Conta criada com sucesso! Faca login para comecar.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.rollback()
            flash(f'Erro ao criar conta: {str(e)}', 'error')
            return render_template('auth/register.html', plans=plans, payment_ready=payment_ready)
        finally:
            db.close()

    db.close()
    return render_template('auth/register.html', plans=plans, payment_ready=payment_ready)


@bp.route('/2fa/setup', methods=['GET', 'POST'])
def two_factor_setup():
    client_ip = _get_client_ip()
    db = SessionLocal()
    try:
        user = _load_pending_2fa_user(db, client_ip)
        if not user:
            flash('Sessao de autenticacao expirada. Faca login novamente.', 'error')
            return redirect(url_for('auth.login'))

        if not _is_role_2fa_required(user.role):
            _finalize_authenticated_session(db, user, client_ip)
            flash('Login realizado com sucesso!', 'success')
            return _redirect_after_login(user)

        if user.role != UserRole.SUPER_ADMIN and user.tenant and not user.tenant.is_active:
            _clear_pending_2fa_session()
            if getattr(user.tenant, "deleted_at", None):
                flash('Este cliente foi movido para a lixeira e nao esta disponivel.', 'error')
            elif getattr(user.tenant, "billing_blocked_at", None):
                flash('Cliente bloqueado por inadimplencia. Entre em contato com o suporte para reativacao.', 'error')
            else:
                flash('Este cliente esta desativado. Entre em contato com o suporte.', 'error')
            return redirect(url_for('auth.login'))

        if getattr(user, "totp_secret", None):
            return redirect(url_for('auth.two_factor_verify'))

        setup_secret = session.get(PENDING_2FA_SETUP_SECRET_KEY)
        if not setup_secret:
            setup_secret = generate_totp_secret()
            session[PENDING_2FA_SETUP_SECRET_KEY] = setup_secret

        if request.method == 'POST':
            code = request.form.get('code')
            if verify_totp(setup_secret, code):
                user.totp_secret = setup_secret
                db.commit()
                _clear_login_attempts(client_ip, _normalize_email(user.email))
                _finalize_authenticated_session(db, user, client_ip)
                flash('2FA configurado e login concluido com sucesso!', 'success')
                return _redirect_after_auth_success(user)

            _record_failed_login_attempt(client_ip, _normalize_email(user.email), datetime.utcnow())
            blocked, _ = _is_login_blocked(client_ip, _normalize_email(user.email), datetime.utcnow())
            if blocked:
                _clear_pending_2fa_session()
                flash('Muitas tentativas. Faca login novamente em alguns minutos.', 'error')
                return redirect(url_for('auth.login'))
            flash('Codigo invalido. Confira o app autenticador e tente novamente.', 'error')

        return render_template(
            'auth/two_factor_setup.html',
            email=user.email,
            secret=setup_secret,
            otp_uri=_build_totp_uri(user.email, setup_secret),
        )
    except Exception:
        db.rollback()
        logging.getLogger(__name__).exception("error during 2fa setup")
        flash('Erro ao configurar 2FA. Tente novamente.', 'error')
        return redirect(url_for('auth.login'))
    finally:
        db.close()


@bp.route('/2fa/verify', methods=['GET', 'POST'])
def two_factor_verify():
    client_ip = _get_client_ip()
    db = SessionLocal()
    try:
        user = _load_pending_2fa_user(db, client_ip)
        if not user:
            flash('Sessao de autenticacao expirada. Faca login novamente.', 'error')
            return redirect(url_for('auth.login'))

        if not _is_role_2fa_required(user.role):
            _finalize_authenticated_session(db, user, client_ip)
            flash('Login realizado com sucesso!', 'success')
            return _redirect_after_login(user)

        if user.role != UserRole.SUPER_ADMIN and user.tenant and not user.tenant.is_active:
            _clear_pending_2fa_session()
            if getattr(user.tenant, "deleted_at", None):
                flash('Este cliente foi movido para a lixeira e nao esta disponivel.', 'error')
            elif getattr(user.tenant, "billing_blocked_at", None):
                flash('Cliente bloqueado por inadimplencia. Entre em contato com o suporte para reativacao.', 'error')
            else:
                flash('Este cliente esta desativado. Entre em contato com o suporte.', 'error')
            return redirect(url_for('auth.login'))

        if not getattr(user, "totp_secret", None):
            return redirect(url_for('auth.two_factor_setup'))

        if request.method == 'POST':
            code = request.form.get('code')
            if verify_totp(user.totp_secret, code):
                _clear_login_attempts(client_ip, _normalize_email(user.email))
                _finalize_authenticated_session(db, user, client_ip)
                flash('Login realizado com sucesso!', 'success')
                return _redirect_after_auth_success(user)

            _record_failed_login_attempt(client_ip, _normalize_email(user.email), datetime.utcnow())
            blocked, _ = _is_login_blocked(client_ip, _normalize_email(user.email), datetime.utcnow())
            if blocked:
                _clear_pending_2fa_session()
                flash('Muitas tentativas. Faca login novamente em alguns minutos.', 'error')
                return redirect(url_for('auth.login'))
            flash('Codigo 2FA invalido.', 'error')

        return render_template('auth/two_factor_verify.html', email=user.email)
    except Exception:
        logging.getLogger(__name__).exception("error during 2fa verify")
        flash('Erro ao validar 2FA. Faca login novamente.', 'error')
        return redirect(url_for('auth.login'))
    finally:
        db.close()


@bp.route('/2fa/cancel', methods=['POST'])
def two_factor_cancel():
    _clear_pending_2fa_session()
    flash('Autenticacao cancelada. Faca login novamente.', 'info')
    return redirect(url_for('auth.login'))


@bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Voce saiu da sua conta.', 'info')
    return redirect(url_for('auth.login'))


@bp.route('/force-password-change', methods=['GET', 'POST'])
def force_password_change():
    user_id = session.get('user_id')
    if not user_id:
        flash('Faca login novamente para continuar.', 'error')
        return redirect(url_for('auth.login'))

    db = SessionLocal()
    try:
        from app.models.user import User
        try:
            user_uuid = uuid.UUID(str(user_id))
        except Exception:
            session.clear()
            flash('Sessao invalida. Faca login novamente.', 'error')
            return redirect(url_for('auth.login'))

        user = db.query(User).filter(User.id == user_uuid, User.is_active.is_(True)).first()
        if not user:
            session.clear()
            flash('Usuario nao encontrado. Faca login novamente.', 'error')
            return redirect(url_for('auth.login'))
        if not getattr(user, 'must_change_password', False):
            _clear_password_change_requirement()
            return _redirect_after_login(user)

        if request.method == 'POST':
            password = request.form.get('password')
            confirm = request.form.get('confirm_password')
            if not password or password != confirm:
                flash('As senhas nao conferem.', 'error')
                return render_template('auth/force_password_change.html', email=user.email)
            password_error = validate_password_strength(password)
            if password_error:
                flash(password_error, 'error')
                return render_template('auth/force_password_change.html', email=user.email)

            user.password_hash = AuthService.get_password_hash(password)
            user.must_change_password = False
            user.password_changed_at = datetime.utcnow()
            db.commit()
            _clear_password_change_requirement()
            flash('Senha atualizada com sucesso.', 'success')
            return _redirect_after_login(user)

        return render_template('auth/force_password_change.html', email=user.email)
    finally:
        db.close()

@bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        now = datetime.utcnow()
        client_ip = _get_client_ip()
        allowed, retry_after = _consume_forgot_password_attempt(client_ip, now)
        if not allowed:
            logging.getLogger(__name__).warning(
                "forgot-password rate limited ip=%s retry_after=%ss",
                client_ip,
                retry_after,
            )
            flash('Muitas solicitacoes. Tente novamente em alguns minutos.', 'error')
            return redirect(url_for('auth.forgot_password'))

        email = (request.form.get('email') or "").strip()
        email_lookup = email.lower()
        
        db = SessionLocal()
        try:
            # Check if user exists
            from app.models.user import User
            user = None
            if email:
                user = db.query(User).filter(func.lower(User.email) == email_lookup).first()
            
            if user:
                logging.getLogger(__name__).info("password reset requested for %s", email)
                serializer = _get_serializer()
                token = serializer.dumps({"user_id": str(user.id), "email": user.email})
                reset_url = url_for('auth.reset_password', token=token, _external=True)
                _send_reset_email(user.email, reset_url)

            flash('Se o email estiver cadastrado, voce recebera instrucoes de recuperacao.', 'info')
            return redirect(url_for('auth.login'))
        except Exception:
            logging.getLogger(__name__).exception("error requesting password reset")
            flash('Erro ao processar solicitacao de reset.', 'error')
        finally:
            db.close()
            
    return render_template('auth/forgot_password.html')


@bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    serializer = _get_serializer()
    try:
        data = serializer.loads(token, max_age=3600)
    except SignatureExpired:
        flash('Token expirado. Solicite um novo reset.', 'error')
        return redirect(url_for('auth.forgot_password'))
    except BadSignature:
        flash('Token invalido.', 'error')
        return redirect(url_for('auth.forgot_password'))

    db = SessionLocal()
    try:
        from app.models.user import User
        try:
            user_uuid = uuid.UUID(data.get("user_id"))
        except (TypeError, ValueError):
            flash('Token invalido.', 'error')
            return redirect(url_for('auth.forgot_password'))

        user = db.query(User).filter(User.id == user_uuid, User.email == data.get("email")).first()
        if not user:
            flash('Usuario nao encontrado.', 'error')
            return redirect(url_for('auth.forgot_password'))

        if request.method == 'POST':
            password = request.form.get('password')
            confirm = request.form.get('confirm_password')
            if not password or password != confirm:
                flash('As senhas nao conferem.', 'error')
                return render_template('auth/reset_password.html', token=token)
            password_error = validate_password_strength(password)
            if password_error:
                flash(password_error, 'error')
                return render_template('auth/reset_password.html', token=token)

            user.password_hash = AuthService.get_password_hash(password)
            user.must_change_password = False
            user.password_changed_at = datetime.utcnow()
            db.commit()
            flash('Senha atualizada com sucesso.', 'success')
            return redirect(url_for('auth.login'))
    finally:
        db.close()

    return render_template('auth/reset_password.html', token=token)


