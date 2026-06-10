from flask import Flask, session, request, abort, jsonify, flash, redirect, url_for, g, render_template
from datetime import timedelta, datetime
from fastapi import FastAPI, Request, HTTPException
from starlette.responses import Response
from zoneinfo import ZoneInfo
from fastapi.middleware.wsgi import WSGIMiddleware
from app.core.config import settings, validate_settings
from app.core.logging_config import setup_logging
import logging
from app.core.database import SessionLocal
from app.models.notification import Notification
from app.models.tenant import Tenant
from app.models.user import User
import uuid
import secrets
from sqlalchemy import text
from redis import Redis
from werkzeug.exceptions import HTTPException
from urllib.parse import urlsplit, urlunsplit
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import SQLAlchemyError

def create_flask_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = settings.SECRET_KEY
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = settings.SESSION_COOKIE_SAMESITE
    app.config['SESSION_COOKIE_SECURE'] = settings.SESSION_COOKIE_SECURE
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=settings.SESSION_MAX_AGE_MINUTES)
    setup_logging()
    validate_settings()
    from app.services.platform_settings_service import PlatformSettingsService
    from app.services.tenant_access_service import TenantAccessService
    from app.services.billing_policy_service import BillingPolicyService
    from app.services.plan_limits_service import PlanLimitsService
    from app.services.auth_service import AuthService
    from app.services.device_subgroup_service import DeviceSubgroupService
    PlatformSettingsService.ensure_schema()
    TenantAccessService.apply_builtin_overrides()
    BillingPolicyService.ensure_schema()
    PlanLimitsService.ensure_schema()
    DeviceSubgroupService.ensure_schema()
    _schema_db = SessionLocal()
    try:
        AuthService.ensure_schema(_schema_db)
    finally:
        _schema_db.close()

    def _generate_csrf_token():
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    def _sanitize_admin_return_target(raw_value: str | None) -> str | None:
        value = (raw_value or "").strip()
        if not value:
            return None
        parsed = urlsplit(value)
        if parsed.scheme or parsed.netloc:
            return None
        if not parsed.path.startswith("/admin/"):
            return None
        return urlunsplit(("", "", parsed.path, parsed.query, ""))

    @app.before_request
    def _attach_request_id():
        header_rid = (request.headers.get("X-Request-ID") or "").strip()
        g.request_id = header_rid or str(uuid.uuid4())

    @app.before_request
    def _csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if request.path.startswith("/webhooks/billing/mercadopago"):
                return
            session_token = session.get("_csrf_token")
            request_token = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token")
            if not session_token or not request_token or session_token != request_token:
                abort(400)

    @app.before_request
    def _track_superadmin_tenant_origin():
        if session.get("user_role") != "super_admin":
            session.pop("superadmin_return_url", None)
            session.pop("superadmin_return_label", None)
            session.pop("superadmin_return_tenant_slug", None)
            return

        if not request.path.startswith("/tenant/"):
            return

        admin_return = _sanitize_admin_return_target(request.args.get("admin_return"))
        if not admin_return:
            return

        session["superadmin_return_url"] = admin_return
        session["superadmin_return_label"] = (
            (request.args.get("admin_return_label") or "").strip()[:80] or "Voltar ao Cliente 360"
        )
        current_tenant_slug = (request.view_args or {}).get("tenant_slug")
        if current_tenant_slug:
            session["superadmin_return_tenant_slug"] = current_tenant_slug

    @app.before_request
    def _guard_force_password_change():
        if request.path.startswith('/static/') or request.path.startswith('/healthz'):
            return
        if request.path.startswith('/auth/logout') or request.path.startswith('/auth/forgot-password') or request.path.startswith('/auth/reset-password/'):
            return
        if request.path.startswith('/auth/force-password-change'):
            return
        user_id = session.get('user_id')
        if not user_id:
            return
        db = SessionLocal()
        try:
            try:
                user_uuid = uuid.UUID(str(user_id))
            except Exception:
                session.clear()
                return redirect(url_for('auth.login'))
            user = db.query(User).filter(User.id == user_uuid, User.is_active.is_(True)).first()
            if user and getattr(user, 'must_change_password', False):
                return redirect(url_for('auth.force_password_change'))
        finally:
            db.close()

    @app.before_request
    def _guard_inactive_tenant_access():
        if session.get("user_role") == "super_admin":
            return
        if not request.path.startswith("/tenant/"):
            return

        tenant_slug = (request.view_args or {}).get("tenant_slug")
        if not tenant_slug:
            return

        db = SessionLocal()
        try:
            tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
            if tenant and not tenant.is_active:
                session.clear()
                if getattr(tenant, "deleted_at", None):
                    flash("Este cliente foi movido para a lixeira e não está disponível.", "error")
                elif getattr(tenant, "billing_blocked_at", None):
                    flash("Cliente bloqueado por inadimplencia. Entre em contato com o suporte para reativacao.", "error")
                else:
                    flash("Este cliente esta desativado. Entre em contato com o suporte.", "error")
                return redirect(url_for("auth.login"))
        finally:
            db.close()

    @app.before_request
    def _enforce_https():
        if settings.APP_ENV.lower() == "development":
            return
        host = (request.host or "").split(":")[0]
        proto = request.headers.get("X-Forwarded-Proto", "http").lower()
        is_secure = request.is_secure or proto == "https"
        if is_secure:
            return
        # Allow local/direct access without redirect for troubleshooting/operations.
        if host in {"127.0.0.1", "localhost", "168.194.14.85"}:
            return
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)

    @app.after_request
    def _audit_user_requests(resp):
        # Mantemos apenas logs de eventos de negocio registrados explicitamente
        # pelas rotas/servicos do Backup Center.
        return resp

    @app.after_request
    def _set_security_headers(resp):
        resp.headers.setdefault("X-Request-ID", getattr(g, "request_id", ""))
        proto = request.headers.get("X-Forwarded-Proto", "http").lower()
        is_secure = request.is_secure or proto == "https"
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com https://cdn.jsdelivr.net/npm; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://unpkg.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "connect-src 'self' wss: ws: https://cdn.jsdelivr.net https://unpkg.com; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "base-uri 'self'"
        )
        resp.headers.setdefault("Content-Security-Policy", csp)
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if is_secure:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        return resp

    app.jinja_env.globals["csrf_token"] = _generate_csrf_token

    app_tz = ZoneInfo(settings.APP_TIMEZONE)

    def _localtime(value):
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=ZoneInfo("UTC"))
            return value.astimezone(app_tz)
        return value

    def _format_datetime(value, fmt="%d/%m/%Y %H:%M", default="-"):
        dt = _localtime(value)
        if isinstance(dt, datetime):
            return dt.strftime(fmt)
        return default

    app.jinja_env.filters["localtime"] = _localtime
    app.jinja_env.globals["localtime"] = _localtime
    app.jinja_env.filters["format_datetime"] = _format_datetime
    app.jinja_env.globals["format_datetime"] = _format_datetime

    @app.context_processor
    def inject_notifications():
        user_id = session.get('user_id')
        if not user_id:
            return {}
        try:
            user_uuid = uuid.UUID(user_id)
        except ValueError:
            return {}
        db = SessionLocal()
        try:
            notifications = db.query(Notification).filter(
                Notification.user_id == user_uuid
            ).order_by(Notification.created_at.desc()).limit(5).all()
            unread_count = db.query(Notification).filter(
                Notification.user_id == user_uuid,
                Notification.is_read == False
            ).count()
            return {
                "notifications_list": notifications,
                "notifications_count": unread_count,
            }
        finally:
            db.close()

    @app.context_processor
    def inject_superadmin_tenant_return():
        if session.get("user_role") != "super_admin":
            return {}

        current_tenant_slug = (request.view_args or {}).get("tenant_slug")
        return_url = session.get("superadmin_return_url")
        return_label = session.get("superadmin_return_label") or "Voltar ao Cliente 360"
        return_tenant_slug = session.get("superadmin_return_tenant_slug")
        is_tenant_area = request.path.startswith("/tenant/")
        is_active = bool(
            is_tenant_area
            and return_url
            and current_tenant_slug
            and (not return_tenant_slug or return_tenant_slug == current_tenant_slug)
        )

        return {
            "superadmin_return_url": return_url if is_active else None,
            "superadmin_return_label": return_label,
            "is_superadmin_tenant_view": is_active,
        }

    @app.context_processor
    def inject_tenant_billing_alert():
        if session.get("user_role") == "super_admin":
            return {}
        tenant_slug = (session.get("tenant_slug") or "").strip()
        if not tenant_slug or tenant_slug == "admin":
            return {}

        db = SessionLocal()
        try:
            tenant = (
                db.query(Tenant)
                .options(joinedload(Tenant.plan))
                .filter(Tenant.slug == tenant_slug)
                .first()
            )
            if not tenant or not tenant.is_active:
                return {}

            from app.services.billing_policy_service import BillingPolicyService

            alert = BillingPolicyService.build_runtime_alert(tenant)
            if not alert:
                return {}
            return {
                "tenant_billing_alert": alert,
                "tenant_billing_url": url_for("billing.dashboard", tenant_slug=tenant_slug),
            }
        except SQLAlchemyError as exc:
            db.rollback()
            app.logger.warning(
                "Ignorando alerta de billing por falha temporaria no banco: %s",
                exc.__class__.__name__,
            )
            return {}
        finally:
            db.close()
    
    logger = logging.getLogger(__name__)

    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        # Renderiza as paginas de erro do redesign (Quiet Operations) em vez da
        # pagina padrao do Werkzeug. Mantem APIs/JSON intactas e cai no padrao
        # caso o template falhe por qualquer motivo.
        code = e.code or 500
        if request.path.startswith("/api") or request.path.startswith("/upload"):
            return e
        try:
            if code == 404:
                return render_template("errors/404.html"), 404
            if code >= 500:
                return render_template("errors/500.html"), code
        except Exception:
            logger.exception("falha ao renderizar pagina de erro")
        return e

    @app.errorhandler(Exception)
    def handle_exception(e):
        logger.exception("flask error")
        try:
            return render_template("errors/500.html"), 500
        except Exception:
            return "Internal Server Error", 500

    @app.get("/healthz")
    def healthz():
        return jsonify({"status": "ok"}), 200

    @app.get("/readyz")
    def readyz():
        db_ok = False
        redis_ok = False

        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            logger.exception("readyz db check failed")
        finally:
            db.close()

        try:
            redis_ok = bool(Redis.from_url(settings.REDIS_URL, socket_connect_timeout=1, socket_timeout=1).ping())
        except Exception:
            logger.exception("readyz redis check failed")

        status_code = 200 if db_ok and redis_ok else 503
        return jsonify({
            "status": "ready" if status_code == 200 else "degraded",
            "checks": {
                "database": db_ok,
                "redis": redis_ok,
            }
        }), status_code

    @app.get("/internal/metrics/backups")
    def backup_metrics():
        from app.services.backup_observability import (
            metrics_token_is_valid,
            render_prometheus_metrics,
        )

        auth_header = request.headers.get("Authorization")
        if not metrics_token_is_valid(auth_header):
            return "forbidden\n", 403

        payload = render_prometheus_metrics()
        return payload, 200, {"Content-Type": "text/plain; version=0.0.4; charset=utf-8"}
    
    # Register Blueprints
    from app.web.superadmin.dashboard import bp as superadmin_dashboard_bp
    app.register_blueprint(superadmin_dashboard_bp)

    from app.web.public.routes import bp as public_bp
    app.register_blueprint(public_bp)
    
    from app.web.auth.routes import bp as auth_bp
    app.register_blueprint(auth_bp)
    
    from app.web.tenant.dashboard import bp as tenant_bp
    app.register_blueprint(tenant_bp)
    
    from app.web.tenant.devices import bp as devices_bp
    app.register_blueprint(devices_bp)
    
    from app.web.tenant.groups import bp as groups_bp
    app.register_blueprint(groups_bp)
    
    from app.web.tenant.users import bp as users_bp
    app.register_blueprint(users_bp)

    from app.web.tenant.settings import bp as tenant_settings_bp
    app.register_blueprint(tenant_settings_bp)

    from app.web.tenant.backups import bp as tenant_backups_bp
    app.register_blueprint(tenant_backups_bp)

    from app.web.tenant.compare import bp as tenant_compare_bp
    app.register_blueprint(tenant_compare_bp)



    from app.web.tenant.activity import bp as tenant_activity_bp
    app.register_blueprint(tenant_activity_bp)

    from app.web.tenant.schedules import bp as tenant_schedules_bp
    app.register_blueprint(tenant_schedules_bp)

    from app.web.tenant.operations import bp as tenant_operations_bp
    app.register_blueprint(tenant_operations_bp)

    from app.web.tenant.reports import bp as tenant_reports_bp
    app.register_blueprint(tenant_reports_bp)

    from app.web.billing.routes import bp as billing_bp
    app.register_blueprint(billing_bp)

    from app.web.billing.webhooks import bp as billing_webhooks_bp
    app.register_blueprint(billing_webhooks_bp)

    from app.web.superadmin.tenants import bp as superadmin_tenants_bp
    app.register_blueprint(superadmin_tenants_bp)

    from app.web.superadmin.device_types import bp as superadmin_device_types_bp
    app.register_blueprint(superadmin_device_types_bp)

    from app.web.superadmin.plans import bp as superadmin_plans_bp
    app.register_blueprint(superadmin_plans_bp)

    from app.web.superadmin.users import bp as superadmin_users_bp
    app.register_blueprint(superadmin_users_bp)

    from app.web.superadmin.billing import bp as superadmin_billing_bp
    app.register_blueprint(superadmin_billing_bp)

    from app.web.tenant.api_tokens import bp as api_tokens_bp
    app.register_blueprint(api_tokens_bp)
    return app


api_description = """
<div style="font-family: sans-serif;">
    <h2 style="color: #2563eb;">📚 Bem-vindo à Documentação Interativa da API (Backup Center)</h2>
    <p>Esta página serve para você <strong>entender e testar</strong> como integrar outra aplicação com o Backup Center.</p>
    
    <div style="background-color: #f3f4f6; padding: 15px; border-left: 4px solid #3b82f6; border-radius: 4px; margin-bottom: 20px;">
        <strong>🔑 Como Autenticar:</strong><br/>
        Clique no botão verde <b>"Authorize"</b> no canto superior direito.<br/>
        No campo <i>"Value"</i>, cole o Token da sua API (ex: <code>bc_ABC123...</code>) e clique em <i>Authorize</i>.<br/>
        <i>Nota: Não precisa escrever "Bearer ", o sistema já faz isso sozinho aqui nessa tela de teste.</i>
    </div>

    <h3>🚀 Fluxo de Trabalho Passo a Passo</h3>
    <ol style="line-height: 1.8;">
        <li><strong>Passo 1: Encontrar os Grupos</strong><br/> 
        Abra a rota <code style="background:#e5e7eb; padding:2px 6px; border-radius:4px;">GET /api/v1/external/groups</code>, clique em <i>"Try it out"</i> e em <i>"Execute"</i>. A resposta te dará o <b>id</b> do grupo.</li>
        
        <li><strong>Passo 2: Ver Backups de um Grupo</strong><br/> 
        Pegue o <b>id</b> do passo anterior. Abra <code style="background:#e5e7eb; padding:2px 6px; border-radius:4px;">GET /api/v1/external/groups/{group_id}/backups</code>, clique em <i>"Try it out"</i>, preencha o campo <code>group_id</code> e clique em <i>"Execute"</i>. Extraia o <b>id do backup</b> que deseja.</li>
        
        <li><strong>Passo 3: Download</strong><br/> 
        Abra <code style="background:#e5e7eb; padding:2px 6px; border-radius:4px;">GET /api/v1/external/backups/{backup_id}/download</code> e preencha com o ID do backup para baixar o arquivo.</li>
    </ol>
</div>
"""

def create_fastapi_app():
    app = FastAPI(
        title=f"{settings.APP_NAME} - API",
        version="1.0.0",
        docs_url=None,  # Desabilita o Swagger padrão
        redoc_url=None,  # Desabilita o ReDoc
        openapi_url=None  # Desabilita OpenAPI JSON
    )

    @app.middleware("http")
    async def add_security_headers(request, call_next):
        response = await call_next(request)
        proto = request.headers.get("x-forwarded-proto", "http").lower()
        is_secure = request.url.scheme == "https" or proto == "https"
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com https://cdn.jsdelivr.net/npm; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://unpkg.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "connect-src 'self' wss: ws: https://cdn.jsdelivr.net https://unpkg.com; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "base-uri 'self'"
        )
        headers = {
            "Content-Security-Policy": csp,
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        }
        if is_secure:
            headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        for k, v in headers.items():
            if k not in response.headers:
                response.headers[k] = v
        return response

    @app.get("/healthz")
    async def api_healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    async def api_readyz():
        db_ok = False
        redis_ok = False

        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            logging.getLogger(__name__).exception("readyz db check failed")
        finally:
            db.close()

        try:
            redis_ok = bool(Redis.from_url(settings.REDIS_URL, socket_connect_timeout=1, socket_timeout=1).ping())
        except Exception:
            logging.getLogger(__name__).exception("readyz redis check failed")

        return {
            "status": "ready" if db_ok and redis_ok else "degraded",
            "checks": {"database": db_ok, "redis": redis_ok},
        }

    @app.get("/favicon.ico")
    async def api_favicon():
        return {}, 204

    @app.api_route("/internal/olt-upload/{token}/{filename:path}", methods=["PUT", "POST"])
    async def olt_config_upload(token: str, filename: str, req: Request):
        from app.services.realtime_backup_logs import get_redis_client
        import json
        import os

        client = get_redis_client()
        if not client:
            raise HTTPException(status_code=503, detail="upload receiver unavailable")

        key = f"backup_center:olt_upload:{token}"
        raw_meta = client.get(key)
        if not raw_meta:
            raise HTTPException(status_code=404, detail="upload token not found")

        try:
            meta = json.loads(raw_meta)
        except Exception:
            client.delete(key)
            raise HTTPException(status_code=400, detail="invalid upload token")

        target_path = os.path.abspath(str(meta.get("path") or ""))
        storage_root = os.path.abspath(os.path.join(os.getcwd(), "storage", "backups"))
        if not target_path.startswith(storage_root + os.sep):
            client.delete(key)
            raise HTTPException(status_code=400, detail="invalid upload target")

        payload = await req.body()
        max_bytes = int(meta.get("max_bytes") or 20 * 1024 * 1024)
        if not payload:
            raise HTTPException(status_code=400, detail="empty upload")
        if len(payload) > max_bytes:
            raise HTTPException(status_code=413, detail="upload too large")

        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "wb") as fp:
            fp.write(payload)
        client.delete(key)
        return {"status": "ok", "filename": filename, "bytes": len(payload)}

    @app.get("/docs", include_in_schema=False, response_class=Response)
    @app.get("/api/docs", include_in_schema=False, response_class=Response)
    async def custom_api_documentation_route(req: Request):
        """Página de documentação customizada e amigável da API"""
        from fastapi.responses import HTMLResponse
        cache_headers = {
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        }
        try:
            from app.api.v1.external.documentation import API_DOCUMENTATION_HTML
            return HTMLResponse(
                content=API_DOCUMENTATION_HTML,
                status_code=200,
                headers=cache_headers,
            )
        except Exception as e:
            return HTMLResponse(
                content=f"<h1>ERROR loading docs</h1><p>{str(e)}</p>",
                status_code=500,
                headers=cache_headers,
            )

    # Include Routers
    from app.api.v1.auth import router as auth_v1_router
    app.include_router(auth_v1_router, prefix="/api/v1/auth", tags=["auth"])

    from app.api.v1.external.routes import router as external_router
    app.include_router(external_router, prefix="/api/v1/external", tags=["external"])

    return app


# The main app will be FastAPI, hosting Flask as a sub-application for SSR
def create_main_app():
    fastapi_app = create_fastapi_app()
    flask_app = create_flask_app()

    # Mount Flask to handle SSR pages ONLY
    # FastAPI routes like /docs, /api/* take priority and are matched first
    fastapi_app.mount("/", WSGIMiddleware(flask_app))

    return fastapi_app
