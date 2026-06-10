import re
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlsplit, urlunsplit

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from sqlalchemy import case, func, select
from sqlalchemy.orm import joinedload

from app.models.activity_log import ActivityLog
from app.models.api_token import ApiToken
from app.core.database import SessionLocal
from app.core.security import get_password_hash, validate_password_strength
from app.models.backup import Backup, BackupStatus
from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.models.invoice import Invoice, InvoiceStatus
from app.models.notification import Notification
from app.models.payment import PaymentMethod, Subscription
from app.models.plan import Plan
from app.models.report import Report
from app.models.schedule import Schedule
from app.models.tenant import Tenant
from app.models.user import User, UserRole
from app.services.tenant_access_service import TenantAccessService

bp = Blueprint("superadmin_tenants", __name__, url_prefix="/admin/tenants")


@bp.before_request
def check_superadmin():
    if session.get("user_role") != UserRole.SUPER_ADMIN.value:
        return redirect(url_for("auth.login"))


def _normalize_slug(raw: str) -> str:
    value = (raw or "").strip().lower()
    value = re.sub(r"[^a-z0-9-]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-")
    return value


def _parse_tenant_uuid(raw_value: str):
    try:
        return uuid.UUID(str(raw_value))
    except Exception:
        return None


def _parse_plan_uuid(raw_value: str | None):
    value = (raw_value or "").strip()
    if not value:
        return None
    try:
        return uuid.UUID(str(value))
    except Exception:
        return None


def _active_plans_query(db):
    return db.query(Plan).filter(Plan.is_active.is_(True)).order_by(Plan.price_monthly.asc(), Plan.name.asc())


def _safe_admin_return_url(raw_value: str | None) -> str | None:
    value = (raw_value or "").strip()
    if not value:
        return None
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        return None
    if not parsed.path.startswith("/admin/"):
        return None
    return urlunsplit(("", "", parsed.path, parsed.query, ""))


def _redirect_after_client_action(default_endpoint: str = "superadmin_tenants.list_tenants", **values):
    safe_return = _safe_admin_return_url(request.form.get("return_url"))
    if safe_return:
        return redirect(safe_return)
    return redirect(url_for(default_endpoint, **values))


def _current_superadmin_uuid():
    try:
        return uuid.UUID(str(session.get("user_id") or ""))
    except Exception:
        return None


def _delete_client_dependencies(db, tenant_id):
    user_ids = [row[0] for row in db.query(User.id).filter(User.tenant_id == tenant_id).all()]
    device_ids = [row[0] for row in db.query(Device.id).filter(Device.tenant_id == tenant_id).all()]

    if user_ids:
        db.query(ActivityLog).filter(ActivityLog.user_id.in_(user_ids)).update(
            {ActivityLog.user_id: None},
            synchronize_session=False,
        )
        db.query(Backup).filter(Backup.triggered_by_user_id.in_(user_ids)).update(
            {Backup.triggered_by_user_id: None},
            synchronize_session=False,
        )
        db.query(Notification).filter(Notification.user_id.in_(user_ids)).delete(synchronize_session=False)
        db.query(ApiToken).filter(ApiToken.user_id.in_(user_ids)).delete(synchronize_session=False)

    db.query(ActivityLog).filter(ActivityLog.tenant_id == tenant_id).update(
        {ActivityLog.tenant_id: None},
        synchronize_session=False,
    )
    db.query(ApiToken).filter(ApiToken.tenant_id == tenant_id).delete(synchronize_session=False)
    db.query(PaymentMethod).filter(PaymentMethod.tenant_id == tenant_id).delete(synchronize_session=False)
    db.query(Subscription).filter(Subscription.tenant_id == tenant_id).delete(synchronize_session=False)
    db.query(Report).filter(Report.tenant_id == tenant_id).delete(synchronize_session=False)

    if device_ids:
        db.query(Schedule).filter(Schedule.device_id.in_(device_ids)).delete(synchronize_session=False)
        db.query(Backup).filter(Backup.device_id.in_(device_ids)).delete(synchronize_session=False)
        db.query(Device).filter(Device.id.in_(device_ids)).delete(synchronize_session=False)

    db.query(DeviceGroup).filter(DeviceGroup.tenant_id == tenant_id).delete(synchronize_session=False)
    db.query(Invoice).filter(Invoice.tenant_id == tenant_id).delete(synchronize_session=False)
    db.query(User).filter(User.tenant_id == tenant_id).delete(synchronize_session=False)


@bp.route("/")
def list_tenants():
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "all").strip().lower()
    subscription = (request.args.get("subscription") or "all").strip().lower()
    ops = (request.args.get("ops") or "all").strip().lower()
    sort = (request.args.get("sort") or "created_desc").strip().lower()
    per_page = request.args.get("per_page", type=int) or 20
    page = request.args.get("page", type=int) or 1
    per_page = per_page if per_page in {20, 50, 100} else 20

    db = SessionLocal()
    try:
        query = db.query(Tenant).options(joinedload(Tenant.plan))
        if q:
            term = f"%{q}%"
            query = query.filter(
                Tenant.name.ilike(term) | Tenant.slug.ilike(term) | Tenant.email.ilike(term)
            )
        if status == "trash":
            query = query.filter(Tenant.deleted_at.isnot(None))
        else:
            query = query.filter(Tenant.deleted_at.is_(None))
        if status == "active":
            query = query.filter(Tenant.is_active.is_(True))
        elif status == "inactive":
            query = query.filter(Tenant.is_active.is_(False))
        elif status != "trash":
            status = "all"
        if subscription != "all":
            query = query.filter(Tenant.subscription_status == subscription)
        if ops == "no_plan":
            query = query.filter(Tenant.plan_id.is_(None), Tenant.access_unlimited.is_(False))
        elif ops == "payment_risk":
            query = query.filter(Tenant.subscription_status.in_(["trial", "past_due", "pending_payment", "canceled"]))
        elif ops == "payment_pending":
            query = query.filter(Tenant.subscription_status.in_(["trial", "past_due", "pending_payment"]))
        elif ops == "past_due":
            query = query.filter(Tenant.subscription_status == "past_due")
        elif ops == "canceled":
            query = query.filter(Tenant.subscription_status == "canceled")
        elif ops == "no_devices":
            subq = (
                db.query(Device.tenant_id)
                .group_by(Device.tenant_id)
                .subquery()
            )
            query = query.filter(Tenant.id.notin_(select(subq.c.tenant_id)))
        elif ops == "no_admin":
            subq = (
                db.query(User.tenant_id)
                .filter(User.role.in_([UserRole.TENANT_OWNER, UserRole.TENANT_ADMIN]))
                .group_by(User.tenant_id)
                .subquery()
            )
            query = query.filter(Tenant.id.notin_(select(subq.c.tenant_id)))
        else:
            ops = "all"

        total = query.count()
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = max(1, min(page, total_pages))

        if sort == "name_asc":
            query = query.order_by(Tenant.name.asc())
        elif sort == "name_desc":
            query = query.order_by(Tenant.name.desc())
        elif sort == "created_asc":
            query = query.order_by(Tenant.created_at.asc())
        else:
            sort = "created_desc"
            query = query.order_by(Tenant.created_at.desc())

        tenants = query.offset((page - 1) * per_page).limit(per_page).all()

        tenant_ids = [t.id for t in tenants]
        device_counts = {}
        user_counts = {}
        backup_stats = {}
        if tenant_ids:
            device_counts = {
                str(tid): int(count or 0)
                for tid, count in db.query(Device.tenant_id, func.count(Device.id))
                .filter(Device.tenant_id.in_(tenant_ids))
                .group_by(Device.tenant_id)
                .all()
            }
            user_counts = {
                str(tid): int(count or 0)
                for tid, count in db.query(User.tenant_id, func.count(User.id))
                .filter(User.tenant_id.in_(tenant_ids))
                .group_by(User.tenant_id)
                .all()
            }

            window_24h = datetime.utcnow() - timedelta(hours=24)
            backup_rows = (
                db.query(
                    Device.tenant_id,
                    func.sum(
                        case((Backup.status == BackupStatus.SUCCESS, 1), else_=0)
                    ).label("success_24h"),
                    func.sum(
                        case((Backup.status == BackupStatus.FAILED, 1), else_=0)
                    ).label("failed_24h"),
                )
                .join(Backup, Backup.device_id == Device.id)
                .filter(Device.tenant_id.in_(tenant_ids), Backup.created_at >= window_24h)
                .group_by(Device.tenant_id)
                .all()
            )
            backup_stats = {
                str(tid): {
                    "success_24h": int(success_24h or 0),
                    "failed_24h": int(failed_24h or 0),
                }
                for tid, success_24h, failed_24h in backup_rows
            }

        rows = []
        for tenant in tenants:
            tid = str(tenant.id)
            backup = backup_stats.get(tid, {"success_24h": 0, "failed_24h": 0})
            rows.append(
                {
                    "tenant": tenant,
                    "plan_label": TenantAccessService.get_plan_display_name(tenant),
                    "devices_count": device_counts.get(tid, 0),
                    "users_count": user_counts.get(tid, 0),
                    "success_24h": backup["success_24h"],
                    "failed_24h": backup["failed_24h"],
                }
            )

        stats = {
            "total": db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.is_(None)).scalar() or 0,
            "active": db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.is_(None), Tenant.is_active.is_(True)).scalar() or 0,
            "inactive": db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.is_(None), Tenant.is_active.is_(False)).scalar() or 0,
            "trash": db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.isnot(None)).scalar() or 0,
            "subscription_active": (
                db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.is_(None), Tenant.subscription_status == "active").scalar() or 0
            ),
            "subscription_trial": (
                db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.is_(None), Tenant.subscription_status == "trial").scalar() or 0
            ),
            "subscription_pending_payment": (
                db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.is_(None), Tenant.subscription_status == "pending_payment").scalar() or 0
            ),
            "subscription_past_due": (
                db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.is_(None), Tenant.subscription_status == "past_due").scalar() or 0
            ),
            "subscription_canceled": (
                db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.is_(None), Tenant.subscription_status == "canceled").scalar() or 0
            ),
            "no_plan": (
                db.query(func.count(Tenant.id))
                .filter(Tenant.deleted_at.is_(None), Tenant.plan_id.is_(None), Tenant.access_unlimited.is_(False))
                .scalar()
                or 0
            ),
            "unlimited_access": db.query(func.count(Tenant.id)).filter(Tenant.deleted_at.is_(None), Tenant.access_unlimited.is_(True)).scalar() or 0,
        }

        return render_template(
            "superadmin/tenants/list.html",
            rows=rows,
            stats=stats,
            q=q,
            status=status,
            subscription=subscription,
            ops=ops,
            sort=sort,
            per_page=per_page,
            page=page,
            total=total,
            total_pages=total_pages,
        )
    finally:
        db.close()


@bp.route("/<tenant_id>")
def view_tenant(tenant_id):
    db = SessionLocal()
    try:
        tenant_uuid = _parse_tenant_uuid(tenant_id)
        if not tenant_uuid:
            flash("Cliente inválido.", "error")
            return redirect(url_for("superadmin_tenants.list_tenants"))

        tenant = (
            db.query(Tenant)
            .options(joinedload(Tenant.plan))
            .filter(Tenant.id == tenant_uuid)
            .first()
        )
        if not tenant:
            flash("Cliente não encontrado.", "error")
            return redirect(url_for("superadmin_tenants.list_tenants"))

        now = datetime.utcnow()
        window_24h = now - timedelta(hours=24)
        window_30d = now - timedelta(days=30)

        device_count = db.query(func.count(Device.id)).filter(Device.tenant_id == tenant.id).scalar() or 0
        active_device_count = (
            db.query(func.count(Device.id))
            .filter(Device.tenant_id == tenant.id, Device.is_active.is_(True))
            .scalar()
            or 0
        )
        scheduled_device_count = (
            db.query(func.count(Device.id))
            .filter(Device.tenant_id == tenant.id, Device.backup_scheduled.is_(True))
            .scalar()
            or 0
        )
        group_count = db.query(func.count(DeviceGroup.id)).filter(DeviceGroup.tenant_id == tenant.id).scalar() or 0
        user_count = db.query(func.count(User.id)).filter(User.tenant_id == tenant.id).scalar() or 0
        admin_user_count = (
            db.query(func.count(User.id))
            .filter(User.tenant_id == tenant.id, User.role.in_([UserRole.TENANT_OWNER, UserRole.TENANT_ADMIN]))
            .scalar()
            or 0
        )

        backup_success_24h = (
            db.query(func.count(Backup.id))
            .join(Device, Backup.device_id == Device.id)
            .filter(
                Device.tenant_id == tenant.id,
                Backup.created_at >= window_24h,
                Backup.status == BackupStatus.SUCCESS,
            )
            .scalar()
            or 0
        )
        backup_failed_24h = (
            db.query(func.count(Backup.id))
            .join(Device, Backup.device_id == Device.id)
            .filter(
                Device.tenant_id == tenant.id,
                Backup.created_at >= window_24h,
                Backup.status == BackupStatus.FAILED,
            )
            .scalar()
            or 0
        )
        backup_success_30d = (
            db.query(func.count(Backup.id))
            .join(Device, Backup.device_id == Device.id)
            .filter(
                Device.tenant_id == tenant.id,
                Backup.created_at >= window_30d,
                Backup.status == BackupStatus.SUCCESS,
            )
            .scalar()
            or 0
        )
        backup_failed_30d = (
            db.query(func.count(Backup.id))
            .join(Device, Backup.device_id == Device.id)
            .filter(
                Device.tenant_id == tenant.id,
                Backup.created_at >= window_30d,
                Backup.status == BackupStatus.FAILED,
            )
            .scalar()
            or 0
        )

        invoices_paid = (
            db.query(func.count(Invoice.id))
            .filter(Invoice.tenant_id == tenant.id, Invoice.status == InvoiceStatus.PAID)
            .scalar()
            or 0
        )
        invoices_pending = (
            db.query(func.count(Invoice.id))
            .filter(Invoice.tenant_id == tenant.id, Invoice.status == InvoiceStatus.PENDING)
            .scalar()
            or 0
        )
        invoices_failed = (
            db.query(func.count(Invoice.id))
            .filter(Invoice.tenant_id == tenant.id, Invoice.status == InvoiceStatus.FAILED)
            .scalar()
            or 0
        )
        open_invoices_amount = (
            db.query(func.coalesce(func.sum(Invoice.amount), 0))
            .filter(
                Invoice.tenant_id == tenant.id,
                Invoice.status.in_([InvoiceStatus.PENDING, InvoiceStatus.FAILED]),
            )
            .scalar()
            or 0
        )
        next_due = (
            db.query(func.min(Invoice.due_date))
            .filter(
                Invoice.tenant_id == tenant.id,
                Invoice.status.in_([InvoiceStatus.PENDING, InvoiceStatus.FAILED]),
            )
            .scalar()
        )

        recent_users = (
            db.query(User)
            .filter(User.tenant_id == tenant.id)
            .order_by(User.created_at.desc())
            .limit(8)
            .all()
        )
        recent_invoices = (
            db.query(Invoice)
            .filter(Invoice.tenant_id == tenant.id)
            .order_by(Invoice.created_at.desc())
            .limit(8)
            .all()
        )
        recent_backups = (
            db.query(Backup, Device.name)
            .join(Device, Backup.device_id == Device.id)
            .filter(Device.tenant_id == tenant.id)
            .order_by(Backup.created_at.desc())
            .limit(12)
            .all()
        )
        recent_activities = (
            db.query(ActivityLog)
            .options(joinedload(ActivityLog.user))
            .filter(ActivityLog.tenant_id == tenant.id)
            .order_by(ActivityLog.created_at.desc())
            .limit(15)
            .all()
        )

        stats = {
            "device_count": int(device_count),
            "active_device_count": int(active_device_count),
            "scheduled_device_count": int(scheduled_device_count),
            "group_count": int(group_count),
            "user_count": int(user_count),
            "admin_user_count": int(admin_user_count),
            "backup_success_24h": int(backup_success_24h),
            "backup_failed_24h": int(backup_failed_24h),
            "backup_success_30d": int(backup_success_30d),
            "backup_failed_30d": int(backup_failed_30d),
            "invoices_paid": int(invoices_paid),
            "invoices_pending": int(invoices_pending),
            "invoices_failed": int(invoices_failed),
            "open_invoices_amount": float(open_invoices_amount or 0) / 100.0,
            "mrr": float((tenant.plan.price_monthly if tenant.plan else 0) or 0) / 100.0,
            "next_due": next_due,
        }

        return render_template(
            "superadmin/tenants/detail.html",
            tenant=tenant,
            plan_label=TenantAccessService.get_plan_display_name(tenant),
            stats=stats,
            recent_users=recent_users,
            recent_invoices=recent_invoices,
            recent_backups=recent_backups,
            recent_activities=recent_activities,
        )
    finally:
        db.close()


@bp.route("/add", methods=["GET", "POST"])
def add_tenant():
    db = SessionLocal()
    try:
        plans = _active_plans_query(db).all()
        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            slug = _normalize_slug(request.form.get("slug"))
            owner_email = (request.form.get("owner_email") or "").strip().lower()
            owner_password = (request.form.get("owner_password") or "").strip()
            owner_full_name = (request.form.get("owner_full_name") or "").strip() or f"Admin {name}"
            company_name = (request.form.get("company_name") or "").strip() or name
            access_unlimited = request.form.get("access_unlimited") == "on"
            plan_uuid = _parse_plan_uuid(request.form.get("plan_id"))
            selected_plan = db.query(Plan).filter(Plan.id == plan_uuid, Plan.is_active.is_(True)).first() if plan_uuid else None

            if not name or not slug or not owner_email or not owner_password:
                flash("Todos os campos obrigatórios devem ser preenchidos.", "error")
                return render_template("superadmin/tenants/add.html", plans=plans)

            if not access_unlimited and not selected_plan:
                flash("Todo cliente precisa de um plano ativo ou acesso ilimitado.", "error")
                return render_template("superadmin/tenants/add.html", plans=plans)

            password_error = validate_password_strength(owner_password)
            if password_error:
                flash(password_error, "error")
                return render_template("superadmin/tenants/add.html", plans=plans)

            if db.query(Tenant).filter(Tenant.slug == slug).first():
                flash("Esse slug já está em uso por outro cliente.", "error")
                return render_template("superadmin/tenants/add.html", plans=plans)

            if db.query(User).filter(User.email == owner_email).first():
                flash("Esse e-mail já está em uso por outro usuário.", "error")
                return render_template("superadmin/tenants/add.html", plans=plans)

            tenant = Tenant(
                name=name,
                slug=slug,
                email=owner_email,
                company_name=company_name,
                subscription_status="trial",
                is_active=True,
                access_unlimited=access_unlimited,
            )
            if selected_plan:
                TenantAccessService.seed_trial_plan_fields(tenant, selected_plan)
            db.add(tenant)
            db.flush()

            owner = User(
                email=owner_email,
                password_hash=get_password_hash(owner_password),
                full_name=owner_full_name,
                tenant_id=tenant.id,
                role=UserRole.TENANT_OWNER,
                is_active=True,
                email_verified=False,
                must_change_password=True,
                password_changed_at=None,
            )
            db.add(owner)
            db.commit()

            flash("Cliente criado com sucesso.", "success")
            return redirect(url_for("superadmin_tenants.list_tenants"))
        return render_template("superadmin/tenants/add.html", plans=plans)
    except Exception as exc:
        db.rollback()
        flash(f"Erro ao criar cliente: {str(exc)}", "error")
        return render_template("superadmin/tenants/add.html", plans=plans)
    finally:
        db.close()


@bp.route("/<tenant_id>/edit", methods=["GET", "POST"])
def edit_tenant(tenant_id):
    db = SessionLocal()
    try:
        plans = _active_plans_query(db).all()
        tenant_uuid = _parse_tenant_uuid(tenant_id)
        if not tenant_uuid:
            flash("Cliente inválido.", "error")
            return redirect(url_for("superadmin_tenants.list_tenants"))

        tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
        if not tenant:
            flash("Cliente não encontrado.", "error")
            return redirect(url_for("superadmin_tenants.list_tenants"))
        if TenantAccessService.is_deleted(tenant):
            flash("Cliente está na lixeira. Restaure antes de editar.", "error")
            return redirect(url_for("superadmin_tenants.view_tenant", tenant_id=tenant.id))

        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            slug = _normalize_slug(request.form.get("slug"))
            company_name = (request.form.get("company_name") or "").strip()
            email = (request.form.get("email") or "").strip().lower()
            access_unlimited = request.form.get("access_unlimited") == "on"
            plan_uuid = _parse_plan_uuid(request.form.get("plan_id"))
            selected_plan = db.query(Plan).filter(Plan.id == plan_uuid, Plan.is_active.is_(True)).first() if plan_uuid else None
            subscription_status = (request.form.get("subscription_status") or tenant.subscription_status or "trial").strip().lower()
            allowed_sub_status = {"trial", "active", "pending_payment", "past_due", "canceled"}
            if subscription_status not in allowed_sub_status:
                subscription_status = "trial"

            if not name or not slug or not email:
                flash("Nome, slug e e-mail são obrigatórios.", "error")
                return render_template("superadmin/tenants/edit.html", tenant=tenant, plans=plans)

            if not access_unlimited and not selected_plan:
                flash("Todo cliente precisa de um plano ativo ou acesso ilimitado.", "error")
                return render_template("superadmin/tenants/edit.html", tenant=tenant, plans=plans)

            exists_slug = (
                db.query(Tenant)
                .filter(Tenant.slug == slug, Tenant.id != tenant.id)
                .first()
            )
            if exists_slug:
                flash("Esse slug já está em uso por outro cliente.", "error")
                return render_template("superadmin/tenants/edit.html", tenant=tenant, plans=plans)

            device_count = TenantAccessService.get_device_count(db, tenant.id)
            if selected_plan:
                TenantAccessService.validate_plan_selection(
                    selected_plan,
                    device_count,
                    user_count=TenantAccessService.get_active_user_count(db, tenant.id),
                    storage_used_bytes=TenantAccessService.get_storage_used_bytes(db, tenant.id),
                )

            tenant.name = name
            tenant.slug = slug
            tenant.company_name = company_name or None
            tenant.email = email
            tenant.is_active = request.form.get("is_active") == "on"
            tenant.subscription_status = subscription_status
            tenant.access_unlimited = access_unlimited
            tenant.plan_id = selected_plan.id if selected_plan else None

            db.commit()
            flash("Cliente atualizado com sucesso.", "success")
            return redirect(url_for("superadmin_tenants.list_tenants"))

        return render_template("superadmin/tenants/edit.html", tenant=tenant, plans=plans)
    except Exception as exc:
        db.rollback()
        flash(f"Erro ao editar cliente: {str(exc)}", "error")
        if request.method == "POST" and "tenant" in locals():
            plans = _active_plans_query(db).all()
            return render_template("superadmin/tenants/edit.html", tenant=tenant, plans=plans)
        return redirect(url_for("superadmin_tenants.list_tenants"))
    finally:
        db.close()


@bp.route("/<tenant_id>/toggle-active", methods=["POST"])
def toggle_tenant_active(tenant_id):
    db = SessionLocal()
    try:
        tenant_uuid = _parse_tenant_uuid(tenant_id)
        if not tenant_uuid:
            flash("Cliente inválido.", "error")
            return redirect(url_for("superadmin_tenants.list_tenants"))

        tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
        if not tenant:
            flash("Cliente não encontrado.", "error")
            return redirect(url_for("superadmin_tenants.list_tenants"))
        if TenantAccessService.is_deleted(tenant):
            flash("Cliente está na lixeira. Restaure antes de alterar o status.", "error")
            return _redirect_after_client_action(
                "superadmin_tenants.view_tenant",
                tenant_id=tenant.id,
            )

        tenant.is_active = not bool(tenant.is_active)
        db.commit()

        action_label = "ativado" if tenant.is_active else "desativado"
        flash(f"Cliente {tenant.name} {action_label} com sucesso.", "success")
        return _redirect_after_client_action(
            "superadmin_tenants.view_tenant",
            tenant_id=tenant.id,
        )
    except Exception as exc:
        db.rollback()
        flash(f"Erro ao alterar status do cliente: {str(exc)}", "error")
        return redirect(url_for("superadmin_tenants.list_tenants"))
    finally:
        db.close()


@bp.route("/<tenant_id>/delete", methods=["POST"])
def delete_tenant(tenant_id):
    db = SessionLocal()
    try:
        tenant_uuid = _parse_tenant_uuid(tenant_id)
        if not tenant_uuid:
            flash("Cliente inválido.", "error")
            return redirect(url_for("superadmin_tenants.list_tenants"))

        tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
        if not tenant:
            flash("Cliente não encontrado.", "error")
            return redirect(url_for("superadmin_tenants.list_tenants"))

        if bool(tenant.protected_system_tenant) or tenant.slug in TenantAccessService.PROTECTED_DEFAULT_SLUGS:
            flash("Esse cliente é protegido e não pode ser apagado.", "error")
            return _redirect_after_client_action(
                "superadmin_tenants.view_tenant",
                tenant_id=tenant.id,
            )

        if TenantAccessService.is_deleted(tenant):
            flash("Cliente já está na lixeira.", "warning")
            return _redirect_after_client_action(
                "superadmin_tenants.view_tenant",
                tenant_id=tenant.id,
            )

        tenant.deleted_was_active = bool(tenant.is_active)
        tenant.is_active = False
        tenant.deleted_at = datetime.utcnow()
        tenant.deleted_by = _current_superadmin_uuid()
        tenant.delete_reason = (request.form.get("delete_reason") or "").strip() or None
        db.commit()

        flash(f"Cliente {tenant.name} enviado para a lixeira.", "success")
        return _redirect_after_client_action()
    except Exception as exc:
        db.rollback()
        flash(f"Erro ao apagar cliente: {str(exc)}", "error")
        return redirect(url_for("superadmin_tenants.list_tenants"))
    finally:
        db.close()


@bp.route("/<tenant_id>/restore", methods=["POST"])
def restore_tenant(tenant_id):
    db = SessionLocal()
    try:
        tenant_uuid = _parse_tenant_uuid(tenant_id)
        if not tenant_uuid:
            flash("Cliente inválido.", "error")
            return redirect(url_for("superadmin_tenants.list_tenants", status="trash"))

        tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
        if not tenant:
            flash("Cliente não encontrado.", "error")
            return redirect(url_for("superadmin_tenants.list_tenants", status="trash"))
        if not TenantAccessService.is_deleted(tenant):
            flash("Cliente não está na lixeira.", "warning")
            return _redirect_after_client_action(
                "superadmin_tenants.view_tenant",
                tenant_id=tenant.id,
            )

        can_reactivate = bool(tenant.deleted_was_active) and not bool(tenant.billing_blocked_at) and (
            (tenant.subscription_status or "").strip().lower() not in {"pending_payment", "canceled"}
        )
        tenant.is_active = can_reactivate
        tenant.deleted_at = None
        tenant.deleted_by = None
        tenant.delete_reason = None
        tenant.deleted_was_active = False
        db.commit()

        flash(
            f"Cliente {tenant.name} restaurado com sucesso."
            + ("" if can_reactivate else " O cliente voltou inativo e pode ser revisado antes de reabrir o acesso."),
            "success",
        )
        return _redirect_after_client_action(
            "superadmin_tenants.view_tenant",
            tenant_id=tenant.id,
        )
    except Exception as exc:
        db.rollback()
        flash(f"Erro ao restaurar cliente: {str(exc)}", "error")
        return redirect(url_for("superadmin_tenants.list_tenants", status="trash"))
    finally:
        db.close()


@bp.route("/<tenant_id>/purge", methods=["POST"])
def purge_tenant(tenant_id):
    db = SessionLocal()
    try:
        tenant_uuid = _parse_tenant_uuid(tenant_id)
        if not tenant_uuid:
            flash("Cliente inválido.", "error")
            return redirect(url_for("superadmin_tenants.list_tenants", status="trash"))

        tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
        if not tenant:
            flash("Cliente não encontrado.", "error")
            return redirect(url_for("superadmin_tenants.list_tenants", status="trash"))
        if bool(tenant.protected_system_tenant) or tenant.slug in TenantAccessService.PROTECTED_DEFAULT_SLUGS:
            flash("Esse cliente é protegido e não pode ser apagado permanentemente.", "error")
            return _redirect_after_client_action(
                "superadmin_tenants.view_tenant",
                tenant_id=tenant.id,
            )
        if not TenantAccessService.is_deleted(tenant):
            flash("Envie o cliente para a lixeira antes de apagar permanentemente.", "error")
            return _redirect_after_client_action(
                "superadmin_tenants.view_tenant",
                tenant_id=tenant.id,
            )

        client_name = tenant.name
        _delete_client_dependencies(db, tenant.id)
        db.query(Tenant).filter(Tenant.id == tenant.id).delete(synchronize_session=False)
        db.commit()

        flash(f"Cliente {client_name} apagado permanentemente.", "success")
        return redirect(url_for("superadmin_tenants.list_tenants", status="trash"))
    except Exception as exc:
        db.rollback()
        flash(f"Erro ao apagar definitivamente o cliente: {str(exc)}", "error")
        return redirect(url_for("superadmin_tenants.list_tenants", status="trash"))
    finally:
        db.close()
