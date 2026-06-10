import uuid

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from sqlalchemy import func

from app.core.database import SessionLocal
from app.models.plan import Plan
from app.models.tenant import Tenant
from app.models.user import UserRole
from app.services.billing_policy_service import BillingPolicyService
from app.services.plan_limits_service import PlanLimitsService

bp = Blueprint("superadmin_plans", __name__, url_prefix="/admin/plans")


@bp.before_request
def check_superadmin():
    if session.get("user_role") != UserRole.SUPER_ADMIN.value:
        return redirect(url_for("auth.login"))


def _to_cents(value: str) -> int:
    return int(round(float(value or 0) * 100))


def _to_int(value: str, default: int, minimum: int) -> int:
    try:
        parsed = int(str(value or "").strip())
    except Exception:
        parsed = default
    return max(parsed, minimum)


@bp.route("/")
def list_plans():
    BillingPolicyService.ensure_schema()
    PlanLimitsService.ensure_schema()
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "all").strip().lower()
    sort = (request.args.get("sort") or "price_monthly_asc").strip().lower()

    db = SessionLocal()
    try:
        query = db.query(Plan)
        if q:
            term = f"%{q}%"
            query = query.filter(Plan.name.ilike(term) | Plan.slug.ilike(term) | Plan.description.ilike(term))
        if status == "active":
            query = query.filter(Plan.is_active.is_(True))
        elif status == "inactive":
            query = query.filter(Plan.is_active.is_(False))

        if sort == "price_monthly_desc":
            query = query.order_by(Plan.price_monthly.desc(), Plan.name.asc())
        elif sort == "name_asc":
            query = query.order_by(Plan.name.asc())
        elif sort == "name_desc":
            query = query.order_by(Plan.name.desc())
        else:
            query = query.order_by(Plan.price_monthly.asc(), Plan.name.asc())

        plans = query.all()
        usage_counts = {
            str(plan_id): int(count or 0)
            for plan_id, count in db.query(Tenant.plan_id, func.count(Tenant.id))
            .filter(Tenant.plan_id.isnot(None), Tenant.deleted_at.is_(None))
            .group_by(Tenant.plan_id)
            .all()
        }

        rows = []
        for plan in plans:
            rows.append(
                {
                    "plan": plan,
                    "tenant_count": usage_counts.get(str(plan.id), 0),
                }
            )

        stats = {
            "total": db.query(func.count(Plan.id)).scalar() or 0,
            "active": db.query(func.count(Plan.id)).filter(Plan.is_active.is_(True)).scalar() or 0,
            "inactive": db.query(func.count(Plan.id)).filter(Plan.is_active.is_(False)).scalar() or 0,
        }
        return render_template(
            "superadmin/plans/list.html",
            rows=rows,
            stats=stats,
            q=q,
            status=status,
            sort=sort,
        )
    finally:
        db.close()


@bp.route("/add", methods=["GET", "POST"])
def add_plan():
    BillingPolicyService.ensure_schema()
    PlanLimitsService.ensure_schema()
    if request.method == "POST":
        db = SessionLocal()
        try:
            slug = (request.form.get("slug") or "").strip().lower()
            if not slug:
                flash("Slug é obrigatório.", "error")
                return render_template("superadmin/plans/add.html")
            if db.query(Plan).filter(Plan.slug == slug).first():
                flash("Slug já utilizado em outro plano.", "error")
                return render_template("superadmin/plans/add.html")

            new_plan = Plan(
                name=(request.form.get("name") or "").strip(),
                slug=slug,
                description=(request.form.get("description") or "").strip() or None,
                price_monthly=_to_cents(request.form.get("price_monthly")),
                price_yearly=_to_cents(request.form.get("price_yearly")),
                trial_days=int(request.form.get("trial_days") or 14),
                billing_period_days=_to_int(request.form.get("billing_period_days"), 30, 1),
                payment_grace_days=_to_int(request.form.get("payment_grace_days"), 3, 0),
                max_devices=int(request.form.get("max_devices") or 0),
                max_users=int(request.form.get("max_users") or 0),
                backup_retention_days=int(request.form.get("backup_retention_days") or 30),
                storage_quota_gb=_to_int(request.form.get("storage_quota_gb"), 10, 0),
                download_quota_gb_month=_to_int(request.form.get("download_quota_gb_month"), 20, 0),
                max_download_rate_mbps=_to_int(request.form.get("max_download_rate_mbps"), 0, 0),
                is_active=request.form.get("is_active") == "on",
            )
            db.add(new_plan)
            db.commit()
            flash("Plano criado com sucesso.", "success")
            return redirect(url_for("superadmin_plans.list_plans"))
        except Exception as exc:
            db.rollback()
            flash(f"Erro ao criar plano: {str(exc)}", "error")
        finally:
            db.close()

    return render_template("superadmin/plans/add.html")


@bp.route("/<plan_id>/edit", methods=["GET", "POST"])
def edit_plan(plan_id):
    BillingPolicyService.ensure_schema()
    PlanLimitsService.ensure_schema()
    db = SessionLocal()
    try:
        try:
            plan_uuid = uuid.UUID(str(plan_id))
        except Exception:
            flash("Plano inválido.", "error")
            return redirect(url_for("superadmin_plans.list_plans"))

        plan = db.query(Plan).filter(Plan.id == plan_uuid).first()
        if not plan:
            flash("Plano não encontrado.", "error")
            return redirect(url_for("superadmin_plans.list_plans"))

        if request.method == "POST":
            slug = (request.form.get("slug") or "").strip().lower()
            if not slug:
                flash("Slug é obrigatório.", "error")
                return render_template("superadmin/plans/edit.html", plan=plan)
            slug_exists = db.query(Plan).filter(Plan.slug == slug, Plan.id != plan.id).first()
            if slug_exists:
                flash("Slug já utilizado em outro plano.", "error")
                return render_template("superadmin/plans/edit.html", plan=plan)

            plan.name = (request.form.get("name") or "").strip()
            plan.slug = slug
            plan.description = (request.form.get("description") or "").strip() or None
            plan.price_monthly = _to_cents(request.form.get("price_monthly"))
            plan.price_yearly = _to_cents(request.form.get("price_yearly"))
            plan.trial_days = int(request.form.get("trial_days") or 14)
            plan.billing_period_days = _to_int(request.form.get("billing_period_days"), 30, 1)
            plan.payment_grace_days = _to_int(request.form.get("payment_grace_days"), 3, 0)
            plan.max_devices = int(request.form.get("max_devices") or 0)
            plan.max_users = int(request.form.get("max_users") or 0)
            plan.backup_retention_days = int(request.form.get("backup_retention_days") or 30)
            plan.storage_quota_gb = _to_int(request.form.get("storage_quota_gb"), 10, 0)
            plan.download_quota_gb_month = _to_int(request.form.get("download_quota_gb_month"), 20, 0)
            plan.max_download_rate_mbps = _to_int(request.form.get("max_download_rate_mbps"), 0, 0)
            plan.is_active = request.form.get("is_active") == "on"

            db.commit()
            flash("Plano atualizado com sucesso.", "success")
            return redirect(url_for("superadmin_plans.list_plans"))

        return render_template("superadmin/plans/edit.html", plan=plan)
    except Exception as exc:
        db.rollback()
        flash(f"Erro ao editar plano: {str(exc)}", "error")
        return redirect(url_for("superadmin_plans.list_plans"))
    finally:
        db.close()
