from collections import OrderedDict

from flask import Blueprint, render_template, request, session, abort
from app.web.auth.decorators import login_required
from app.core.database import SessionLocal
from app.models.tenant import Tenant
from app.models.backup import Backup
from app.models.device import Device
from app.models.user import UserRole
from app.services.backup_diagnostics import classify_failure
from sqlalchemy.orm import joinedload
from sqlalchemy import func
from datetime import datetime, timedelta

bp = Blueprint('tenant_reports', __name__, url_prefix='/tenant/<tenant_slug>/reports')


def _pending_reason_bucket(category: str) -> tuple[str, str]:
    normalized = str(category or "").strip().lower()
    if normalized == "auth":
        return "Credencial", "crit"
    if normalized in {"connection", "no_ping", "jump_session_closed", "circuit_breaker", "banner_timeout"}:
        return "Rota / conectividade", "care"
    if normalized in {"timeout", "port_refused"}:
        return "Porta / timeout", "care"
    if normalized == "vpn":
        return "VPN", "warn"
    if normalized == "script":
        return "Script / coleta", "ink-2"
    return "Não classificado", "ink-3"

@bp.route('/daily')
@login_required
def daily(tenant_slug):
    return render_report(tenant_slug, 'daily', 'Relatório Diário')

@bp.route('/weekly')
@login_required
def weekly(tenant_slug):
    return render_report(tenant_slug, 'weekly', 'Relatório Semanal')

@bp.route('/monthly')
@login_required
def monthly(tenant_slug):
    return render_report(tenant_slug, 'monthly', 'Relatório Mensal')

def render_report(tenant_slug, period_type, title):
    if session.get('user_role') != UserRole.SUPER_ADMIN.value and session.get('tenant_slug') != tenant_slug:
        abort(403)
    db = SessionLocal()
    tenant = db.query(Tenant).filter_by(slug=tenant_slug).first()
    if not tenant:
        db.close()
        return "Tenant not found", 404
    
    # Definir intervalo de datas
    now = datetime.utcnow()
    if period_type == 'daily':
        start_date = now - timedelta(days=1)
    elif period_type == 'weekly':
        start_date = now - timedelta(weeks=1)
    elif period_type == 'monthly':
        start_date = now - timedelta(days=30)
    else:
        start_date = now - timedelta(days=1)

    try:
        # Estatísticas no período
        query = (
            db.query(Backup)
            .join(Device)
            .filter(
                Device.tenant_id == tenant.id,
                Backup.created_at >= start_date
            )
        )

        total = query.count()
        success = query.filter(Backup.status == 'success').count()
        failed = query.filter(Backup.status == 'failed').count()

        # Lista detalhada com eager loading para evitar DetachedInstanceError no template
        backups = (
            db.query(Backup)
            .options(joinedload(Backup.device))
            .join(Device)
            .filter(
                Device.tenant_id == tenant.id,
                Backup.created_at >= start_date
            )
            .order_by(Backup.created_at.desc())
            .limit(100)
            .all()
        )

        pending_reason_counts = OrderedDict()
        pending_total = 0
        for backup in backups:
            status_value = str(
                getattr(backup, "status_value", None)
                or getattr(getattr(backup, "status", None), "value", None)
                or getattr(backup, "status", "")
                or ""
            ).strip().lower()
            if status_value not in {"failed", "failure"}:
                continue
            bucket_label, bucket_tone = _pending_reason_bucket(classify_failure(backup.error_message or ""))
            bucket = pending_reason_counts.get(bucket_label)
            if not bucket:
                bucket = {"label": bucket_label, "tone": bucket_tone, "count": 0}
                pending_reason_counts[bucket_label] = bucket
            bucket["count"] += 1
            pending_total += 1

        pending_reason_breakdown = []
        if pending_total > 0:
            pending_reason_breakdown = sorted(
                (
                    {
                        "label": item["label"],
                        "tone": item["tone"],
                        "count": int(item["count"]),
                        "pct": int((int(item["count"]) * 100) // pending_total),
                    }
                    for item in pending_reason_counts.values()
                    if int(item["count"]) > 0
                ),
                key=lambda item: (-int(item["count"]), str(item["label"]).lower()),
            )

        return render_template(
            'tenant/reports/index.html',
            tenant=tenant,
            report_title=title,
            period=period_type,
            stats={'total': total, 'success': success, 'failed': failed},
            backups=backups,
            pending_reason_breakdown=pending_reason_breakdown,
        )
    finally:
        db.close()
