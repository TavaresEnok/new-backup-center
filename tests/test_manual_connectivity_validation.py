import uuid
from pathlib import Path

import pytest

from app import create_flask_app
from app.celery_app import celery_app
from app.core.database import SessionLocal
from app.models.tenant import Tenant
from app.models.user import UserRole


@pytest.fixture
def flask_client():
    app = create_flask_app()
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def seeded_manual_validation_tenant():
    tenant_slug = f"tenant-manual-validation-{uuid.uuid4().hex[:8]}"
    db = SessionLocal()
    try:
        tenant = Tenant(
            id=uuid.uuid4(),
            slug=tenant_slug,
            name="Tenant Validacao Manual",
            email=f"{tenant_slug}@test.local",
            is_active=True,
        )
        db.add(tenant)
        db.commit()
        return {"tenant_slug": tenant_slug}
    finally:
        db.close()


def _login_session(client, role: UserRole, tenant_slug: str):
    with client.session_transaction() as sess:
        sess["user_id"] = str(uuid.uuid4())
        sess["user_role"] = role.value
        sess["tenant_slug"] = tenant_slug
        sess["_csrf_token"] = "csrf-test-token"


def test_celery_beat_removes_automatic_ping_schedule():
    scheduled_tasks = celery_app.conf.beat_schedule
    assert "ping-all-devices-every-5-min" not in scheduled_tasks
    assert all(
        entry.get("task") != "app.tasks.monitoring.ping_all_devices_periodic"
        for entry in scheduled_tasks.values()
    )
    assert all(
        entry.get("task") != "app.tasks.monitoring.run_jump_host_health_checks_periodic"
        for entry in scheduled_tasks.values()
    )


def test_dashboard_and_schedules_reflect_manual_validation_only(
    flask_client,
    seeded_manual_validation_tenant,
):
    tenant_slug = seeded_manual_validation_tenant["tenant_slug"]
    _login_session(flask_client, UserRole.TENANT_OWNER, tenant_slug)

    dashboard_template = Path("app/templates/tenant/dashboard.html").read_text()
    assert "monitoramento automatico de ping" in dashboard_template
    assert "Ping OK:" not in dashboard_template
    assert "Ping sem login:" not in dashboard_template
    assert "url_for('tenant.refresh_status'" not in dashboard_template

    refresh_response = flask_client.post(
        f"/tenant/{tenant_slug}/refresh-status",
        data={"_csrf_token": "csrf-test-token"},
        follow_redirects=False,
    )
    assert refresh_response.status_code in (302, 303)

    schedules_response = flask_client.get(f"/tenant/{tenant_slug}/schedules/", follow_redirects=False)
    schedules_html = schedules_response.get_data(as_text=True)
    assert schedules_response.status_code == 200
    assert "Validar conectividade" in schedules_html
    assert "Aplicar neste grupo" not in schedules_html
    assert "Diagnosticar Jump" not in dashboard_template
    assert "Ping/Login" not in schedules_html
