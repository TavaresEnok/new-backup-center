import uuid
from datetime import datetime, timedelta

import pytest

from app import create_flask_app
from app.core.database import SessionLocal
from app.core.security import encrypt_password
from app.models.activity_log import ActivityLog
from app.models.backup import Backup, BackupStatus
from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.models.tenant import Tenant
from app.models.user import UserRole
from app.tasks.backups import purge_failed_backups_periodic


@pytest.fixture
def flask_client():
    app = create_flask_app()
    app.config["TESTING"] = True
    return app.test_client()


def _login_session(client, role: UserRole, tenant_slug: str):
    with client.session_transaction() as sess:
        sess["user_id"] = str(uuid.uuid4())
        sess["user_role"] = role.value
        sess["tenant_slug"] = tenant_slug
        sess["_csrf_token"] = "csrf-test-token"


def _seed_tenant_with_device():
    tenant_slug = f"tenant-cleanup-{uuid.uuid4().hex[:8]}"
    db = SessionLocal()
    try:
        tenant = Tenant(
            id=uuid.uuid4(),
            slug=tenant_slug,
            name="Tenant Cleanup",
            email=f"{tenant_slug}@test.local",
            is_active=True,
        )
        group = DeviceGroup(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            name="Grupo Teste",
            slug=f"grupo-{uuid.uuid4().hex[:6]}",
            connection_type="direct",
            is_active=True,
        )
        device = Device(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            group_id=group.id,
            name="Device Paginacao",
            ip_address="10.0.0.1",
            port=22,
            username="admin",
            password_encrypted=encrypt_password("secret"),
            is_active=True,
            extra_parameters={},
            backup_scheduled=True,
        )
        db.add(tenant)
        db.add(group)
        db.add(device)
        db.commit()
        return tenant_slug, tenant.id, device.id
    finally:
        db.close()


def test_schedules_page_has_cleanup_buttons(flask_client):
    tenant_slug, _, _ = _seed_tenant_with_device()
    _login_session(flask_client, UserRole.TENANT_OWNER, tenant_slug)

    response = flask_client.get(f"/tenant/{tenant_slug}/schedules/", follow_redirects=False)

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Limpar tempo real/alertas" in html
    assert "Limpar backups failed" in html


def test_clear_failed_backups_route_removes_only_failed(flask_client):
    tenant_slug, _, device_id = _seed_tenant_with_device()
    _login_session(flask_client, UserRole.TENANT_OWNER, tenant_slug)

    db = SessionLocal()
    try:
        db.add(
            Backup(
                id=uuid.uuid4(),
                device_id=device_id,
                status=BackupStatus.SUCCESS,
                created_at=datetime.utcnow(),
            )
        )
        db.add(
            Backup(
                id=uuid.uuid4(),
                device_id=device_id,
                status=BackupStatus.FAILED,
                error_message="Falha 1",
                created_at=datetime.utcnow() - timedelta(minutes=1),
            )
        )
        db.add(
            Backup(
                id=uuid.uuid4(),
                device_id=device_id,
                status=BackupStatus.FAILED,
                error_message="Falha 2",
                created_at=datetime.utcnow() - timedelta(minutes=2),
            )
        )
        db.commit()
    finally:
        db.close()

    response = flask_client.post(
        f"/tenant/{tenant_slug}/backups/failed/clear",
        data={"_csrf_token": "csrf-test-token", "return_to": "schedules"},
        follow_redirects=False,
    )
    assert response.status_code in (302, 303)

    db = SessionLocal()
    try:
        remaining = db.query(Backup).filter(Backup.device_id == device_id).all()
        assert len(remaining) == 1
        assert remaining[0].status_value == BackupStatus.SUCCESS.value
    finally:
        db.close()


def test_clear_live_alerts_route_removes_alert_actions(flask_client):
    tenant_slug, tenant_id, _ = _seed_tenant_with_device()
    _login_session(flask_client, UserRole.TENANT_OWNER, tenant_slug)

    db = SessionLocal()
    try:
        db.add(
            ActivityLog(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                user_id=None,
                action="BACKUP_FAIL",
                details="falha de conexao",
                ip_address="127.0.0.1",
            )
        )
        db.add(
            ActivityLog(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                user_id=None,
                action="SYSTEM_ERROR",
                details="erro de script",
                ip_address="127.0.0.1",
            )
        )
        db.add(
            ActivityLog(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                user_id=None,
                action="LOGIN_SUCCESS",
                details="login ok",
                ip_address="127.0.0.1",
            )
        )
        db.commit()
    finally:
        db.close()

    response = flask_client.post(
        f"/tenant/{tenant_slug}/activity/clear-alerts",
        data={"_csrf_token": "csrf-test-token", "return_to": "schedules"},
        follow_redirects=False,
    )
    assert response.status_code in (302, 303)

    db = SessionLocal()
    try:
        actions = [
            row.action
            for row in db.query(ActivityLog).filter(ActivityLog.tenant_id == tenant_id).all()
        ]
        assert "BACKUP_FAIL" not in actions
        assert "SYSTEM_ERROR" not in actions
        assert "LOGIN_SUCCESS" in actions
    finally:
        db.close()


def test_periodic_failed_cleanup_removes_only_failed_older_than_3_days():
    tenant_slug, _, device_id = _seed_tenant_with_device()
    assert tenant_slug  # evita linter de variável não usada

    db = SessionLocal()
    try:
        old_failed = Backup(
            id=uuid.uuid4(),
            device_id=device_id,
            status=BackupStatus.FAILED,
            created_at=datetime.utcnow() - timedelta(days=4),
            error_message="antigo",
        )
        recent_failed = Backup(
            id=uuid.uuid4(),
            device_id=device_id,
            status=BackupStatus.FAILED,
            created_at=datetime.utcnow() - timedelta(days=1),
            error_message="recente",
        )
        old_success = Backup(
            id=uuid.uuid4(),
            device_id=device_id,
            status=BackupStatus.SUCCESS,
            created_at=datetime.utcnow() - timedelta(days=10),
        )
        db.add(old_failed)
        db.add(recent_failed)
        db.add(old_success)
        db.commit()
    finally:
        db.close()

    result = purge_failed_backups_periodic()
    assert isinstance(result, dict)
    assert int(result.get("deleted", 0)) >= 1

    db = SessionLocal()
    try:
        rows = db.query(Backup).filter(Backup.device_id == device_id).all()
        statuses = sorted((row.status_value, row.error_message or "") for row in rows)
        assert (BackupStatus.FAILED.value, "recente") in statuses
        assert (BackupStatus.SUCCESS.value, "") in statuses
        assert (BackupStatus.FAILED.value, "antigo") not in statuses
    finally:
        db.close()


def test_device_view_backup_history_has_pagination(flask_client):
    tenant_slug, _, device_id = _seed_tenant_with_device()
    _login_session(flask_client, UserRole.TENANT_OWNER, tenant_slug)

    db = SessionLocal()
    try:
        now = datetime.utcnow()
        for idx in range(30):
            db.add(
                Backup(
                    id=uuid.uuid4(),
                    device_id=device_id,
                    status=BackupStatus.SUCCESS,
                    created_at=now - timedelta(minutes=idx),
                )
            )
        db.commit()
    finally:
        db.close()

    response_page_1 = flask_client.get(f"/tenant/{tenant_slug}/devices/{device_id}", follow_redirects=False)
    assert response_page_1.status_code == 200
    html_page_1 = response_page_1.get_data(as_text=True)
    assert "Página 1 de 2" in html_page_1
    assert "backup_page=2" in html_page_1

    response_page_2 = flask_client.get(
        f"/tenant/{tenant_slug}/devices/{device_id}?backup_page=2",
        follow_redirects=False,
    )
    assert response_page_2.status_code == 200
    html_page_2 = response_page_2.get_data(as_text=True)
    assert "Página 2 de 2" in html_page_2
