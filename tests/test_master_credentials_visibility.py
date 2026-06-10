import uuid

import pytest

from app import create_flask_app
from app.core.database import SessionLocal
from app.core.security import encrypt_password
from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.models.tenant import Tenant
from app.models.user import User, UserRole


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


def _login_session_with_user_id(client, role: UserRole, tenant_slug: str, user_id):
    with client.session_transaction() as sess:
        sess["user_id"] = str(user_id)
        sess["user_role"] = role.value
        sess["tenant_slug"] = tenant_slug
        sess["_csrf_token"] = "csrf-test-token"


@pytest.fixture
def seeded_credentials_data():
    tenant_slug = f"tenant-master-creds-{uuid.uuid4().hex[:8]}"
    db = SessionLocal()
    try:
        tenant = Tenant(
            id=uuid.uuid4(),
            slug=tenant_slug,
            name="Tenant Credenciais",
            email=f"{tenant_slug}@test.local",
            is_active=True,
        )
        vpn_group = DeviceGroup(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            name="Grupo VPN",
            slug=f"grupo-vpn-{uuid.uuid4().hex[:6]}",
            description="Grupo com VPN",
            connection_type="vpn",
            uses_vpn=True,
            vpn_type="l2tp",
            vpn_server="vpn.example.local",
            vpn_username="vpn-user",
            vpn_password_encrypted=encrypt_password("vpnpass123"),
            vpn_ipsec_secret_encrypted=encrypt_password("ipsecsecret123"),
            is_active=True,
        )
        jump_group = DeviceGroup(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            name="Grupo Jump",
            slug=f"grupo-jump-{uuid.uuid4().hex[:6]}",
            description="Grupo com jump host",
            connection_type="jump_host",
            uses_jump_host=True,
            jump_host="jump.example.local",
            jump_port=22,
            jump_username="jump-user",
            jump_password_encrypted=encrypt_password("jumppass123"),
            jump_key_encrypted=encrypt_password("-----BEGIN PRIVATE KEY-----\njump-key-material\n-----END PRIVATE KEY-----"),
            is_active=True,
        )
        device = Device(
            id=uuid.uuid4(),
            tenant_id=tenant.id,
            group_id=vpn_group.id,
            name="Router Core",
            ip_address="10.10.10.10",
            port=22,
            username="admin",
            password_encrypted=encrypt_password("routerpass123"),
            description="Device inicial",
            use_telnet=False,
            backup_scheduled=False,
            is_active=True,
            extra_parameters={},
        )

        db.add(tenant)
        db.add(vpn_group)
        db.add(jump_group)
        db.add(device)
        db.commit()

        return {
            "tenant_slug": tenant_slug,
            "tenant_id": tenant.id,
            "vpn_group_id": str(vpn_group.id),
            "jump_group_id": str(jump_group.id),
            "device_id": str(device.id),
        }
    finally:
        db.close()


def test_tenant_owner_sees_current_device_password(flask_client, seeded_credentials_data):
    tenant_slug = seeded_credentials_data["tenant_slug"]
    device_id = seeded_credentials_data["device_id"]
    _login_session(flask_client, UserRole.TENANT_OWNER, tenant_slug)

    response = flask_client.get(f"/tenant/{tenant_slug}/devices/{device_id}/edit", follow_redirects=False)

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'id="device_password"' in html
    assert "routerpass123" in html
    assert "toggleSensitiveField('device_password'" in html


def test_stale_session_role_still_shows_owner_credentials(flask_client, seeded_credentials_data):
    tenant_slug = seeded_credentials_data["tenant_slug"]
    device_id = seeded_credentials_data["device_id"]

    db = SessionLocal()
    try:
        owner_user = User(
            id=uuid.uuid4(),
            tenant_id=seeded_credentials_data["tenant_id"],
            email=f"owner-{uuid.uuid4().hex[:6]}@test.local",
            full_name="Owner Real",
            password_hash="hash",
            role=UserRole.TENANT_OWNER,
            is_active=True,
        )
        db.add(owner_user)
        db.commit()
        owner_user_id = owner_user.id
    finally:
        db.close()

    _login_session_with_user_id(flask_client, UserRole.TENANT_ADMIN, tenant_slug, owner_user_id)

    response = flask_client.get(f"/tenant/{tenant_slug}/devices/{device_id}/edit", follow_redirects=False)

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'id="device_password"' in html
    assert "routerpass123" in html


def test_tenant_admin_does_not_see_current_device_password(flask_client, seeded_credentials_data):
    tenant_slug = seeded_credentials_data["tenant_slug"]
    device_id = seeded_credentials_data["device_id"]
    _login_session(flask_client, UserRole.TENANT_ADMIN, tenant_slug)

    response = flask_client.get(f"/tenant/{tenant_slug}/devices/{device_id}/edit", follow_redirects=False)

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "routerpass123" not in html
    assert 'id="device_password"' in html
    assert "Deixe em" in html
    assert "branco para manter" in html


def test_tenant_owner_sees_current_vpn_group_credentials(flask_client, seeded_credentials_data):
    tenant_slug = seeded_credentials_data["tenant_slug"]
    group_id = seeded_credentials_data["vpn_group_id"]
    _login_session(flask_client, UserRole.TENANT_OWNER, tenant_slug)

    response = flask_client.get(f"/tenant/{tenant_slug}/groups/{group_id}/edit", follow_redirects=False)

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "vpnpass123" in html
    assert "ipsecsecret123" in html
    assert 'id="group_vpn_password"' in html
    assert 'id="group_vpn_ipsec_secret"' in html
    assert "toggleSensitiveField('group_vpn_password'" in html
    assert "toggleSensitiveField('group_vpn_ipsec_secret'" in html


def test_tenant_admin_does_not_see_current_vpn_group_credentials(flask_client, seeded_credentials_data):
    tenant_slug = seeded_credentials_data["tenant_slug"]
    group_id = seeded_credentials_data["vpn_group_id"]
    _login_session(flask_client, UserRole.TENANT_ADMIN, tenant_slug)

    response = flask_client.get(f"/tenant/{tenant_slug}/groups/{group_id}/edit", follow_redirects=False)

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "vpnpass123" not in html
    assert "ipsecsecret123" not in html


def test_tenant_owner_sees_current_jump_group_credentials(flask_client, seeded_credentials_data):
    tenant_slug = seeded_credentials_data["tenant_slug"]
    group_id = seeded_credentials_data["jump_group_id"]
    _login_session(flask_client, UserRole.TENANT_OWNER, tenant_slug)

    response = flask_client.get(f"/tenant/{tenant_slug}/groups/{group_id}/edit", follow_redirects=False)

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "jumppass123" in html
    assert "BEGIN PRIVATE KEY" in html
    assert 'id="group_jump_password"' in html
    assert "toggleSensitiveField('group_jump_password'" in html


def test_editing_device_without_new_password_keeps_existing_secret(flask_client, seeded_credentials_data):
    tenant_slug = seeded_credentials_data["tenant_slug"]
    device_id = seeded_credentials_data["device_id"]
    _login_session(flask_client, UserRole.TENANT_OWNER, tenant_slug)

    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == uuid.UUID(device_id)).first()
        original_password_encrypted = device.password_encrypted
        group_id = str(device.group_id)
    finally:
        db.close()

    response = flask_client.post(
        f"/tenant/{tenant_slug}/devices/{device_id}/edit",
        data={
            "_csrf_token": "csrf-test-token",
            "name": "Router Core Atualizado",
            "device_type_id": "",
            "group_id": group_id,
            "ip_address": "10.10.10.10",
            "port": "22",
            "username": "admin",
            "password": "",
            "description": "Descricao alterada",
            "schedule_frequency": "daily",
            "schedule_time": "00:00",
        },
        follow_redirects=False,
    )

    assert response.status_code in (302, 303)

    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == uuid.UUID(device_id)).first()
        assert device.password_encrypted == original_password_encrypted
        assert device.description == "Descricao alterada"
    finally:
        db.close()


def test_editing_group_without_new_secrets_keeps_existing_values(flask_client, seeded_credentials_data):
    tenant_slug = seeded_credentials_data["tenant_slug"]
    group_id = seeded_credentials_data["jump_group_id"]
    _login_session(flask_client, UserRole.TENANT_OWNER, tenant_slug)

    db = SessionLocal()
    try:
        group = db.query(DeviceGroup).filter(DeviceGroup.id == uuid.UUID(group_id)).first()
        original_jump_password = group.jump_password_encrypted
        original_jump_key = group.jump_key_encrypted
    finally:
        db.close()

    response = flask_client.post(
        f"/tenant/{tenant_slug}/groups/{group_id}/edit",
        data={
            "_csrf_token": "csrf-test-token",
            "name": "Grupo Jump",
            "description": "Descricao atualizada sem trocar segredo",
            "connection_type": "jump_host",
            "jump_host": "jump.example.local",
            "jump_port": "22",
            "jump_username": "jump-user",
            "jump_password": "",
            "jump_key": "",
            "vpn_type": "l2tp",
            "vpn_server": "",
            "vpn_username": "",
            "vpn_password": "",
            "vpn_ipsec_secret": "",
        },
        follow_redirects=False,
    )

    assert response.status_code in (302, 303)

    db = SessionLocal()
    try:
        group = db.query(DeviceGroup).filter(DeviceGroup.id == uuid.UUID(group_id)).first()
        assert group.jump_password_encrypted == original_jump_password
        assert group.jump_key_encrypted == original_jump_key
        assert group.description == "Descricao atualizada sem trocar segredo"
    finally:
        db.close()


def test_corrupted_saved_secret_does_not_break_device_edit_page(flask_client, seeded_credentials_data):
    tenant_slug = seeded_credentials_data["tenant_slug"]
    device_id = seeded_credentials_data["device_id"]
    _login_session(flask_client, UserRole.TENANT_OWNER, tenant_slug)

    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == uuid.UUID(device_id)).first()
        device.password_encrypted = "valor-invalido"
        db.commit()
    finally:
        db.close()

    response = flask_client.get(f"/tenant/{tenant_slug}/devices/{device_id}/edit", follow_redirects=False)

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "valor-invalido" not in html
