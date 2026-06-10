from datetime import datetime

import pytest
from httpx import AsyncClient

from app.models.api_token import ApiToken
from app.models.backup import Backup, BackupStatus
from app.models.device import Device
from app.models.device_group import DeviceGroup
from app.models.tenant import Tenant
from app.models.user import User, UserRole
from app.services.api_token_service import ApiTokenService


@pytest.mark.asyncio
async def test_external_api_no_token(async_client: AsyncClient):
    response = await async_client.get("/api/v1/external/groups")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_docs_page_includes_device_id_reference(async_client: AsyncClient):
    response = await async_client.get("/docs")

    assert response.status_code == 200
    assert "Backup Center External API" in response.text
    assert "device_id" in response.text


@pytest.mark.asyncio
async def test_external_group_backups_returns_device_id(async_client: AsyncClient, db_session):
    tenant = Tenant(
        name="Tenant API",
        slug="tenant-api",
        company_name="Tenant API Ltda",
        email="api@example.com",
        is_active=True,
    )
    db_session.add(tenant)
    db_session.flush()

    user = User(
        tenant_id=tenant.id,
        email="owner@example.com",
        password_hash="hash",
        full_name="Owner",
        role=UserRole.TENANT_OWNER,
        is_active=True,
        email_verified=True,
    )
    db_session.add(user)
    db_session.flush()

    group = DeviceGroup(
        tenant_id=tenant.id,
        name="Grupo API",
        slug="grupo-api",
        is_active=True,
    )
    db_session.add(group)
    db_session.flush()

    device = Device(
        tenant_id=tenant.id,
        group_id=group.id,
        name="Device API",
        ip_address="10.0.0.10",
        port=22,
        username="admin",
        password_encrypted="encrypted",
        is_active=True,
        last_backup_status="success",
    )
    db_session.add(device)
    db_session.flush()

    backup = Backup(
        device_id=device.id,
        status=BackupStatus.SUCCESS,
        file_path="tenant/device/backup.bin",
        file_size_bytes=1024,
        hash_sha256="a" * 64,
        created_at=datetime(2026, 5, 14, 12, 0, 0),
    )
    db_session.add(backup)
    db_session.commit()

    _, raw_token = ApiTokenService.create_token(
        db_session,
        tenant_id=tenant.id,
        user_id=user.id,
        name="Docs Test",
    )

    response = await async_client.get(
        f"/api/v1/external/groups/{group.id}/backups",
        headers={"Authorization": f"Bearer {raw_token}"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["group"] == "Grupo API"
    assert payload["total"] == 1
    assert payload["items"][0]["id"] == str(backup.id)
    assert payload["items"][0]["device_id"] == str(device.id)
    assert payload["items"][0]["device_name"] == "Device API"


@pytest.mark.asyncio
async def test_external_api_only_exposes_devices_with_latest_backup_success(async_client: AsyncClient, db_session):
    tenant = Tenant(
        name="Tenant API Success Only",
        slug="tenant-api-success-only",
        company_name="Tenant API Success Only Ltda",
        email="api-success@example.com",
        is_active=True,
    )
    db_session.add(tenant)
    db_session.flush()

    user = User(
        tenant_id=tenant.id,
        email="owner-success@example.com",
        password_hash="hash",
        full_name="Owner",
        role=UserRole.TENANT_OWNER,
        is_active=True,
        email_verified=True,
    )
    db_session.add(user)
    db_session.flush()

    group = DeviceGroup(
        tenant_id=tenant.id,
        name="Grupo API Success",
        slug="grupo-api-success",
        is_active=True,
    )
    db_session.add(group)
    db_session.flush()

    ok_device = Device(
        tenant_id=tenant.id,
        group_id=group.id,
        name="Device OK",
        ip_address="10.0.0.11",
        port=22,
        username="admin",
        password_encrypted="encrypted",
        is_active=True,
        last_backup_status="success",
    )
    failed_latest_device = Device(
        tenant_id=tenant.id,
        group_id=group.id,
        name="Device Ultimo Falhou",
        ip_address="10.0.0.12",
        port=22,
        username="admin",
        password_encrypted="encrypted",
        is_active=True,
        last_backup_status="failure",
    )
    db_session.add_all([ok_device, failed_latest_device])
    db_session.flush()

    ok_backup = Backup(
        device_id=ok_device.id,
        status=BackupStatus.SUCCESS,
        file_path="tenant/ok/backup.bin",
        created_at=datetime(2026, 5, 14, 12, 0, 0),
    )
    hidden_backup = Backup(
        device_id=failed_latest_device.id,
        status=BackupStatus.SUCCESS,
        file_path="tenant/failed-latest/backup.bin",
        created_at=datetime(2026, 5, 14, 13, 0, 0),
    )
    db_session.add_all([ok_backup, hidden_backup])
    db_session.commit()

    _, raw_token = ApiTokenService.create_token(
        db_session,
        tenant_id=tenant.id,
        user_id=user.id,
        name="Success Only Test",
    )

    headers = {"Authorization": f"Bearer {raw_token}"}
    groups_response = await async_client.get("/api/v1/external/groups", headers=headers)
    assert groups_response.status_code == 200
    group_payload = groups_response.json()
    assert group_payload["groups"][0]["device_count"] == 1

    backups_response = await async_client.get(
        f"/api/v1/external/groups/{group.id}/backups",
        headers=headers,
    )
    assert backups_response.status_code == 200
    backups_payload = backups_response.json()
    assert backups_payload["total"] == 1
    assert backups_payload["items"][0]["device_id"] == str(ok_device.id)
    assert backups_payload["items"][0]["id"] == str(ok_backup.id)
