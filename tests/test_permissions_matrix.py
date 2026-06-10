import uuid

import pytest

from app import create_flask_app
from app.core.database import SessionLocal
from app.models.tenant import Tenant
from app.models.user import UserRole


@pytest.fixture
def flask_client():
    app = create_flask_app()
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def tenant_slug():
    slug = "tenant-perm-test"
    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.slug == slug).first()
        if not tenant:
            tenant = Tenant(
                id=uuid.uuid4(),
                slug=slug,
                name="Tenant Permissao",
                email="tenant-perm@test.local",
                is_active=True,
            )
            db.add(tenant)
            db.commit()
        return slug
    finally:
        db.close()


def _login_session(client, role: UserRole, tenant_slug: str):
    with client.session_transaction() as sess:
        sess["user_id"] = str(uuid.uuid4())
        sess["user_role"] = role.value
        sess["tenant_slug"] = tenant_slug
        sess["_csrf_token"] = "csrf-test-token"


def test_api_tokens_requires_admin(flask_client, tenant_slug):
    _login_session(flask_client, UserRole.TENANT_TECHNICIAN, tenant_slug)
    response = flask_client.get(f"/tenant/{tenant_slug}/settings/api-tokens/", follow_redirects=False)
    assert response.status_code in (302, 303)


def test_api_tokens_allows_admin(flask_client, tenant_slug):
    _login_session(flask_client, UserRole.TENANT_ADMIN, tenant_slug)
    response = flask_client.get(f"/tenant/{tenant_slug}/settings/api-tokens/", follow_redirects=False)
    assert response.status_code == 200


def test_billing_requires_master(flask_client, tenant_slug):
    _login_session(flask_client, UserRole.TENANT_ADMIN, tenant_slug)
    response = flask_client.get(f"/tenant/{tenant_slug}/billing/", follow_redirects=False)
    assert response.status_code in (302, 303)


def test_billing_allows_master(flask_client, tenant_slug):
    _login_session(flask_client, UserRole.TENANT_OWNER, tenant_slug)
    response = flask_client.get(f"/tenant/{tenant_slug}/billing/", follow_redirects=False)
    assert response.status_code == 200


def test_schedule_apply_requires_admin(flask_client, tenant_slug):
    _login_session(flask_client, UserRole.TENANT_TECHNICIAN, tenant_slug)
    response = flask_client.post(
        f"/tenant/{tenant_slug}/schedules/apply-daily",
        data={
            "_csrf_token": "csrf-test-token",
            "daily_time": "02:00",
            "apply_scope": "missing",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 303)
