import uuid

import pytest

from app import create_flask_app
from app.core.database import SessionLocal
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


@pytest.fixture
def seeded_users_search_data():
    tenant_slug = f"tenant-users-search-{uuid.uuid4().hex[:8]}"
    db = SessionLocal()
    try:
        tenant = Tenant(
            id=uuid.uuid4(),
            slug=tenant_slug,
            name="Tenant Busca Usuarios",
            email=f"{tenant_slug}@test.local",
            is_active=True,
        )
        users = [
            User(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                email="ana@example.local",
                full_name="Ana Souza",
                password_hash="hash",
                role=UserRole.TENANT_OWNER,
                is_active=True,
            ),
            User(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                email="bruno.netops@example.local",
                full_name="Bruno NOC",
                password_hash="hash",
                role=UserRole.TENANT_ADMIN,
                is_active=True,
            ),
        ]
        db.add(tenant)
        for user in users:
            db.add(user)
        db.commit()
        return {"tenant_slug": tenant_slug}
    finally:
        db.close()


def test_users_search_filters_by_name_and_email(flask_client, seeded_users_search_data):
    tenant_slug = seeded_users_search_data["tenant_slug"]
    _login_session(flask_client, UserRole.TENANT_OWNER, tenant_slug)

    response_page = flask_client.get(f"/tenant/{tenant_slug}/users/", follow_redirects=False)
    html_page = response_page.get_data(as_text=True)
    assert response_page.status_code == 200
    assert 'id="users-search"' not in html_page
    assert 'name="q"' in html_page

    response_name = flask_client.get(f"/tenant/{tenant_slug}/users/?q=Ana", follow_redirects=False)
    html_name = response_name.get_data(as_text=True)
    assert response_name.status_code == 200
    assert "Ana Souza" in html_name
    assert "Bruno NOC" not in html_name

    response_email = flask_client.get(f"/tenant/{tenant_slug}/users/?q=netops", follow_redirects=False)
    html_email = response_email.get_data(as_text=True)
    assert response_email.status_code == 200
    assert "Bruno NOC" in html_email
    assert "Ana Souza" not in html_email
