import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_login_invalid_credentials(async_client: AsyncClient):
    response = await async_client.post(
        "/api/v1/auth/login",
        data={"username": "wrong@example.com", "password": "wrongpassword"}
    )
    # The current login is via form data / API endpoint or Flask
    # This expects a 401 or similar (unauthorized) or 400
    assert response.status_code in [400, 401]
