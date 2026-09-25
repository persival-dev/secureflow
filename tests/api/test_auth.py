"""
Тесты аутентификации: регистрация, логин, refresh, /me.
"""
import uuid
import pytest
from httpx import AsyncClient
from app.core.security import create_access_token, create_refresh_token
# ---------- /auth/register ----------
@pytest.mark.asyncio
async def test_register_creates_user(client: AsyncClient) -> None:
    payload = {
        "email": f"new-{uuid.uuid4().hex[:8]}@example.com",
        "password": "StrongPass123!",
        "full_name": "New User",
    }
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == payload["email"]
    assert data["role"] == "developer"
    assert data["is_active"] is True
    assert "hashed_password" not in data
    assert "password" not in data

@pytest.mark.asyncio
async def test_register_duplicate_email_returns_409(
    client: AsyncClient, test_user
) -> None:
    payload = {
        "email": test_user.email,
        "password": "Another123!",
    }
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 409

@pytest.mark.asyncio
async def test_register_short_password_returns_422(client: AsyncClient) -> None:
    payload = {
        "email": f"x-{uuid.uuid4().hex[:8]}@example.com",
        "password": "short",
    }
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_register_invalid_email_returns_422(client: AsyncClient) -> None:
    payload = {
        "email": "not-an-email",
        "password": "StrongPass123!",
    }
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422

# ---------- /auth/login ----------
@pytest.mark.asyncio
async def test_login_success_returns_token_pair(
    client: AsyncClient, test_user
) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        data={
            "username": test_user.email,
            "password": "TestPassword123!",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 900

@pytest.mark.asyncio
async def test_login_wrong_password_returns_401(
    client: AsyncClient, test_user
) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        data={
            "username": test_user.email,
            "password": "WrongPassword999!",
        },
    )
    assert response.status_code == 401
    assert "password" not in response.json()["detail"].lower() or \
           response.json()["detail"] == "Invalid email or password"

@pytest.mark.asyncio
async def test_login_nonexistent_email_returns_401(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        data={
            "username": f"ghost-{uuid.uuid4().hex[:8]}@example.com",
            "password": "AnyPassword123!",
        },
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"

# ---------- /auth/me ----------
@pytest.mark.asyncio
async def test_me_with_valid_token(
    auth_client: AsyncClient, test_user
) -> None:
    response = await auth_client.get("/api/v1/auth/me")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(test_user.id)
    assert data["email"] == test_user.email

@pytest.mark.asyncio
async def test_me_without_token_returns_401(client: AsyncClient) -> None:
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_me_with_invalid_token_returns_401(client: AsyncClient) -> None:
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer not.a.valid.jwt"},
    )
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_me_with_refresh_token_returns_401(
    client: AsyncClient, test_user
) -> None:
    """
    Refresh-токен НЕ должен работать как access.
    Проверяем защиту от подмены типа токена.
    """
    refresh = create_refresh_token(test_user.id)
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {refresh}"},
    )
    assert response.status_code == 401

# ---------- /auth/refresh ----------
@pytest.mark.asyncio
async def test_refresh_returns_new_pair(
    client: AsyncClient, test_user
) -> None:
    refresh = create_refresh_token(test_user.id)
    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data

@pytest.mark.asyncio
async def test_refresh_with_access_token_returns_401(
    client: AsyncClient, test_user
) -> None:
    """Access нельзя использовать как refresh — обратная защита."""
    access = create_access_token(test_user.id)
    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": access},
    )
    assert response.status_code == 401