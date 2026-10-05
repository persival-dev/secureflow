"""Тесты UI-страниц (server-rendered HTML)."""

import uuid

from httpx import AsyncClient

from app.core.security import create_access_token
from app.models.user import User
from app.ui.deps import COOKIE_NAME

# Пароль из фикстуры test_user (tests/conftest.py)
TEST_USER_PASSWORD = "TestPassword123!"


def _auth_cookie(user: User) -> dict[str, str]:
    """Cookie для UI-аутентификации (в обход формы логина)."""
    token = create_access_token(subject=str(user.id))
    return {COOKIE_NAME: token}


# ---------- Login ----------

async def test_login_page_returns_html(client: AsyncClient) -> None:
    """GET /ui/login без cookie → 200 + HTML."""
    response = await client.get("/ui/login")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Вход" in response.text


async def test_login_success_sets_cookie(
    client: AsyncClient, test_user: User
) -> None:
    """POST /ui/login с верным паролем → 303 + HttpOnly cookie."""
    response = await client.post(
        "/ui/login",
        data={"email": test_user.email, "password": TEST_USER_PASSWORD},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    assert response.headers["location"] == "/ui/scans"
    assert COOKIE_NAME in response.cookies


async def test_login_wrong_password_returns_401(
    client: AsyncClient, test_user: User
) -> None:
    """POST /ui/login с неверным паролем → 401 + HTML с ошибкой."""
    response = await client.post(
        "/ui/login",
        data={"email": test_user.email, "password": "WRONG_PASSWORD"},
    )
    assert response.status_code == 401
    assert "Неверный email или пароль" in response.text


# ---------- Scans list ----------

async def test_scans_requires_auth(client: AsyncClient) -> None:
    """GET /ui/scans без cookie → 401."""
    response = await client.get("/ui/scans")
    assert response.status_code == 401


async def test_scans_with_auth_returns_html(
    client: AsyncClient, test_user: User
) -> None:
    """GET /ui/scans с валидной cookie → 200 HTML."""
    client.cookies.update(_auth_cookie(test_user))
    response = await client.get("/ui/scans")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Сканы" in response.text


async def test_scans_create_route_not_shadowed_by_uuid(
    client: AsyncClient, test_user: User
) -> None:
    """GET /ui/scans/create → 200 (форма), НЕ 422. Регрессия на порядок роутов."""
    client.cookies.update(_auth_cookie(test_user))
    response = await client.get("/ui/scans/create")
    assert response.status_code == 200, response.text
    assert "Запустить скан" in response.text


async def test_scans_detail_not_found_returns_404(
    client: AsyncClient, test_user: User
) -> None:
    """GET /ui/scans/{несуществующий uuid} → 404."""
    client.cookies.update(_auth_cookie(test_user))
    response = await client.get(f"/ui/scans/{uuid.uuid4()}")
    assert response.status_code == 404