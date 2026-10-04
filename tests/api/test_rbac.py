"""
Тесты ролевой модели (RBAC).

Проверяем матрицу доступа:
- DEVELOPER не может создавать/удалять уязвимости, но видит их.
- SECURITY может всё с уязвимостями.
- ADMIN может всё + управлять юзерами.
"""

import pytest
from httpx import AsyncClient

from app.core.security import create_access_token
from app.models.user import User

VALID_PAYLOAD = {
    "title": "Test Vuln",
    "description": "This is a test vulnerability description.",
    "severity": "high",
    "cvss": 8.0,
}

def _headers(user: User) -> dict[str, str]:
    """Authorization header для конкретного юзера."""
    return {"Authorization": f"Bearer {create_access_token(user.id)}"}

# ---------- DEVELOPER: может смотреть, не может создавать/удалять ----------
@pytest.mark.asyncio
async def test_developer_can_list_vulnerabilities(
    client: AsyncClient, developer_user, sample_project
) -> None:
    response = await client.get(
        "/api/v1/vulnerabilities", headers=_headers(developer_user)
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_developer_cannot_create_vulnerability(
    client: AsyncClient, developer_user, sample_project
) -> None:
    payload = {**VALID_PAYLOAD, "project_id": str(sample_project.id)}
    response = await client.post(
        "/api/v1/vulnerabilities",
        json=payload,
        headers=_headers(developer_user),
    )
    assert response.status_code == 403

# ---------- SECURITY: может всё с уязвимостями ----------
@pytest.mark.asyncio
async def test_security_can_create_vulnerability(
    client: AsyncClient, security_user, sample_project
) -> None:
    payload = {**VALID_PAYLOAD, "project_id": str(sample_project.id)}
    response = await client.post(
        "/api/v1/vulnerabilities",
        json=payload,
        headers=_headers(security_user),
    )
    assert response.status_code == 201

@pytest.mark.asyncio
async def test_security_can_delete_vulnerability(
    client: AsyncClient, security_user, sample_project
) -> None:
    create = await client.post(
        "/api/v1/vulnerabilities",
        json={**VALID_PAYLOAD, "project_id": str(sample_project.id)},
        headers=_headers(security_user),
    )
    vuln_id = create.json()["id"]

    response = await client.delete(
        f"/api/v1/vulnerabilities/{vuln_id}",
        headers=_headers(security_user),
    )
    assert response.status_code == 204


# ---------- ADMIN: может управлять юзерами ----------
@pytest.mark.asyncio
async def test_admin_can_list_users(
    client: AsyncClient, admin_user
) -> None:
    response = await client.get(
        "/api/v1/users", headers=_headers(admin_user)
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_security_cannot_list_users(
    client: AsyncClient, security_user
) -> None:
    """SECURITY не имеет доступа к управлению юзерами."""
    response = await client.get(
        "/api/v1/users", headers=_headers(security_user)
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_developer_cannot_list_users(
    client: AsyncClient, developer_user
) -> None:
    response = await client.get(
        "/api/v1/users", headers=_headers(developer_user)
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_change_role(
    client: AsyncClient, admin_user, developer_user
) -> None:
    response = await client.patch(
        f"/api/v1/users/{developer_user.id}",
        json={"role": "security"},
        headers=_headers(admin_user),
    )
    assert response.status_code == 200
    assert response.json()["role"] == "security"


@pytest.mark.asyncio
async def test_admin_cannot_modify_self(
    client: AsyncClient, admin_user
) -> None:
    """Защита от self-lockout — админ не может менять себя."""
    response = await client.patch(
        f"/api/v1/users/{admin_user.id}",
        json={"role": "developer"},
        headers=_headers(admin_user),
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_admin_cannot_deactivate_self(
    client: AsyncClient, admin_user
) -> None:
    response = await client.delete(
        f"/api/v1/users/{admin_user.id}",
        headers=_headers(admin_user),
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_deactivated_user_cannot_use_token(
    client: AsyncClient, admin_user, developer_user
) -> None:
    """
    Деактивированный юзер не может ходить с валидным токеном.

    Токен ещё не истёк, но is_active=False — get_current_user отсечёт.
    """
    r1 = await client.get(
        "/api/v1/vulnerabilities", headers=_headers(developer_user)
    )
    assert r1.status_code == 200

    r2 = await client.delete(
        f"/api/v1/users/{developer_user.id}",
        headers=_headers(admin_user),
    )
    assert r2.status_code == 204

    r3 = await client.get(
        "/api/v1/vulnerabilities", headers=_headers(developer_user)
    )
    assert r3.status_code == 401