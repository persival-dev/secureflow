"""
Тесты CRUD для уязвимостей.

Все эндпоинты требуют авторизации — используем фикстуру auth_headers.
"""
import uuid

import pytest
from httpx import AsyncClient

VALID_PAYLOAD = {
    "title": "SQL Injection in login",
    "description": "User input passed unsanitized to SQL query.",
    "severity": "critical",
    "cvss": 9.8,
    "cwe": 89,
    "cve_id": "CVE-2024-12345",
}


# ---------- Auth guards ----------

@pytest.mark.asyncio
async def test_create_without_token_returns_401(
    client: AsyncClient, sample_project
) -> None:
    """Без токена создание запрещено."""
    payload = {**VALID_PAYLOAD, "project_id": str(sample_project.id)}
    response = await client.post("/api/v1/vulnerabilities", json=payload)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_list_without_token_returns_401(client: AsyncClient) -> None:
    """Без токена список недоступен."""
    response = await client.get("/api/v1/vulnerabilities")
    assert response.status_code == 401


# ---------- POST ----------

@pytest.mark.asyncio
async def test_create_vulnerability(
    client: AsyncClient, auth_headers, sample_project
) -> None:
    payload = {**VALID_PAYLOAD, "project_id": str(sample_project.id)}
    response = await client.post(
        "/api/v1/vulnerabilities", json=payload, headers=auth_headers
    )

    assert response.status_code == 201
    data = response.json()
    assert data["title"] == VALID_PAYLOAD["title"]
    assert data["severity"] == "critical"
    assert data["status"] == "open"
    assert data["project_id"] == str(sample_project.id)
    assert "id" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_create_with_nonexistent_project_returns_404(
    client: AsyncClient, auth_headers,
) -> None:
    payload = {**VALID_PAYLOAD, "project_id": str(uuid.uuid4())}
    response = await client.post(
        "/api/v1/vulnerabilities", json=payload, headers=auth_headers
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_create_with_invalid_severity_returns_422(
    client: AsyncClient, auth_headers, sample_project
) -> None:
    payload = {
        **VALID_PAYLOAD,
        "severity": "SUPER_CRITICAL",
        "project_id": str(sample_project.id),
    }
    response = await client.post(
        "/api/v1/vulnerabilities", json=payload, headers=auth_headers
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_with_invalid_cvss_returns_422(
    client: AsyncClient, auth_headers, sample_project
) -> None:
    payload = {
        **VALID_PAYLOAD,
        "cvss": 15.0,
        "project_id": str(sample_project.id),
    }
    response = await client.post(
        "/api/v1/vulnerabilities", json=payload, headers=auth_headers
    )
    assert response.status_code == 422


# ---------- GET ----------

@pytest.mark.asyncio
async def test_get_vulnerability_by_id(
    client: AsyncClient, auth_headers, sample_project
) -> None:
    create = await client.post(
        "/api/v1/vulnerabilities",
        json={**VALID_PAYLOAD, "project_id": str(sample_project.id)},
        headers=auth_headers,
    )
    vuln_id = create.json()["id"]

    response = await client.get(
        f"/api/v1/vulnerabilities/{vuln_id}", headers=auth_headers
    )
    assert response.status_code == 200
    assert response.json()["id"] == vuln_id


@pytest.mark.asyncio
async def test_get_nonexistent_returns_404(
    client: AsyncClient, auth_headers
) -> None:
    response = await client.get(
        f"/api/v1/vulnerabilities/{uuid.uuid4()}", headers=auth_headers
    )
    assert response.status_code == 404


# ---------- PATCH ----------

@pytest.mark.asyncio
async def test_partial_update_only_changes_provided_fields(
    client: AsyncClient, auth_headers, sample_project
) -> None:
    create = await client.post(
        "/api/v1/vulnerabilities",
        json={**VALID_PAYLOAD, "project_id": str(sample_project.id)},
        headers=auth_headers,
    )
    vuln = create.json()

    response = await client.patch(
        f"/api/v1/vulnerabilities/{vuln['id']}",
        json={"status": "triaged"},
        headers=auth_headers,
    )
    assert response.status_code == 200
    updated = response.json()
    assert updated["status"] == "triaged"
    assert updated["title"] == vuln["title"]
    assert updated["severity"] == vuln["severity"]


# ---------- DELETE ----------

@pytest.mark.asyncio
async def test_delete_vulnerability(
    client: AsyncClient, auth_headers, sample_project
) -> None:
    create = await client.post(
        "/api/v1/vulnerabilities",
        json={**VALID_PAYLOAD, "project_id": str(sample_project.id)},
        headers=auth_headers,
    )
    vuln_id = create.json()["id"]

    response = await client.delete(
        f"/api/v1/vulnerabilities/{vuln_id}", headers=auth_headers
    )
    assert response.status_code == 204

    get = await client.get(
        f"/api/v1/vulnerabilities/{vuln_id}", headers=auth_headers
    )
    assert get.status_code == 404


# ---------- List ----------

@pytest.mark.asyncio
async def test_list_returns_pagination_metadata(
    client: AsyncClient, auth_headers, sample_project
) -> None:
    for i in range(3):
        await client.post(
            "/api/v1/vulnerabilities",
            json={
                **VALID_PAYLOAD,
                "title": f"Issue #{i}",
                "project_id": str(sample_project.id),
            },
            headers=auth_headers,
        )

    response = await client.get(
        "/api/v1/vulnerabilities?limit=2&offset=0", headers=auth_headers
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 2
    assert data["total"] == 3
    assert data["limit"] == 2
    assert data["offset"] == 0