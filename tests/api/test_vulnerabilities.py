"""
Тесты CRUD для уязвимостей.
"""
import uuid

import pytest
from httpx import AsyncClient

from app.models.vulnerability import SeverityLevel, VulnerabilityStatus


VALID_PAYLOAD = {
    "title": "SQL Injection in login",
    "description": "User input passed unsanitized to SQL query.",
    "severity": "critical",
    "cvss": 9.8,
    "cwe": 89,
    "cve_id": "CVE-2024-12345",
}


# ---------- POST ----------

@pytest.mark.asyncio
async def test_create_vulnerability(client: AsyncClient, sample_project) -> None:
    payload = {**VALID_PAYLOAD, "project_id": str(sample_project.id)}
    response = await client.post("/api/v1/vulnerabilities", json=payload)

    assert response.status_code == 201
    data = response.json()
    assert data["title"] == VALID_PAYLOAD["title"]
    assert data["severity"] == "critical"
    assert data["status"] == "open"          # default из модели
    assert data["project_id"] == str(sample_project.id)
    assert "id" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_create_with_nonexistent_project_returns_404(
    client: AsyncClient,
) -> None:
    payload = {**VALID_PAYLOAD, "project_id": str(uuid.uuid4())}
    response = await client.post("/api/v1/vulnerabilities", json=payload)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_create_with_invalid_severity_returns_422(
    client: AsyncClient, sample_project
) -> None:
    payload = {
        **VALID_PAYLOAD,
        "severity": "SUPER_CRITICAL",   # не из enum
        "project_id": str(sample_project.id),
    }
    response = await client.post("/api/v1/vulnerabilities", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_with_invalid_cvss_returns_422(
    client: AsyncClient, sample_project
) -> None:
    payload = {
        **VALID_PAYLOAD,
        "cvss": 15.0,   # > 10
        "project_id": str(sample_project.id),
    }
    response = await client.post("/api/v1/vulnerabilities", json=payload)
    assert response.status_code == 422


# ---------- GET ----------

@pytest.mark.asyncio
async def test_get_vulnerability_by_id(
    client: AsyncClient, sample_project
) -> None:
    create = await client.post(
        "/api/v1/vulnerabilities",
        json={**VALID_PAYLOAD, "project_id": str(sample_project.id)},
    )
    vuln_id = create.json()["id"]

    response = await client.get(f"/api/v1/vulnerabilities/{vuln_id}")
    assert response.status_code == 200
    assert response.json()["id"] == vuln_id


@pytest.mark.asyncio
async def test_get_nonexistent_returns_404(client: AsyncClient) -> None:
    response = await client.get(f"/api/v1/vulnerabilities/{uuid.uuid4()}")
    assert response.status_code == 404


# ---------- PATCH ----------

@pytest.mark.asyncio
async def test_partial_update_only_changes_provided_fields(
    client: AsyncClient, sample_project
) -> None:
    create = await client.post(
        "/api/v1/vulnerabilities",
        json={**VALID_PAYLOAD, "project_id": str(sample_project.id)},
    )
    vuln = create.json()

    response = await client.patch(
        f"/api/v1/vulnerabilities/{vuln['id']}",
        json={"status": "triaged"},
    )
    assert response.status_code == 200
    updated = response.json()
    assert updated["status"] == "triaged"
    assert updated["title"] == vuln["title"]
    assert updated["severity"] == vuln["severity"]


# ---------- DELETE ----------

@pytest.mark.asyncio
async def test_delete_vulnerability(
    client: AsyncClient, sample_project
) -> None:
    create = await client.post(
        "/api/v1/vulnerabilities",
        json={**VALID_PAYLOAD, "project_id": str(sample_project.id)},
    )
    vuln_id = create.json()["id"]

    response = await client.delete(f"/api/v1/vulnerabilities/{vuln_id}")
    assert response.status_code == 204

    get = await client.get(f"/api/v1/vulnerabilities/{vuln_id}")
    assert get.status_code == 404


# ---------- List + filters ----------

@pytest.mark.asyncio
async def test_list_returns_pagination_metadata(
    client: AsyncClient, sample_project
) -> None:
    for i in range(3):
        await client.post(
            "/api/v1/vulnerabilities",
            json={
                **VALID_PAYLOAD,
                "title": f"Issue #{i}",
                "project_id": str(sample_project.id),
            },
        )

    response = await client.get("/api/v1/vulnerabilities?limit=2&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 2
    assert data["total"] == 3
    assert data["limit"] == 2
    assert data["offset"] == 0