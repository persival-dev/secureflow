"""
Тесты API для сканов.

Celery-задача мокается — мы проверяем поведение API, а не работу worker'а.
Для проверки реального скана есть integration-тесты (позже).
"""
import uuid
from unittest.mock import MagicMock, patch

import pytest
from httpx import AsyncClient

VALID_PAYLOAD_TEMPLATE = {
    "scanner": "bandit",
    "target": "/app/demo/vulnerable_code.py",
}


# ---------- Auth guards ----------

@pytest.mark.asyncio
async def test_create_scan_without_token_returns_401(
    client: AsyncClient, sample_project
) -> None:
    payload = {**VALID_PAYLOAD_TEMPLATE, "project_id": str(sample_project.id)}
    response = await client.post("/api/v1/scans", json=payload)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_create_scan_as_developer_returns_403(
    client: AsyncClient, developer_user, sample_project
) -> None:
    from app.core.security import create_access_token
    headers = {"Authorization": f"Bearer {create_access_token(developer_user.id)}"}

    payload = {**VALID_PAYLOAD_TEMPLATE, "project_id": str(sample_project.id)}
    response = await client.post("/api/v1/scans", json=payload, headers=headers)
    assert response.status_code == 403


# ---------- POST /scans (SECURITY+) ----------

@pytest.mark.asyncio
async def test_create_scan_dispatches_celery_task(
    auth_client: AsyncClient, sample_project
) -> None:
    """
    SECURITY-юзер (auth_headers) создаёт скан.
    Celery.delay() мокается — проверяем, что он был вызван с правильным scan_id.
    """
    payload = {**VALID_PAYLOAD_TEMPLATE, "project_id": str(sample_project.id)}

    with patch("app.services.scan.run_bandit_scan") as mock_task:
        # Задача возвращает объект с полем .id
        mock_task.delay.return_value = MagicMock(id="mock-task-id-123")

        response = await auth_client.post("/api/v1/scans", json=payload)

    assert response.status_code == 202
    data = response.json()
    assert data["scanner"] == "bandit"
    assert data["status"] == "pending"
    assert data["celery_task_id"] == "mock-task-id-123"
    assert data["project_id"] == str(sample_project.id)

    # Проверяем, что задача была отправлена с правильным scan_id
    mock_task.delay.assert_called_once()
    called_scan_id = mock_task.delay.call_args[0][0]
    assert called_scan_id == data["id"]


@pytest.mark.asyncio
async def test_create_scan_for_missing_project_returns_404(
    auth_client: AsyncClient
) -> None:
    payload = {**VALID_PAYLOAD_TEMPLATE, "project_id": str(uuid.uuid4())}

    with patch("app.services.scan.run_bandit_scan") as mock_task:
        response = await auth_client.post("/api/v1/scans", json=payload)

    assert response.status_code == 404
    mock_task.delay.assert_not_called()


@pytest.mark.asyncio
async def test_create_scan_with_invalid_scanner_returns_422(
    auth_client: AsyncClient, sample_project
) -> None:
    payload = {
        "scanner": "not-a-real-scanner",
        "target": "/app/demo/vulnerable_code.py",
        "project_id": str(sample_project.id),
    }
    response = await auth_client.post("/api/v1/scans", json=payload)
    assert response.status_code == 422


# ---------- GET /scans/{id} ----------

@pytest.mark.asyncio
async def test_get_scan_by_id(
    auth_client: AsyncClient, sample_project
) -> None:
    payload = {**VALID_PAYLOAD_TEMPLATE, "project_id": str(sample_project.id)}

    with patch("app.services.scan.run_bandit_scan") as mock_task:
        mock_task.delay.return_value = MagicMock(id="task-id-abc")
        create = await auth_client.post("/api/v1/scans", json=payload)

    scan_id = create.json()["id"]
    response = await auth_client.get(f"/api/v1/scans/{scan_id}")
    assert response.status_code == 200
    assert response.json()["id"] == scan_id


@pytest.mark.asyncio
async def test_get_nonexistent_scan_returns_404(
    auth_client: AsyncClient
) -> None:
    response = await auth_client.get(f"/api/v1/scans/{uuid.uuid4()}")
    assert response.status_code == 404


# ---------- GET /scans (list) ----------

@pytest.mark.asyncio
async def test_list_scans_returns_pagination(
    auth_client: AsyncClient, sample_project
) -> None:
    payload = {**VALID_PAYLOAD_TEMPLATE, "project_id": str(sample_project.id)}

    with patch("app.services.scan.run_bandit_scan") as mock_task:
        mock_task.delay.return_value = MagicMock(id="task-id")
        for _ in range(3):
            await auth_client.post("/api/v1/scans", json=payload)

    response = await auth_client.get("/api/v1/scans?limit=2&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 2
    assert data["total"] == 3