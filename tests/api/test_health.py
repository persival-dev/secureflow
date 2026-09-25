"""
Тесты health/ready эндпоинтов.
"""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_returns_ok(client: AsyncClient) -> None:
    """Liveness-проверка не требует БД и всегда возвращает 200."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert "service" in data
    assert "environment" in data


@pytest.mark.asyncio
async def test_ready_checks_database(client: AsyncClient) -> None:
    """Readiness-проверка должна достучаться до БД."""
    response = await client.get("/api/v1/ready")
    # Если Postgres поднят — 200. Если нет — 503.
    # В CI с docker-compose — 200.
    assert response.status_code == 200
    assert response.json()["database"] == "ok"