"""
Тесты PDF-отчёта.

WeasyPrint мокается — мы проверяем контракт эндпоинта,
а не рендеринг (для него нужны системные либы, которых нет локально).
"""
import uuid
from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import SeverityLevel, Vulnerability


@pytest_asyncio.fixture
async def sample_scan_with_vulns(
    db_session: AsyncSession, sample_project
) -> Scan:
    """Скан + 2 уязвимости для PDF-теста."""
    scan = Scan(
        project_id=sample_project.id,
        scanner="bandit",
        target="/app/demo/vulnerable_code.py",
        status=ScanStatus.SUCCESS,
        findings_count=2,
    )
    db_session.add(scan)
    await db_session.flush()
    await db_session.refresh(scan)

    for title, severity, cwe in [
        ("SQL Injection", SeverityLevel.CRITICAL, 89),
        ("Weak hash", SeverityLevel.HIGH, 327),
    ]:
        db_session.add(
            Vulnerability(
                title=title,
                description=f"Description for {title}",
                severity=severity,
                cwe=cwe,
                project_id=sample_project.id,
                scan_id=scan.id,
                scanner="bandit",
            )
        )
    await db_session.flush()
    return scan


@pytest.mark.asyncio
async def test_pdf_endpoint_returns_pdf(
    auth_client: AsyncClient, sample_scan_with_vulns: Scan
) -> None:
    fake_pdf_bytes = b"%PDF-1.4 fake pdf content"

    with patch("app.services.report.render_pdf_from_html", return_value=fake_pdf_bytes):
        response = await auth_client.get(
            f"/api/v1/scans/{sample_scan_with_vulns.id}/report.pdf"
        )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content == fake_pdf_bytes
    disposition = response.headers["content-disposition"]
    assert "attachment" in disposition
    assert str(sample_scan_with_vulns.id) in disposition


@pytest.mark.asyncio
async def test_pdf_endpoint_returns_404_for_missing_scan(
    auth_client: AsyncClient,
) -> None:
    """Несуществующий скан → 404."""
    response = await auth_client.get(f"/api/v1/scans/{uuid.uuid4()}/report.pdf")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_pdf_endpoint_requires_auth(client: AsyncClient) -> None:
    """Без токена → 401."""
    response = await client.get(f"/api/v1/scans/{uuid.uuid4()}/report.pdf")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_pdf_endpoint_returns_503_when_weasyprint_missing(
    auth_client: AsyncClient, sample_scan_with_vulns: Scan
) -> None:
    """
    Если WeasyPrint не установлен (например, локально без extra [reports]) →
    503 Service Unavailable, а не 500.
    """
    with patch(
        "app.services.report.render_pdf_from_html",
        side_effect=RuntimeError("WeasyPrint is not installed"),
    ):
        response = await auth_client.get(
            f"/api/v1/scans/{sample_scan_with_vulns.id}/report.pdf"
        )

    assert response.status_code == 503
    assert "WeasyPrint" in response.json()["detail"]