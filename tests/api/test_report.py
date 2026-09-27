"""
Тесты HTML-отчёта по скану.
"""
import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import SeverityLevel, Vulnerability


@pytest_asyncio.fixture
async def sample_scan_with_vulns(
    db_session: AsyncSession, sample_project
) -> tuple[Scan, list[Vulnerability]]:
    """
    Создаёт скан + 3 уязвимости с разными severity.
    Используется в тестах отчёта.
    """
    scan = Scan(
        project_id=sample_project.id,
        scanner="bandit",
        target="/app/demo/vulnerable_code.py",
        status=ScanStatus.SUCCESS,
        findings_count=3,
    )
    db_session.add(scan)
    await db_session.flush()
    await db_session.refresh(scan)

    vulns = [
        Vulnerability(
            title="SQL Injection in login",
            description="User input in raw query",
            severity=SeverityLevel.CRITICAL,
            cwe=89,
            project_id=sample_project.id,
            scan_id=scan.id,
            scanner="bandit",
        ),
        Vulnerability(
            title="Weak MD5 hash",
            description="MD5 is deprecated",
            severity=SeverityLevel.HIGH,
            cwe=327,
            project_id=sample_project.id,
            scan_id=scan.id,
            scanner="bandit",
        ),
        Vulnerability(
            title="assert used",
            description="Assert removed with -O",
            severity=SeverityLevel.LOW,
            cwe=703,
            project_id=sample_project.id,
            scan_id=scan.id,
            scanner="bandit",
        ),
    ]
    for v in vulns:
        db_session.add(v)
    await db_session.flush()
    return scan, vulns


@pytest.mark.asyncio
async def test_report_returns_html(
    auth_client: AsyncClient, sample_scan_with_vulns
) -> None:
    """Эндпоинт отдаёт HTML с правильным Content-Type."""
    scan, _ = sample_scan_with_vulns
    response = await auth_client.get(f"/api/v1/scans/{scan.id}/report")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<!DOCTYPE html>" in response.text


@pytest.mark.asyncio
async def test_report_contains_findings(
    auth_client: AsyncClient, sample_scan_with_vulns
) -> None:
    """В HTML попадают все уязвимости скана."""
    scan, _ = sample_scan_with_vulns
    response = await auth_client.get(f"/api/v1/scans/{scan.id}/report")
    body = response.text

    assert "SQL Injection in login" in body
    assert "Weak MD5 hash" in body
    assert "assert used" in body
    # CWE отрисованы как badges
    assert "CWE-89" in body
    assert "CWE-327" in body
    # Severity-классы для CSS
    assert "severity-critical" in body
    assert "severity-high" in body
    assert "severity-low" in body


@pytest.mark.asyncio
async def test_report_does_not_contain_other_scan_findings(
    auth_client: AsyncClient,
    db_session: AsyncSession,
    sample_project,
    sample_scan_with_vulns,
) -> None:
    """Отчёт не должен включать уязвимости из другого скана."""
    scan, _ = sample_scan_with_vulns

    # Создаём вторую уязвимость в другом скане
    other_scan = Scan(
        project_id=sample_project.id,
        scanner="bandit",
        target="/tmp/other.py",
        status=ScanStatus.SUCCESS,
        findings_count=1,
    )
    db_session.add(other_scan)
    await db_session.flush()
    db_session.add(
        Vulnerability(
            title="FOREIGN_SCAN_VULN",
            description="Should not appear",
            severity=SeverityLevel.HIGH,
            project_id=sample_project.id,
            scan_id=other_scan.id,
            scanner="bandit",
        )
    )
    await db_session.flush()

    response = await auth_client.get(f"/api/v1/scans/{scan.id}/report")
    assert "FOREIGN_SCAN_VULN" not in response.text


@pytest.mark.asyncio
async def test_report_for_nonexistent_scan_returns_404(
    auth_client: AsyncClient,
) -> None:
    response = await auth_client.get(f"/api/v1/scans/{uuid.uuid4()}/report")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_report_without_auth_returns_401(
    client: AsyncClient, sample_scan_with_vulns
) -> None:
    scan, _ = sample_scan_with_vulns
    response = await client.get(f"/api/v1/scans/{scan.id}/report")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_report_escapes_html_in_user_input(
    auth_client: AsyncClient,
    db_session: AsyncSession,
    sample_project,
) -> None:
    """
    Проверяем XSS-защиту: title уязвимости с <script> должен
    быть экранирован в HTML (autoescape=True в Jinja2).
    """
    scan = Scan(
        project_id=sample_project.id,
        scanner="bandit",
        target="/tmp/xss.py",
        status=ScanStatus.SUCCESS,
        findings_count=1,
    )
    db_session.add(scan)
    await db_session.flush()

    db_session.add(
        Vulnerability(
            title="<script>alert('xss')</script>",
            description="Attempted XSS",
            severity=SeverityLevel.HIGH,
            project_id=sample_project.id,
            scan_id=scan.id,
            scanner="bandit",
        )
    )
    await db_session.flush()

    response = await auth_client.get(f"/api/v1/scans/{scan.id}/report")
    assert response.status_code == 200
    # Сырой <script> НЕ должен попасть в HTML
    assert "<script>alert('xss')</script>" not in response.text
    # Экранированная версия — должна
    assert "&lt;script&gt;" in response.text