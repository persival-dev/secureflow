"""
Сервис генерации HTML-отчёта по скану.

Отчёт — самодостаточный HTML с инлайн-CSS. Никаких внешних CDN,
чтобы работал офлайн и в корпоративных сетях без интернета.
"""
import uuid
from collections import Counter
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.scan import Scan
from app.models.vulnerability import Vulnerability

# templates/ лежит рядом с app/ — путь от корня проекта
_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

# Один Environment на весь процесс. autoescape=True критично —
# без него пользовательский title уязвимости = XSS в отчёте.
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


class ReportService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def render_scan_report(self, scan_id: uuid.UUID) -> str | None:
        """
        Возвращает HTML-строку отчёта или None, если скан не найден.
        """
        stmt = (
            select(Scan)
            .options(selectinload(Scan.project))
            .where(Scan.id == scan_id)
        )
        scan = (await self.session.execute(stmt)).scalar_one_or_none()
        if scan is None:
            return None

        vuln_stmt = (
            select(Vulnerability)
            .where(Vulnerability.scan_id == scan_id)
            # Сначала критичные, потом по CVSS (если есть), потом по дате
            .order_by(
                Vulnerability.severity.desc(),
                Vulnerability.created_at.desc(),
            )
        )
        vulnerabilities = list((await self.session.execute(vuln_stmt)).scalars().all())

        # Статистика по severity. Counter — удобно и читаемо.
        severity_counts = Counter(v.severity.value for v in vulnerabilities)
        # Гарантируем, что все ключи есть (даже с нулями)
        for level in ("critical", "high", "medium", "low", "info"):
            severity_counts.setdefault(level, 0)

        template = _env.get_template("report.html")
        return template.render(
            scan=scan,
            project=scan.project,
            vulnerabilities=vulnerabilities,
            total=len(vulnerabilities),
            severity_counts=severity_counts,
        )