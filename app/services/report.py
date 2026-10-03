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

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

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
            .order_by(
                Vulnerability.severity.desc(),
                Vulnerability.created_at.desc(),
            )
        )
        vulnerabilities = list((await self.session.execute(vuln_stmt)).scalars().all())
        severity_counts = Counter(v.severity.value for v in vulnerabilities)
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
    async def render_scan_report_pdf(self, scan_id: uuid.UUID) -> bytes | None:
        html = await self.render_scan_report(scan_id)
        if html is None:
            return None
        return render_pdf_from_html(html)

def render_pdf_from_html(html: str) -> bytes:
    try:
        from weasyprint import HTML
    except ImportError as e:
        raise RuntimeError(
            "WeasyPrint is not installed. "
            "It's available in Docker via '.[reports]' extra."
        ) from e
    return HTML(string=html, base_url=".").write_pdf()