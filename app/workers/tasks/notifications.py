"""
Celery-задачи для уведомлений.

Задачи, отправляющие сообщения во внешние системы
(Telegram, Slack, email). Не блокируют HTTP-запросы.
"""
import asyncio
import logging
import uuid

from app.db.worker_session import WorkerSessionLocal
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import SeverityLevel, Vulnerability
from app.services.notification import NotificationService
from app.workers.celery_app import celery_app

from sqlalchemy import select
from sqlalchemy.orm import selectinload
logger = logging.getLogger(__name__)


# Эмодзи для уровня критичности — для визуальной сортировки в чате
_SEVERITY_EMOJI = {
    SeverityLevel.CRITICAL: "🔴",
    SeverityLevel.HIGH: "🟠",
    SeverityLevel.MEDIUM: "🟡",
    SeverityLevel.LOW: "🔵",
    SeverityLevel.INFO: "⚪",
}


@celery_app.task(
    name="notifications.notify_scan_completed",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
)
def notify_scan_completed(self, scan_id: str) -> dict[str, str | bool]:
    """
    Отправляет уведомление в Telegram о завершении скана.

    Аргумент — scan_id (str, потому что Celery передаёт через JSON).

    Retry: до 2 раз с интервалом 30с. Полезно для transient-ошибок
    (сеть моргнула, Telegram отдал 503).
    """
    logger.info("Notification task started: scan_id=%s", scan_id)
    return asyncio.run(_notify_scan_completed_async(uuid.UUID(scan_id)))


async def _notify_scan_completed_async(scan_id: uuid.UUID) -> dict:
    """Async-версия. Читает скан из БД, формирует сообщение, отправляет."""
    async with WorkerSessionLocal() as session:
        stmt = (
            select(Scan)
            .options(selectinload(Scan.project))
            .where(Scan.id == scan_id)
        )
        scan = (await session.execute(stmt)).scalar_one_or_none()
        if scan is None:
            logger.warning("Scan %s not found for notification", scan_id)
            return {"status": "skipped", "reason": "scan not found", "sent": False}
        ...

        # Формируем текст сообщения
        text = await _format_scan_message(session, scan)

        # Отправляем
        notifier = NotificationService()
        sent = await notifier.send_telegram(text)

        return {
            "status": "ok" if sent else "skipped",
            "scan_id": str(scan_id),
            "sent": sent,
        }


async def _format_scan_message(session, scan: Scan) -> str:
    """
    Формирует HTML-сообщение для Telegram.

    Пример:
        🔍 <b>Scan completed</b>

        Project: <code>backend-api</code>
        Scanner: <code>bandit</code>
        Status: ✅ success
        Findings: <b>10</b>

        🟠 high: SQL Injection in login
        🟠 high: Weak MD5 hash
        🟡 medium: Pickle deserialization
        ... (топ-5)
    """
    from sqlalchemy import select

    # Топ-5 находок по severity
    stmt = (
        select(Vulnerability)
        .where(Vulnerability.scan_id == scan.id)
        .order_by(Vulnerability.severity.desc())
        .limit(5)
    )
    top_vulns = list((await session.execute(stmt)).scalars().all())

    # Проект (для отображения slug)
    project = scan.project  # loaded via lazy="selectin"
    project_name = project.slug if project else "unknown"

    # Иконка статуса
    status_icon = "✅" if scan.status == ScanStatus.SUCCESS else "❌"

    lines = [
        "🔍 <b>Scan completed</b>",
        "",
        f"Project: <code>{project_name}</code>",
        f"Scanner: <code>{scan.scanner}</code>",
        f"Target: <code>{scan.target}</code>",
        f"Status: {status_icon} {scan.status.value}",
        f"Findings: <b>{scan.findings_count}</b>",
    ]

    if scan.error_message:
        lines.append(f"Error: <code>{scan.error_message[:200]}</code>")

    if top_vulns:
        lines.append("")
        lines.append("<b>Top findings:</b>")
        for v in top_vulns:
            emoji = _SEVERITY_EMOJI.get(v.severity, "•")
            # Экранируем HTML-спецсимволы в title, чтобы Telegram не ругался
            title = _escape_html(v.title[:80])
            lines.append(f"{emoji} {title}")

    return "\n".join(lines)


def _escape_html(text: str) -> str:
    """Экранирует < > & в тексте — обязательное требование Telegram HTML."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )