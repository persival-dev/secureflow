"""
Celery-задачи сканирования.

Каждая задача:
1. Открывает async-сессию (свой worker-engine с NullPool).
2. Загружает Scan, ставит status=running, started_at=now.
3. Запускает сканер (subprocess, отдельный класс).
4. Создаёт Vulnerability-записи.
5. Обновляет Scan: status, findings_count, finished_at.
6. При ошибке: status=failed, error_message.
"""
import asyncio
import logging
import uuid
from datetime import UTC, datetime

from app.db.worker_session import WorkerSessionLocal
from app.models.scan import Scan, ScanStatus
from app.models.vulnerability import Vulnerability
from app.services.scanner import BanditScanner
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


# Маппинг scanner name → класс
_SCANNERS = {
    "bandit": BanditScanner,
}


@celery_app.task(name="scans.ping")
def ping() -> dict[str, str]:
    """Тестовая задача — проверка, что worker жив."""
    return {"status": "pong"}


@celery_app.task(
    name="scans.run_bandit",
    bind=True,
    max_retries=0,
)
def run_bandit_scan(self, scan_id: str) -> dict[str, str | int]:
    """
    Запускает SAST-скан через Celery.

    Аргументы передаются как строки (JSON-сериализация Celery),
    UUID парсим внутри.

    Returns:
        dict с финальным статусом — чтобы можно было посмотреть через AsyncResult.
    """
    logger.info("Task started: scan_id=%s, celery_task_id=%s", scan_id, self.request.id)
    return asyncio.run(_run_scan_async(uuid.UUID(scan_id), self.request.id))


async def _run_scan_async(scan_id: uuid.UUID, celery_task_id: str) -> dict:
    """Async-версия задачи. Вызывается через asyncio.run() из Celery."""
    async with WorkerSessionLocal() as session:
        # 1. Загружаем Scan
        scan = await session.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s not found", scan_id)
            return {"status": "error", "message": "scan not found"}

        # 2. Помечаем running
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(UTC)
        scan.celery_task_id = celery_task_id
        session.add(scan)
        await session.commit()

        # 3. Выбираем сканер
        scanner_cls = _SCANNERS.get(scan.scanner)
        if scanner_cls is None:
            return await _fail(session, scan, f"Unknown scanner: {scan.scanner}")

        scanner = scanner_cls()

        try:
            findings = await asyncio.to_thread(scanner.scan, scan.target)
        except Exception as e:
            logger.exception("Scanner failed for scan %s", scan_id)
            return await _fail(session, scan, str(e))

        # 5. Создаём Vulnerability для каждой находки
        for f in findings:
            vuln = Vulnerability(
                title=f.title,
                description=f.description,
                severity=f.severity,
                cvss=f.cvss,
                cwe=f.cwe,
                project_id=scan.project_id,
                scan_id=scan.id,
                scanner=scan.scanner,
                scanner_metadata=f.scanner_metadata,
            )
            session.add(vuln)

        # 6. Обновляем Scan
        scan.status = ScanStatus.SUCCESS
        scan.findings_count = len(findings)
        scan.finished_at = datetime.now(UTC)
        session.add(scan)
        await session.commit()

        logger.info("Scan %s done: %d findings", scan_id, len(findings))
        return {"status": "success", "findings": len(findings)}


async def _fail(session, scan: Scan, message: str) -> dict:
    """Помечает Scan как failed и коммитит."""
    scan.status = ScanStatus.FAILED
    scan.error_message = message[:1000]
    scan.finished_at = datetime.now(UTC)
    session.add(scan)
    await session.commit()
    return {"status": "failed", "message": message}