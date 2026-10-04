"""
Сервис для работы со сканами.

Оркестрирует: репозиторий, Celery-задачу, транзакции.
"""
import logging
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus
from app.repositories.project import ProjectRepository
from app.repositories.scan import ScanRepository
from app.schemas.scan import ScanCreate
from app.workers.tasks.scans import run_bandit_scan

logger = logging.getLogger(__name__)


class ProjectNotFoundError(Exception):
    """Проект для скана не найден. На уровне API → 404."""


class ScanService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.scans = ScanRepository(session)
        self.projects = ProjectRepository(session)

    async def create_and_dispatch(self, data: ScanCreate) -> Scan:
        """
        Создаёт запись Scan и отправляет задачу в Celery.

        Порядок важен:
        1. Проверяем, что проект существует.
        2. Создаём Scan со статусом PENDING, коммитим.
        3. Отправляем Celery-задачу.
        4. Сохраняем celery_task_id, коммитим.

        Если Celery недоступен — Scan уже создан, пометим его FAILED.
        Клиент получит 503.

        Локальный импорт задачи — чтобы не тянуть Celery в тесты,
        где задача мокается.
        """

        # 1. Проверка проекта
        project = await self.projects.get(data.project_id)
        if project is None:
            raise ProjectNotFoundError(f"Project {data.project_id} not found")

        # 2. Создаём Scan
        scan = await self.scans.create(data)
        await self.session.commit()
        await self.session.refresh(scan)

        # 3. Отправляем задачу
        try:
            task = run_bandit_scan.delay(str(scan.id))
        except Exception as e:
            logger.exception("Failed to dispatch Celery task for scan %s", scan.id)
            scan.status = ScanStatus.FAILED
            scan.error_message = f"Failed to dispatch: {e}"
            self.session.add(scan)
            await self.session.commit()
            raise

        # 4. Сохраняем task_id
        scan.celery_task_id = task.id
        self.session.add(scan)
        await self.session.commit()
        await self.session.refresh(scan)

        return scan

    async def get(self, scan_id: uuid.UUID) -> Scan | None:
        return await self.scans.get_with_project(scan_id)

    async def list(
        self,
        *,
        project_id: uuid.UUID | None = None,
        scanner: str | None = None,
        status: ScanStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Scan], int]:
        items = await self.scans.get_many_filtered(
            project_id=project_id,
            scanner=scanner,
            status=status,
            limit=limit,
            offset=offset,
        )
        total = await self.scans.count_filtered(
            project_id=project_id,
            scanner=scanner,
            status=status,
        )
        return items, total