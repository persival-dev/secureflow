"""
Репозиторий для Scan.

Extends BaseRepository фильтрами по project_id/scanner/status.
"""
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.models.scan import Scan, ScanStatus
from app.repositories.base import BaseRepository
from app.schemas.scan import ScanCreate, ScanCreate


class ScanRepository(BaseRepository[Scan, ScanCreate, ScanCreate]):
    model = Scan

    async def get_with_project(self, scan_id: uuid.UUID) -> Scan | None:
        """
        Загружает Scan вместе с Project.

        selectinload — как в VulnerabilityRepository. Иначе при
        обращении к scan.project в async-контексте получим MissingGreenlet.
        """
        stmt = (
            select(Scan)
            .options(selectinload(Scan.project))
            .where(Scan.id == scan_id)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_many_filtered(
        self,
        *,
        project_id: uuid.UUID | None = None,
        scanner: str | None = None,
        status: ScanStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Scan]:
        """Список с фильтрами. Все параметры опциональны."""
        stmt = select(Scan)

        if project_id is not None:
            stmt = stmt.where(Scan.project_id == project_id)
        if scanner is not None:
            stmt = stmt.where(Scan.scanner == scanner)
        if status is not None:
            stmt = stmt.where(Scan.status == status)

        stmt = (
            stmt.order_by(Scan.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_filtered(
        self,
        *,
        project_id: uuid.UUID | None = None,
        scanner: str | None = None,
        status: ScanStatus | None = None,
    ) -> int:
        """Всего с учётом фильтров — для pagination.total."""
        stmt = select(func.count()).select_from(Scan)

        if project_id is not None:
            stmt = stmt.where(Scan.project_id == project_id)
        if scanner is not None:
            stmt = stmt.where(Scan.scanner == scanner)
        if status is not None:
            stmt = stmt.where(Scan.status == status)

        result = await self.session.execute(stmt)
        return result.scalar_one()