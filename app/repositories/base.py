"""
Базовый generic-репозиторий.

Позволяет не дублировать CRUD в каждом репозитории. Если в проекте
будет 10 моделей — этот класс сэкономит сотни строк.
"""
import uuid
from typing import Generic, TypeVar

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import Base

ModelT = TypeVar("ModelT", bound=Base)
CreateT = TypeVar("CreateT", bound=BaseModel)
UpdateT = TypeVar("UpdateT", bound=BaseModel)


class BaseRepository(Generic[ModelT, CreateT, UpdateT]):
    """
    Generic CRUD. Наследники задают только `model` и (при необходимости)
    переопределяют методы.
    """
    model: type[ModelT]

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, obj_id: uuid.UUID) -> ModelT | None:
        """Вернуть объект по PK или None."""
        return await self.session.get(self.model, obj_id)

    async def get_many(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ModelT]:
        """
        Список объектов с пагинацией.

        `order_by(created_at.desc())` — новые первыми. Полезно для дашбордов.
        """
        stmt = (
            select(self.model)
            .order_by(self.model.created_at.desc())   # type: ignore[attr-defined]
            .limit(limit)
            .offset(offset)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count(self) -> int:
        """Всего объектов. Нужно для pagination.total."""
        stmt = select(func.count()).select_from(self.model)
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def create(self, obj_in: CreateT) -> ModelT:
        """Создать объект из Pydantic-схемы."""
        # model_dump() — dict из Pydantic-модели.
        db_obj = self.model(**obj_in.model_dump())
        self.session.add(db_obj)
        await self.session.flush()   # получить id до commit
        await self.session.refresh(db_obj)  # подтянуть server_default (created_at)
        return db_obj

    async def update(self, db_obj: ModelT, obj_in: UpdateT) -> ModelT:
        """
        Частичное обновление.

        exclude_unset=True — не трогаем поля, которые клиент не прислал.
        Без этого PATCH с одним полем обнулил бы остальные.
        """
        update_data = obj_in.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_obj, field, value)
        self.session.add(db_obj)
        await self.session.flush()
        await self.session.refresh(db_obj)
        return db_obj

    async def delete(self, db_obj: ModelT) -> None:
        """Удалить объект."""
        await self.session.delete(db_obj)