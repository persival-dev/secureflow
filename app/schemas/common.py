"""
Общие схемы: пагинация, ошибки.
"""
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginationParams(BaseModel):
    """Query-параметры для пагинации."""
    limit: int = Field(default=50, ge=1, le=200, description="Размер страницы")
    offset: int = Field(default=0, ge=0, description="Смещение")


class Page(BaseModel, Generic[T]):
    """
    Пагинированный ответ.

    Generic[T] — Pydantic v2 умеет дженерики, поэтому Page[VulnerabilityRead]
    автоматически валидирует элементы списка.
    """
    items: list[T]
    total: int = Field(description="Всего записей")
    limit: int
    offset: int


class ErrorResponse(BaseModel):
    """Стандартный формат ошибки."""
    detail: str