"""
Pydantic-схемы для Scan.

Отдельно от ORM-модели: API-контракт ≠ структура БД.
"""
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.scan import ScanStatus

ScannerName = Literal["bandit", "semgrep", "zap"]


class ScanCreate(BaseModel):
    """
    Запрос на создание скана.

    target — путь внутри контейнера worker'а. В проде здесь будет
    git URL или ID репозитория; для пет-проекта — путь к локальной папке.
    """
    project_id: uuid.UUID
    scanner: ScannerName
    target: str = Field(
        min_length=1,
        max_length=500,
        description="Путь к файлу/папке внутри worker-контейнера",
    )


class ScanRead(BaseModel):
    """
    Публичное представление Scan.

    Возвращаем всё, что клиенту полезно знать о ходе скана.
    """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    scanner: str
    target: str
    status: ScanStatus
    celery_task_id: str | None
    started_at: datetime | None
    finished_at: datetime | None
    findings_count: int
    error_message: str | None
    created_at: datetime
    updated_at: datetime


class ScanListFilters(BaseModel):
    """
    Query-параметры для фильтрации списка сканов.

    Не используется как Depends — просто DTO для удобства.
    """
    project_id: uuid.UUID | None = None
    scanner: str | None = None
    status: ScanStatus | None = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)