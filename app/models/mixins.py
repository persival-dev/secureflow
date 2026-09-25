"""
Общие миксины для ORM-моделей.

Миксины дают базовые поля (id, timestamps) всем таблицам без дублирования.
"""
import uuid
from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column


class UUIDMixin:
    """
    UUID-первичный ключ.

    Почему UUID, а не integer:
    - не утекает количество записей (нельзя сказать "/vuln/10521" → "их 10k+")
    - удобно генерировать ID на клиенте в распределённой системе
    - безопаснее в публичных URL
    """
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )


class TimestampMixin:
    """
    created_at + updated_at.

    DateTime(timezone=True) — timestamptz в PostgreSQL.
    ОБЯЗАТЕЛЬНО для сервисов, работающих в разных TZ.

    server_default=func.now() — время считает PostgreSQL, не Python.
    Это исключает рассинхрон между контейнерами.
    """
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )