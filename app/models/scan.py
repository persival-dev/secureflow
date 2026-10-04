"""
Модель Scan — запись о запуске SAST/DAST-сканирования.

Один Scan = одна задача сканирования одного проекта одним сканером.
Результаты (Vulnerability) ссылаются обратно через Vulnerability.scan_id.
"""
import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.project import Project
    from app.models.vulnerability import Vulnerability


class ScanStatus(str, enum.Enum):
    """
    Жизненный цикл скана.

    PENDING → RUNNING → (SUCCESS | FAILED)
                     ↘ CANCELLED
    """
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scans"

    # --- Что и чем сканируем ---
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="К какому проекту относится скан",
    )
    scanner: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="bandit | semgrep | zap",
    )
    target: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        comment="Что сканируем: путь к папке/файлу, git URL",
    )

    # --- Статус ---
    status: Mapped[ScanStatus] = mapped_column(
        SAEnum(
            ScanStatus,
            name="scan_status",
            native_enum=True,
            values_callable=lambda cls: [m.value for m in cls],
        ),
        nullable=False,
        default=ScanStatus.PENDING,
        index=True,
    )

    # --- Связь с Celery ---
    celery_task_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        comment="ID задачи Celery — для отслеживания и отмены",
    )

    # --- Тайминги ---
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Когда worker начал выполнение",
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Когда worker завершил",
    )

    # --- Результаты ---
    findings_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Сколько уязвимостей нашёл скан",
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Сообщение об ошибке, если status=failed",
    )

    # --- Relationships ---
    project: Mapped["Project"] = relationship()
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="scan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return (
            f"<Scan id={self.id} scanner={self.scanner!r} "
            f"status={self.status.value} findings={self.findings_count}>"
        )