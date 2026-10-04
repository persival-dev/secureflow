"""
Модель Project — контейнер для уязвимостей.

Примеры: "Backend API", "Mobile App iOS", "Frontend Web".
Один проект = один репозиторий/сервис/модуль.
"""
from typing import TYPE_CHECKING

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.vulnerability import Vulnerability
class Project(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "projects"
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Человекочитаемое имя проекта",
    )
    slug: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        comment="URL-safe идентификатор, например 'backend-api'",
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Опциональное описание проекта",
    )
    github_repo: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        unique=True,
        index=True,
        comment="GitHub repo в формате 'org/repo'. Используется для webhook'ов.",
    )
    default_target: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Путь внутри worker-контейнера для сканирования по webhook'у",
    )
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    def __repr__(self) -> str:
        return f"<Project id={self.id} slug={self.slug!r}>"