"""
Экспорт всех моделей.

Важно: файл нужен, чтобы Alembic через `from app.models import ...`
видел ВСЕ модели и мог их сравнивать с реальной схемой БД.
Если забудешь импортировать — миграция будет пустой.
"""
from app.models.project import Project
from app.models.vulnerability import (
    SeverityLevel,
    Vulnerability,
    VulnerabilityStatus,
)
__all__ = [
    "Project",
    "Vulnerability",
    "SeverityLevel",
    "VulnerabilityStatus",
]