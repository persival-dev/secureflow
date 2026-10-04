"""
Экспорт всех моделей.

Важно: файл нужен, чтобы Alembic через `from app.models import ...`
видел ВСЕ модели и мог их сравнивать с реальной схемой БД.
"""
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user import User, UserRole
from app.models.vulnerability import (
    SeverityLevel,
    Vulnerability,
    VulnerabilityStatus,
)

__all__ = [
    "Project",
    "Scan",
    "ScanStatus",
    "SeverityLevel",
    "User",
    "UserRole",
    "Vulnerability",
    "VulnerabilityStatus",
]