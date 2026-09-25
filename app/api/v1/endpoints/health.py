"""
Health-эндпоинты.

/health  — liveness: приложение живо (без проверки БД)
/ready   — readiness: приложение готово принимать трафик
"""
from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db

router = APIRouter(tags=["health"])


@router.get("/health", summary="Liveness probe")
async def health() -> dict[str, str]:
    """Возвращает 'ok', если процесс приложения работает."""
    return {
        "status": "ok",
        "service": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT,
    }


@router.get("/ready", summary="Readiness probe")
async def ready(db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    """
    Проверяет, что приложение может ходить в БД.
    Если БД недоступна — вернёт 503.
    """
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database unavailable",
        )
    return {"status": "ready", "database": "ok"}