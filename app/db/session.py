"""
Async-движок SQLAlchemy и фабрика сессий.
"""
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings


# ---------- Engine ----------
engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    pool_recycle=3600,
)


# ---------- Session factory ----------
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


# ---------- FastAPI dependency ----------
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Зависимость для роутеров: `db: AsyncSession = Depends(get_db)`.

    Сессия автоматически закрывается после запроса. Транзакция
    коммитится вручную внутри сервисов — это осознанный выбор:
    коммит всегда виден в коде, а не «магически» после роутера.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
