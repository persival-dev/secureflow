"""
Engine для Celery-worker.

Отдельный от основного app.db.session, потому что:
- Celery задача = sync-контекст → asyncio.run() создаёт новый loop.
- Основной engine кэширует соединения в pool → привязка к loop → ошибки.
- NullPool: каждое соединение создаётся заново. Медленнее на ~5мс, но безопасно.
"""
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.config import settings


worker_engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    poolclass=NullPool,
)


WorkerSessionLocal = async_sessionmaker(
    bind=worker_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_worker_session() -> AsyncGenerator[AsyncSession, None]:
    """Async-сессия для worker-задач."""
    async with WorkerSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise