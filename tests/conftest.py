"""
Общие фикстуры для тестов.

Ключевая идея:
- Отдельная тестовая БД (secureflow_test).
- На каждый тест — своя сессия в транзакции, которая откатывается.
- httpx.AsyncClient через ASGITransport — без реального HTTP.
"""
import asyncio
from collections.abc import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.deps import get_db_session
from app.core.config import settings
from app.db.base import Base
from app.main import app as fastapi_app
# Импорт моделей — чтобы они попали в Base.metadata
from app.models import project, vulnerability  # noqa: F401


# ---------- Test DB URL ----------
TEST_DB_URL = (
    f"postgresql+asyncpg://{settings.POSTGRES_USER}:"
    f"{settings.POSTGRES_PASSWORD.get_secret_value()}@"
    f"{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/"
    f"{settings.POSTGRES_DB}_test"
)


# ---------- Event loop ----------
@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """
    Session-scoped event loop.

    Без этого pytest-asyncio создаёт новый loop на каждый тест,
    и engine с привязанным к пулу loop падает.
    """
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------- Test engine (session scope) ----------
@pytest_asyncio.fixture(scope="session")
async def test_engine():
    """Движок для тестовой БД. NullPool — не кэшируем соединения между loop."""
    engine = create_async_engine(TEST_DB_URL, poolclass=NullPool)
    yield engine
    await engine.dispose()


# ---------- Создание схемы (session scope) ----------
@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_database(test_engine):
    """
    Один раз на сессию: создаём схему.

    Не используем Alembic ради скорости. В CI можно переключиться на
    alembic upgrade head — это ближе к проду, но медленнее.
    """
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ---------- Тестовая сессия с rollback ----------
@pytest_asyncio.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """
    Сессия в транзакции. После теста — rollback.

    Схема: outer transaction → session в nested → тест → rollback outer.
    Так изменения теста не остаются в БД.
    """
    async with test_engine.connect() as connection:
        transaction = await connection.begin()
        session_factory = async_sessionmaker(
            bind=connection,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )
        async with session_factory() as session:
            yield session
        await transaction.rollback()


# ---------- HTTP-клиент с override зависимости ----------
@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """
    AsyncClient, общающийся с приложением напрямую (без сети).

    Override get_db_session → тестовая сессия с rollback.
    Каждый запрос пойдёт в ту же транзакцию, что и тест.
    """
    async def _override_get_db():
        yield db_session

    fastapi_app.dependency_overrides[get_db_session] = _override_get_db

    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    fastapi_app.dependency_overrides.clear()


# ---------- Хелпер: создать проект в тестовой БД ----------
@pytest_asyncio.fixture
async def sample_project(db_session: AsyncSession):
    """Создаёт проект для тестов FK. Возвращает ORM-объект."""
    from app.models.project import Project

    project = Project(name="Test Project", slug="test-project")
    db_session.add(project)
    await db_session.flush()
    return project