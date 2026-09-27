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
from app.models import project, vulnerability  # noqa: F401
import uuid
from app.core.security import create_access_token, hash_password
from app.models.user import User, UserRole

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

# ---------- Auth fixtures ----------


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    """
    Юзер в тестовой БД — база для auth_headers.

    SECURITY, а не DEVELOPER: тесты vulnerabilities требуют прав на
    создание/удаление. RBAC-тесты создают свои роли явно.
    """
    user = User(
        email=f"user-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=hash_password("TestPassword123!"),
        full_name="Test User",
        role=UserRole.SECURITY,
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def auth_headers(test_user: User) -> dict[str, str]:
    """Готовый заголовок Authorization для SECURITY-юзера."""
    token = create_access_token(test_user.id)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def auth_client(
    client: AsyncClient,
    auth_headers: dict[str, str],
) -> AsyncGenerator[AsyncClient, None]:
    """httpx-клиент с уже подставленным Authorization."""
    client.headers.update(auth_headers)
    yield client
    client.headers.pop("Authorization", None)


# ---------- Role-specific fixtures (для RBAC и test_scans) ----------


async def _create_user_with_role(db: AsyncSession, role: UserRole) -> User:
    """Хелпер: создаёт юзера с указанной ролью."""
    user = User(
        email=f"{role.value}-{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=hash_password("Password123!"),
        full_name=f"{role.value.title()} User",
        role=role,
        is_active=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


@pytest_asyncio.fixture
async def developer_user(db_session: AsyncSession) -> User:
    return await _create_user_with_role(db_session, UserRole.DEVELOPER)


@pytest_asyncio.fixture
async def security_user(db_session: AsyncSession) -> User:
    return await _create_user_with_role(db_session, UserRole.SECURITY)


@pytest_asyncio.fixture
async def admin_user(db_session: AsyncSession) -> User:
    return await _create_user_with_role(db_session, UserRole.ADMIN)


def _headers(user: User) -> dict[str, str]:
    """Хелпер для тестов: Authorization header для конкретного юзера."""
