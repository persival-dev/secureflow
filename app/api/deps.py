"""
Общие зависимости FastAPI.
"""
from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Выдаёт AsyncSession на время запроса.

    Коммит — в сервисе, не здесь. Здесь только rollback при исключении.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


DbSessionDep = Annotated[AsyncSession, Depends(get_db_session)]


"""
Общие зависимости FastAPI: DB session, current user, RBAC.
"""
import uuid
from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_token
from app.db.session import AsyncSessionLocal
from app.models.user import User
from app.repositories.user import UserRepository


# ---------- DB ----------
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Async-сессия на время запроса. Коммит — в сервисе, не здесь."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


DbSessionDep = Annotated[AsyncSession, Depends(get_db_session)]


# ---------- OAuth2 scheme ----------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# ---------- Current user ----------
async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: DbSessionDep,
) -> User:
    """
    Достаёт текущего юзера из Bearer-токена.

    Логика:
    1. Декодируем токен (подпись, exp, type='access').
    2. Достаём sub → UUID юзера.
    3. Читаем юзера из БД (не из payload!).

     Роль и is_active берём ИЗ БД, а не из токена. Причина:
    если админ понизил роль юзера, а тот держит токен 15 мин —
    с ролью из токена он 15 мин остаётся админом. Из БД — сразу.

    Raises:
        401: токен отсутствует, битый, истёк, или не type='access'.
        401: юзер не найден или деактивирован.
    """
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(token, expected_type="access")
    except InvalidTokenError:
        raise credentials_exc from None

    try:
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError):
        raise credentials_exc from None

    user = await session.get(User, user_id)
    if user is None or not user.is_active:
        raise credentials_exc

    return user


CurrentUserDep = Annotated[User, Depends(get_current_user)]


# ---------- RBAC ----------
from collections.abc import Callable  # noqa: E402

from app.models.user import UserRole  # noqa: E402


_ROLE_HIERARCHY = {
    UserRole.DEVELOPER: 1,
    UserRole.SECURITY: 2,
    UserRole.ADMIN: 3,
}


def require_role(*allowed: UserRole) -> Callable:
    """
    Фабрика dependency для проверки роли.

    Пример:
        @router.delete("/{id}")
        async def delete(
            _: Annotated[User, Depends(require_role(UserRole.ADMIN))],
        ): ...

    Проверяет только точное соответствие или иерархию?
    Точное соответствие — просто и предсказуемо. Если нужно
    "admin ИЛИ security", передаём оба: require_role(ADMIN, SECURITY).
    """
    allowed_set = set(allowed)

    async def _checker(user: CurrentUserDep) -> User:
        if user.role not in allowed_set:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {[r.value for r in allowed]}",
            )
        return user

    return _checker