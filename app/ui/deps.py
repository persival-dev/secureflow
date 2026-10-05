"""UI-зависимости: аутентификация через cookie вместо Authorization header.

Почему cookie: браузер не умеет ставить Authorization: Bearer в навигационных
запросах (переход по ссылке, отправка формы). Cookie летит автоматически.
"""

import uuid
from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, status

from app.api.deps import DbSessionDep
from app.core.security import decode_token
from app.models.user import User
from app.repositories.user import UserRepository

COOKIE_NAME = "sf_access_token"


async def get_current_user_from_cookie(
    session: DbSessionDep,
    sf_access_token: Annotated[str | None, Cookie()] = None,
) -> User:
    """Достаёт пользователя из HttpOnly cookie. 401 если нет/протух."""
    if not sf_access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"Location": "/ui/login"},
        )

    try:
        payload = decode_token(sf_access_token, expected_type="access")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        ) from exc

    user_id = uuid.UUID(payload["sub"])
    user_repo = UserRepository(session)
    user = await user_repo.get(user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    return user


# ⚠️ Annotated, не Depends! FastAPI требует Annotated[Тип, Depends(...)]
CurrentUserDep = Annotated[User, Depends(get_current_user_from_cookie)]