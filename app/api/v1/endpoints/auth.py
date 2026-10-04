"""
Эндпоинты аутентификации.

Регистрация, логин, refresh, /me.
"""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.api.deps import CurrentUserDep, DbSessionDep
from app.schemas.auth import (
    RefreshRequest,
    TokenPair,
    UserCreate,
    UserRead,
)
from app.services.auth import (
    AuthService,
    EmailAlreadyExistsError,
    InvalidCredentialsError,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def get_auth_service(session: DbSessionDep) -> AuthService:
    """DI-провайдер сервиса аутентификации."""
    return AuthService(session)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Регистрация нового пользователя",
)
async def register(
    payload: UserCreate,
    service: AuthServiceDep,
) -> UserRead:
    """
    Создаёт юзера с ролью DEVELOPER.

    Пароль хешируется bcrypt (cost=12), в БД хранится только хеш.
    """
    try:
        user = await service.register(payload)
    except EmailAlreadyExistsError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        ) from e
    return UserRead.model_validate(user)


@router.post(
    "/login",
    response_model=TokenPair,
    summary="Логин по email и паролю",
)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    service: AuthServiceDep,
) -> TokenPair:
    """
    Логин. Принимает form-urlencoded (не JSON) — стандарт OAuth2,
    чтобы кнопка Authorize в Swagger работала из коробки.
    """
    try:
        user = await service.authenticate(
            email=form_data.username,
            password=form_data.password,
        )
    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

    return service.create_token_pair(user)


@router.post(
    "/refresh",
    response_model=TokenPair,
    summary="Обновить пару токенов по refresh",
)
async def refresh(
    payload: RefreshRequest,
    service: AuthServiceDep,
) -> TokenPair:
    """
    Принимает refresh-токен, возвращает новую пару access + refresh.

    Rotating refresh: старый refresh формально можно использовать
    повторно, пока он не истёк. В проде — blacklist в Redis.
    """
    try:
        _, tokens = await service.refresh_tokens(payload.refresh_token)
    except InvalidCredentialsError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    return tokens


@router.get(
    "/me",
    response_model=UserRead,
    summary="Текущий пользователь",
)
async def me(current_user: CurrentUserDep) -> UserRead:
    """
    Возвращает данные юзера из access-токена.

    Требует заголовок Authorization: Bearer <access_token>.
    """
    return UserRead.model_validate(current_user)