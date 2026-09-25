"""
Сервис аутентификации.

Оркестрирует: репозиторий, security-утилиты, выдачу токенов.
"""
import uuid
from datetime import UTC, datetime

from jwt.exceptions import InvalidTokenError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.models.user import User
from app.repositories.user import UserRepository
from app.schemas.auth import UserCreate


_DUMMY_HASH = "$2b$12$C6UzMDM.H6dfI/f/IKcEeO8xIbV5HUnWzpKMix4o6nBbh3DJlbLg6"


class AuthError(Exception):
    """Базовое исключение auth-слоя. На уровне API превращается в 401."""
    pass


class EmailAlreadyExistsError(AuthError):
    """Email уже занят. На уровне API → 409 Conflict."""
    pass


class InvalidCredentialsError(AuthError):
    """
    Неверный email или пароль.

     Умышленно НЕ разделяем "email не найден" и "пароль неверный" —
    иначе атакующий собирает базу email через /auth/login.
    """
    pass


class AuthService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.users = UserRepository(session)

    async def register(self, data: UserCreate) -> User:
        """
        Регистрация нового пользователя.

        Логика:
        1. Проверяем, что email уникален.
        2. Хешируем пароль.
        3. Создаём юзера с ролью DEVELOPER (по умолчанию).
        4. Возвращаем (пароль НЕ возвращаем!).

        Роль по умолчанию — DEVELOPER. Повышение до SECURITY/ADMIN —
        задача админа (сделаем на Дне 9).
        """
        existing = await self.users.get_by_email(data.email)
        if existing is not None:
            raise EmailAlreadyExistsError(f"Email {data.email} already registered")

        hashed = hash_password(data.password)
        user = await self.users.create_from_schema(data, hashed)
        await self.session.commit()
        return user

    async def authenticate(self, email: str, password: str) -> User:
        """
        Проверяет email + пароль, возвращает юзера.

        Защита от user enumeration:
        - Если юзер не найден — всё равно делаем bcrypt-verify против
          dummy-хеша. Время ответа одинаково (250 мс), атакующий не
          отличит "нет такого email" от "неверный пароль".
        - Сообщение об ошибке одинаковое в обоих случаях.
        """
        user = await self.users.get_by_email(email)

        if user is None:
            verify_password(password, _DUMMY_HASH)
            raise InvalidCredentialsError("Invalid email or password")

        if not verify_password(password, user.hashed_password):
            raise InvalidCredentialsError("Invalid email or password")

        if not user.is_active:
            raise InvalidCredentialsError("Invalid email or password")

        user.last_login_at = datetime.now(UTC)
        self.session.add(user)
        await self.session.commit()
        return user

    def create_token_pair(self, user: User) -> dict[str, str | int]:
        """
        Создаёт пару access + refresh для юзера.

        Возвращает dict — на уровне API Pydantic-схема TokenPair
        провалидирует и отдаст клиенту.
        """
        access = create_access_token(user.id)
        refresh = create_refresh_token(user.id)
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
            "expires_in": 60 * 15,  # 15 минут в секундах (соответствует settings)
        }

    async def refresh_tokens(self, refresh_token: str) -> tuple[User, dict]:
        """
        Обновляет пару токенов по refresh-токену.

        Логика:
        1. Декодируем refresh, проверяем что type == 'refresh'.
        2. Достаём юзера по sub.
        3. Проверяем, что он ещё активен.
        4. Выдаём НОВУЮ пару (rotating refresh tokens).

         Rotating refresh: старый refresh становится недействительным.
        В stateless JWT мы не можем отозвать его без blacklist —
        это добавим в проде через Redis. Пока — просто выдаём новые.
        """
        try:
            payload = decode_token(refresh_token, expected_type="refresh")
        except InvalidTokenError as e:
            raise InvalidCredentialsError(f"Invalid refresh token: {e}") from e

        try:
            user_id = uuid.UUID(payload["sub"])
        except (KeyError, ValueError) as e:
            raise InvalidCredentialsError("Malformed token payload") from e

        user = await self.users.get(user_id)
        if user is None or not user.is_active:
            raise InvalidCredentialsError("User not found or inactive")

        new_pair = self.create_token_pair(user)
        return user, new_pair