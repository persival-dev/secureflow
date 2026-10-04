"""
Pydantic-схемы для аутентификации.

Включает: регистрацию, логин, пару токенов, ответ с юзером.
"""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.user import UserRole


# ---------- User ----------
class UserCreate(BaseModel):
    """
    Схема регистрации.

    Password ограничен 8-72 символами:
    - 8 — минимальная разумная длина (NIST SP 800-63B).
    - 72 — bcrypt обрезает >72 байт молча (мы это уже знаем).
    """
    email: EmailStr = Field(description="Email — будет использоваться как логин")
    password: str = Field(
        min_length=8,
        max_length=72,
        description="Пароль (8–72 символа)",
    )
    full_name: str | None = Field(default=None, max_length=255)


class UserRead(BaseModel):
    """
    Публичное представление юзера.

     НИКОГДА не включай сюда hashed_password. Это модель ответа API.
    """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    full_name: str | None
    role: UserRole
    is_active: bool
    created_at: datetime


# ---------- Tokens ----------
class TokenPair(BaseModel):
    """
    Ответ при успешном логине/refresh.

    Формат "Bearer" — стандарт OAuth2. Клиент отправляет:
    Authorization: Bearer <access_token>
    """
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(
        description="Срок жизни access-токена в секундах",
    )


class RefreshRequest(BaseModel):
    """Запрос на обновление пары токенов по refresh-токену."""
    refresh_token: str = Field(min_length=10)

class UserRoleUpdate(BaseModel):
    """Смена роли юзера. Доступно только ADMIN."""
    role: UserRole

class UserUpdate(BaseModel):
    """
    Частичное обновление юзера админом.

    Все поля опциональны. Меняем только то, что прислали.
    """
    full_name: str | None = Field(default=None, max_length=255)
    role: UserRole | None = None
    is_active: bool | None = None