"""
Утилиты безопасности: хеширование паролей и JWT.

Модуль НЕ зависит от БД или FastAPI — чистые функции.
Это позволяет тестировать их в изоляции и переиспользовать
в CLI-скриптах (например, для создания первого админа).
"""
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import bcrypt
import jwt
from jwt.exceptions import InvalidTokenError

from app.core.config import settings


# ---------- Константы ----------
TokenType = Literal["access", "refresh"]

BCRYPT_ROUNDS = 12

BCRYPT_MAX_BYTES = 72


# ---------- Пароли ----------

def hash_password(password: str) -> str:
    """
    Хеширует пароль через bcrypt.

    Возвращает строку вида '$2b$12$...' — salt встроен в результат.
    Не нужно хранить salt отдельно — bcrypt делает это сам.

    Raises:
        ValueError: если пароль длиннее 72 байт (bcrypt обрежет молча).
    """
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > BCRYPT_MAX_BYTES:
        raise ValueError(
            f"Password too long: {len(password_bytes)} bytes "
            f"(max {BCRYPT_MAX_BYTES})"
        )
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Проверяет пароль против bcrypt-хеша.

    Использует constant-time сравнение внутри bcrypt — устойчиво
    к timing-атакам (нельзя угадать пароль по времени ответа).

    Returns:
        True если пароль верный, иначе False.
        НЕ бросает исключение на неверный пароль — это нормальный кейс.
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


# ---------- JWT ----------
def _create_token(
    subject: uuid.UUID | str,
    token_type: TokenType,
    expires_delta: timedelta,
) -> str:
    """
    Общая логика создания токена.

    Приватная функция — не вызывай напрямую, используй
    create_access_token / create_refresh_token.
    """
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": str(subject),
        "type": token_type,
        "iat": now,
        "exp": now + expires_delta,
    }
    return jwt.encode(
        payload,
        settings.SECRET_KEY.get_secret_value(),
        algorithm=settings.ALGORITHM,
    )


def create_access_token(
    subject: uuid.UUID | str,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Создаёт access-токен — короткоживущий, для авторизации запросов.

    По умолчанию живёт ACCESS_TOKEN_EXPIRE_MINUTES из настроек (15 мин).
    """
    delta = expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return _create_token(subject, "access", delta)


def create_refresh_token(
    subject: uuid.UUID | str,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Создаёт refresh-токен — долгоживущий, для получения нового access.

    Живёт REFRESH_TOKEN_EXPIRE_DAYS (7 дней).
    """
    delta = expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return _create_token(subject, "refresh", delta)


def decode_token(token: str, expected_type: TokenType | None = None) -> dict[str, Any]:
    """
    Декодирует и валидирует JWT.

    Проверяет:
    - подпись (алгоритм + секрет)
    - срок действия (exp)
    - тип токена (если указан expected_type)

    Args:
        token: JWT-строка.
        expected_type: 'access' или 'refresh'. Если задан — токен
            другого типа вызовет ошибку. Защита от подмены.

    Raises:
        InvalidTokenError: любая проблема с токеном (истёк, битый,
            неверная подпись, не тот тип).

    Returns:
        Payload как dict. Гарантированно содержит 'sub', 'type', 'exp', 'iat'.

     Не ловим исключения здесь — вызывающий код решает, что делать
    (обычно — вернуть 401). Это правильное разделение ответственности.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY.get_secret_value(),
            algorithms=[settings.ALGORITHM],
        )
    except InvalidTokenError:
        raise

    if expected_type is not None and payload.get("type") != expected_type:
        raise InvalidTokenError(
            f"Invalid token type: expected {expected_type!r}, "
            f"got {payload.get('type')!r}"
        )

    return payload