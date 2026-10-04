"""
Конфигурация приложения.

Все настройки читаются из переменных окружения (файл .env в dev,
секреты окружения в prod). Валидация — при старте приложения.
"""
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """
    Единая точка входа для всех настроек приложения.

    Значения читаются в порядке приоритета:
    1. Переменные окружения (export FOO=bar)
    2. .env файл в корне проекта
    3. Значения по умолчанию из Field(...)
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---------- Общие ----------
    PROJECT_NAME: str = Field(default="SecureFlow")
    ENVIRONMENT: Literal["development", "staging", "production"] = Field(default="development")
    DEBUG: bool = Field(default=False)
    # ---------- GitHub Webhooks ----------
    GITHUB_WEBHOOK_SECRET: SecretStr | None = None
    # ---------- Telegram ----------
    TELEGRAM_BOT_TOKEN: SecretStr | None = None
    TELEGRAM_CHAT_ID: str | None = None
    TELEGRAM_ENABLED: bool = False
    # ---------- PostgreSQL ----------
    POSTGRES_USER: str
    POSTGRES_PASSWORD: SecretStr  # маскируется в логах и repr()
    POSTGRES_DB: str
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432

    # ---------- Redis ----------
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0

    # ---------- JWT ----------
    SECRET_KEY: SecretStr = Field(min_length=32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ---------- CORS ----------
    BACKEND_CORS_ORIGINS: Annotated[list[str], NoDecode] = Field(default_factory=list)


    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def split_cors(cls, v: str | list[str]) -> list[str]:
        """Позволяем задавать CORS как 'a,b' в .env или list в коде."""
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @property
    def DATABASE_URL(self) -> str:
        """
        DSN для asyncpg (async-движок SQLAlchemy).

        asyncpg требует схему postgresql+asyncpg://
        Пароль разворачиваем из SecretStr — в URL попадает только здесь.
        """
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:"
            f"{self.POSTGRES_PASSWORD.get_secret_value()}@"
            f"{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def DATABASE_URL_SYNC(self) -> str:
        """
        DSN для psycopg (sync). Нужен Alembic:
        async-движки в Alembic работают, но это усложняет env.py.
        Проще использовать sync-URL для миграций.
        """
        return (
            f"postgresql+psycopg://{self.POSTGRES_USER}:"
            f"{self.POSTGRES_PASSWORD.get_secret_value()}@"
            f"{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def REDIS_URL(self) -> str:
        """URL для подключения к Redis (Celery, rate-limit)."""
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"


@lru_cache
def get_settings() -> Settings:
    """
    Возвращает единственный экземпляр Settings.

    lru_cache гарантирует, что .env читается один раз за всё время
    жизни процесса. В тестах кэш сбрасывается через
    get_settings.cache_clear().
    """
    return Settings() # type: ignore[call-arg]


settings = get_settings()