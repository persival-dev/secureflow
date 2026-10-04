"""
Точка входа FastAPI-приложения.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.db.session import engine

# ---------- Логирование ----------
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("secureflow")


# ---------- Lifespan ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Управление жизненным циклом приложения.

    Код до yield  — выполняется при старте.
    Код после yield — при graceful shutdown.
    """
    logger.info("Starting %s (%s)", settings.PROJECT_NAME, settings.ENVIRONMENT)
    yield
    # Закрываем пул соединений — иначе Postgres будет держать
    # «висящие» соединения после остановки контейнера
    await engine.dispose()
    logger.info("Shutdown complete")


# ---------- Factory ----------
def create_app() -> FastAPI:
    """Фабрика приложения. Тесты используют её для изолированных инстансов."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version="0.1.0",
        docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
        redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
        openapi_url="/openapi.json" if settings.ENVIRONMENT != "production" else None,
        lifespan=lifespan,
    )

    # CORS — только если заданы origins
    if settings.BACKEND_CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.BACKEND_CORS_ORIGINS,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Основной роутер
    app.include_router(api_router)

    return app


# Глобальный инстанс для `uvicorn app.main:app`
app = create_app()