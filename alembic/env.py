"""
Настройка Alembic для SecureFlow.

URL берём из settings.DATABASE_URL_SYNC (sync-драйвер psycopg),
а не из alembic.ini — там лежит плейсхолдер, который ломает Alembic.
"""
from logging.config import fileConfig
from sqlalchemy import create_engine, pool
from alembic import context
# --- Импорт настроек и метаданных моделей ---
from app.core.config import settings
from app.db.base import Base
from app.models import project, vulnerability  # noqa: F401
# Alembic Config object
config = context.config
# Логирование из alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)
# Метаданные моделей — то, с чем сравнивать реальную схему
target_metadata = Base.metadata
def run_migrations_offline() -> None:
    """Offline-режим: генерация SQL без подключения к БД."""
    context.configure(
        url=settings.DATABASE_URL_SYNC,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    """
    Online-режим: подключение к реальной БД.

    Используем create_engine напрямую, а не engine_from_config,
    чтобы не читать плейсхолдер sqlalchemy.url из alembic.ini.
    """
    connectable = create_engine(
        settings.DATABASE_URL_SYNC,
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()