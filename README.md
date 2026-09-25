# SecureFlow

Vulnerability Management Platform для AppSec-команд: запуск SAST/DAST-сканирований,
трекинг уязвимостей, интеграции с GitHub и Telegram, отчёты с CVSS.

![Python](https://img.shields.io/badge/python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791)

## ✨ Возможности

- ✅ REST API на FastAPI с async SQLAlchemy 2.0
- ✅ PostgreSQL 16 + Redis 7 в Docker
- ✅ Alembic-миграции с native enum-типами
- ✅ Repository + Service слои, DI через FastAPI
- ✅ Health/readiness probes, structured logging
- ✅ Тесты с изоляцией (rollback per test)
- ⬜ JWT-аутентификация с ролями (admin/security/developer)
- ⬜ Запуск SAST-сканов (bandit, semgrep) через Celery
- ⬜ GitHub webhooks + автоматическое создание issues
- ⬜ Генерация PDF-отчётов (WeasyPrint)
- ⬜ Telegram-бот для уведомлений

## 🛠 Стек

**Backend:** FastAPI, SQLAlchemy 2.0 (async), Pydantic v2, Alembic, PyJWT
**БД:** PostgreSQL 16, Redis 7
**Инфра:** Docker Compose, GitHub Actions
**Качество:** pytest, ruff, mypy

## 🚀 Быстрый старт

```bash
git clone https://github.com/persival-dev/secureflow.git
cd secureflow

# 1. Настрой окружение
cp .env.example .env
# Открой .env, сгенерируй SECRET_KEY:
python3 -c "import secrets; print(secrets.token_hex(32))"
# и впиши его + свой POSTGRES_PASSWORD

# 2. Запусти стек
docker compose up -d --build

# 3. Примени миграции
docker compose exec api alembic upgrade head

# 4. Открой документацию
open http://localhost:8000/docs
```

**Проверка:**
```bash
curl http://localhost:8000/api/v1/health
# → {"status":"ok","service":"SecureFlow","environment":"development"}
```

## 🧪 Тесты

```bash
# Создай тестовую БД (один раз)
docker compose exec postgres psql -U secureflow -d postgres \
  -c "CREATE DATABASE secureflow_test OWNER secureflow;"

# Запусти тесты (используй alias sf-test)
POSTGRES_HOST=localhost pytest tests/ -v
```

## 📐 Архитектура

```
API (FastAPI) → Services (бизнес-логика) → Repositories (SQL) → Models (ORM)
```

**Почему слои:** изоляция ORM от бизнес-логики, тестируемость, заменяемость.

## 🗺 Roadmap

- [x] **Неделя 1** — фундамент: Docker, БД, модели, CRUD API, тесты
- [ ] **Неделя 2** — JWT, роли, сканеры (bandit/semgrep), отчёты
- [ ] **Неделя 3** — GitHub webhooks, Celery, Telegram-бот
- [ ] **Неделя 4** — React-фронт, документация, финал

## 📄 Лицензия

MIT