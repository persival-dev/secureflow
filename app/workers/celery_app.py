"""
Celery application для SecureFlow.

Broker: Redis (список задач).
Backend: Redis (результаты задач).

Почему Redis и для broker, и для backend:
- Уже есть в инфраструктуре.
- Backend хранит результаты ~1 час, Redis справляется.
- RabbitMQ мощнее, но оверинжиниринг для пет-проекта.
"""
from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "secureflow",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.workers.tasks.scans",
        "app.workers.tasks.notifications",
    ],
)


# ---------- Конфигурация ----------
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    result_expires=3600,

    timezone="UTC",
    enable_utc=True,

    worker_prefetch_multiplier=1,

    task_always_eager=False,

    task_soft_time_limit=300,
    task_time_limit=360,
)