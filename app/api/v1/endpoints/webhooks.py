"""
Webhook-эндпоинты.

Принимают уведомления от внешних систем (GitHub, GitLab).
Не защищены JWT — вместо этого HMAC-подпись в заголовке.

После валидации подписи:
- push в main → запуск SAST-скана через Celery
- pull_request (opened/synchronize) → пока заглушка
- ping → "pong" (для проверки вебхука из GitHub UI)
"""
import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status

from app.api.deps import DbSessionDep
from app.core.config import settings
from app.core.webhooks import verify_github_signature
from app.repositories.project import ProjectRepository
from app.schemas.scan import ScanCreate
from app.services.scan import ScanService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post(
    "/github",
    status_code=status.HTTP_202_ACCEPTED,
    summary="GitHub webhook",
)
async def github_webhook(
    request: Request,
    session: DbSessionDep,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
) -> dict[str, Any]:
    """
    Принимает события от GitHub.

    Проверяет HMAC-SHA256 подпись X-Hub-Signature-256.
    Если подпись невалидна — 401.
    Если секрет не настроен — 503.

    Возвращает 202 сразу, не дожидаясь завершения скана.
    """
    # 1. Проверяем, что секрет настроен
    if settings.GITHUB_WEBHOOK_SECRET is None:
        logger.error("GITHUB_WEBHOOK_SECRET not configured")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webhook secret not configured",
        )

    # 2. Читаем СЫРОЙ body (bytes) — не парсим JSON сразу!
    #    FastAPI кеширует только одно представление body:
    #    если сначала json(), то body() вернёт пустое. Поэтому порядок важен.
    raw_body = await request.body()

    # 3. Валидируем HMAC
    is_valid = verify_github_signature(
        payload_body=raw_body,
        signature_header=x_hub_signature_256,
        secret=settings.GITHUB_WEBHOOK_SECRET.get_secret_value(),
    )
    if not is_valid:
        logger.warning(
            "Invalid webhook signature (delivery=%s)", x_github_delivery
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid signature",
        )

    # 4. Парсим payload
    try:
        payload: dict[str, Any] = await request.json()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON payload: {e}",
        ) from e

    logger.info(
        "Webhook received: event=%s delivery=%s",
        x_github_event,
        x_github_delivery,
    )

    # 5. Диспатчим по типу события
    if x_github_event == "ping":
        return {"status": "pong"}

    if x_github_event == "push":
        return await _handle_push(payload, session)

    if x_github_event == "pull_request":
        return await _handle_pull_request(payload, session)

    # Неизвестное событие — просто подтверждаем приём
    logger.info("Ignoring unsupported event: %s", x_github_event)
    return {"status": "ignored", "event": x_github_event}


async def _handle_push(
    payload: dict[str, Any],
    session: DbSessionDep,
) -> dict[str, Any]:
    """
    Реакция на push.

    Логика:
    1. Проверяем, что push в main.
    2. Ищем Project по github_repo.
    3. Если найден — создаём Scan и запускаем Celery-задачу.
    4. Возвращаем 202 с scan_id.
    """
    ref = payload.get("ref", "")
    repo_full_name = payload.get("repository", {}).get("full_name", "")

    # Интересует только push в main
    if ref != "refs/heads/main":
        return {"status": "ignored", "reason": f"not main branch: {ref}"}

    if not repo_full_name:
        return {"status": "ignored", "reason": "no repository.full_name in payload"}

    logger.info("Push to main detected: repo=%s", repo_full_name)

    # Ищем проект по repo
    project_repo = ProjectRepository(session)
    project = await project_repo.get_by_github_repo(repo_full_name)
    if project is None:
        logger.warning("No project found for github repo: %s", repo_full_name)
        return {
            "status": "ignored",
            "reason": f"no project linked to repo {repo_full_name}",
        }

    # Target: default_target проекта или fallback на demo-файл
    target = project.default_target or "/app/demo/vulnerable_code.py"

    # Создаём Scan + ставим Celery-задачу.
    # Если Celery упал (Redis недоступен) — Scan уже помечен FAILED,
    # возвращаем 503, чтобы GitHub показал ошибку в UI.
    scan_service = ScanService(session)
    try:
        scan = await scan_service.create_and_dispatch(
            ScanCreate(
                project_id=project.id,
                scanner="bandit",
                target=target,
            )
        )
    except Exception as e:
        logger.exception("Failed to dispatch scan from webhook: %s", e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to dispatch scan: {e}",
        ) from e

    logger.info(
        "Webhook scan dispatched: scan_id=%s project=%s target=%s",
        scan.id,
        project.slug,
        target,
    )
    return {
        "status": "accepted",
        "event": "push",
        "repo": repo_full_name,
        "project_id": str(project.id),
        "scan_id": str(scan.id),
    }


async def _handle_pull_request(
    payload: dict[str, Any],
    session: DbSessionDep,
) -> dict[str, Any]:
    """
    Реакция на pull_request.

    Пока — только логируем. В будущем: запуск diff-сканирования
    только изменённых файлов.
    """
    action = payload.get("action", "")
    pr_number = payload.get("pull_request", {}).get("number")
    repo_full_name = payload.get("repository", {}).get("full_name", "")

    if action not in ("opened", "synchronize"):
        return {"status": "ignored", "reason": f"action {action}"}

    logger.info(
        "PR event: repo=%s pr=#%s action=%s (not implemented)",
        repo_full_name,
        pr_number,
        action,
    )
    return {
        "status": "ignored",
        "reason": "PR scanning not implemented yet",
        "event": "pull_request",
        "pr_number": pr_number,
    }