"""
Сервис уведомлений.

Отправляет сообщения в Telegram через Bot API.
Не требует python-telegram-bot — обходимся httpx.

Если TELEGRAM_ENABLED=false или токен не задан — сервис молча
игнорирует вызовы (no-op). Это позволяет тестам и dev-окружению
работать без настроенного бота.
"""
import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"


class NotificationService:
    """
    Отправка уведомлений во внешние системы.

    Сейчас — только Telegram. Позже можно добавить Slack, Discord,
    email, но интерфейс остаётся: метод send_message(text).
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def send_telegram(self, text: str) -> bool:
        """
        Отправляет текстовое сообщение в Telegram-чат.

        Returns:
            True — если сообщение отправлено.
            False — если уведомления отключены или ошибка сети.
                  Не raise'ит: падение уведомления не должно ломать
                  основной бизнес-процесс (скан).

        Использует HTML parse_mode — можно писать <b>bold</b>,
        <code>code</code>, <a href="...">link</a>.
        """
        if not settings.TELEGRAM_ENABLED:
            logger.debug("Telegram disabled, skipping notification")
            return False

        if settings.TELEGRAM_BOT_TOKEN is None or settings.TELEGRAM_CHAT_ID is None:
            logger.warning(
                "Telegram enabled but token/chat_id not configured — skipping"
            )
            return False

        url = TELEGRAM_API_URL.format(
            token=settings.TELEGRAM_BOT_TOKEN.get_secret_value()
        )
        payload = {
            "chat_id": settings.TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload)
            response.raise_for_status()
        except httpx.HTTPError as e:
            # Не raise'им: упавшее уведомление не должно ломать скан
            logger.error("Telegram send failed: %s", e)
            return False

        logger.info("Telegram notification sent (%d chars)", len(text))
        return True