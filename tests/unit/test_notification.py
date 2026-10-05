"""
Тесты NotificationService.

httpx-вызовы мокаются — реальный Telegram не трогаем.
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.notification import NotificationService


@pytest.mark.asyncio
async def test_send_telegram_when_disabled_returns_false() -> None:
    """Если TELEGRAM_ENABLED=false — метод возвращает False, HTTP не вызывается."""
    with patch("app.services.notification.settings") as mock_settings:
        mock_settings.TELEGRAM_ENABLED = False
        notifier = NotificationService()
        result = await notifier.send_telegram("test")

    assert result is False


@pytest.mark.asyncio
async def test_send_telegram_when_token_missing_returns_false() -> None:
    """Если enabled=true, но токен не задан — False, HTTP не вызывается."""
    with patch("app.services.notification.settings") as mock_settings:
        mock_settings.TELEGRAM_ENABLED = True
        mock_settings.TELEGRAM_BOT_TOKEN = None
        mock_settings.TELEGRAM_CHAT_ID = "123"
        notifier = NotificationService()
        result = await notifier.send_telegram("test")

    assert result is False


@pytest.mark.asyncio
async def test_send_telegram_success() -> None:
    """Успешная отправка: httpx.AsyncClient.post вызвался с правильным URL/payload."""
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()  # не кидать исключение

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    # __aenter__ возвращает сам mock_client
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("app.services.notification.settings") as mock_settings:
        mock_settings.TELEGRAM_ENABLED = True
        mock_settings.TELEGRAM_BOT_TOKEN = MagicMock()
        mock_settings.TELEGRAM_BOT_TOKEN.get_secret_value.return_value = "TOKEN123"
        mock_settings.TELEGRAM_CHAT_ID = "42"

        with patch(
            "app.services.notification.httpx.AsyncClient",
            return_value=mock_client,
        ):
            notifier = NotificationService()
            result = await notifier.send_telegram("Hello <b>world</b>")

    assert result is True
    mock_client.post.assert_called_once()
    call_args = mock_client.post.call_args
    # URL содержит токен
    assert "TOKEN123" in call_args.args[0]
    # payload корректный
    assert call_args.kwargs["json"]["chat_id"] == "42"
    assert call_args.kwargs["json"]["text"] == "Hello <b>world</b>"
    assert call_args.kwargs["json"]["parse_mode"] == "HTML"


@pytest.mark.asyncio
async def test_send_telegram_http_error_returns_false() -> None:
    """Если httpx кинул HTTPError — возвращаем False, не raise."""
    import httpx

    mock_client = MagicMock()
    mock_client.post = AsyncMock(
        side_effect=httpx.HTTPError("Connection failed")
    )
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("app.services.notification.settings") as mock_settings:
        mock_settings.TELEGRAM_ENABLED = True
        mock_settings.TELEGRAM_BOT_TOKEN = MagicMock()
        mock_settings.TELEGRAM_BOT_TOKEN.get_secret_value.return_value = "T"
        mock_settings.TELEGRAM_CHAT_ID = "42"

        with patch(
            "app.services.notification.httpx.AsyncClient",
            return_value=mock_client,
        ):
            notifier = NotificationService()
            result = await notifier.send_telegram("test")

    assert result is False