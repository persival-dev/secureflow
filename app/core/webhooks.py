"""
Утилиты для валидации webhook-подписей.

GitHub подписывает payload HMAC-SHA256 с общим секретом.
Мы считаем тот же HMAC и сравниваем через hmac.compare_digest
(constant-time, устойчиво к timing-атакам).
"""
import hashlib
import hmac


def verify_github_signature(
    *,
    payload_body: bytes,
    signature_header: str | None,
    secret: str,
) -> bool:
    """
    Проверяет HMAC-SHA256 подпись GitHub-вебхука.

    Args:
        payload_body: Сырой body запроса (bytes, не dict!).
        signature_header: Значение X-Hub-Signature-256, формат "sha256=hex".
        secret: Секрет вебхука (общий с GitHub).

    Returns:
        True, если подпись корректна.

    ⚠️ КРИТИЧНО:
    - body должен быть СЫРЫМИ bytes запроса. Если парсить JSON и потом
      re-serialize — пробелы/порядок ключей изменятся, HMAC не совпадёт.
    - Сравнение только через hmac.compare_digest. Обычный `==`
      работает за время, пропорциональное совпадающим байтам,
      что даёт timing-атаку.
    """
    if not signature_header:
        return False

    # Формат заголовка: "sha256=abcdef..."
    prefix = "sha256="
    if not signature_header.startswith(prefix):
        return False

    expected_hex = signature_header[len(prefix):]
    if not expected_hex:
        return False

    # Считаем HMAC-SHA256 от сырого body с секретом
    computed_hmac = hmac.new(
        key=secret.encode("utf-8"),
        msg=payload_body,
        digestmod=hashlib.sha256,
    ).hexdigest()

    # constant-time сравнение
    return hmac.compare_digest(computed_hmac, expected_hex)