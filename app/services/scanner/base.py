"""
Базовый интерфейс SAST-сканера.

Позволяет добавлять semgrep/zap без изменения кода задач.
Каждый сканер возвращает единый формат ScanFinding.
"""
from dataclasses import dataclass, field
from typing import Any

from app.models.vulnerability import SeverityLevel


@dataclass
class ScanFinding:
    """
    Нормализованный результат сканирования.

    Каждый сканер (bandit, semgrep, ...) преобразует свой вывод в этот формат.
    Дальше задача создаёт Vulnerability из ScanFinding.
    """
    title: str
    description: str
    severity: SeverityLevel
    cwe: int | None = None
    cvss: float | None = None
    scanner_metadata: dict[str, Any] = field(default_factory=dict)


class ScannerError(Exception):
    """Ошибка сканера: не найден target, упал subprocess, битый JSON."""
    pass


class BaseScanner:
    """
    Интерфейс сканера. Наследники реализуют `name` и `scan()`.

    Атрибут name попадает в Vulnerability.scanner.
    """
    name: str = "base"

    def scan(self, target: str) -> list[ScanFinding]:
        """
        Запустить сканирование target (файл или директория).

        Args:
            target: путь внутри контейнера. Валидацию делаем в задаче.

        Returns:
            Список находок. Пустой список — не ошибка (чисто).

        Raises:
            ScannerError: если инструмент упал или вернул битый JSON.
        """
        raise NotImplementedError