"""
Scanner на базе bandit — Python SAST.

Запускает bandit CLI через subprocess, парсит JSON, нормализует результат.
"""
import json
import logging
import subprocess
from pathlib import Path
from typing import Any

from app.models.vulnerability import SeverityLevel
from app.services.scanner.base import BaseScanner, ScanFinding, ScannerError

logger = logging.getLogger(__name__)


_BANDIT_SEVERITY_MAP = {
    "LOW": SeverityLevel.LOW,
    "MEDIUM": SeverityLevel.MEDIUM,
    "HIGH": SeverityLevel.HIGH,
    "UNDEFINED": SeverityLevel.INFO,
}

_BANDIT_TO_CWE: dict[str, int] = {
    "B101": 703,   # assert_used
    "B102": 502,   # exec_used
    "B104": 1327,  # hardcoded_bind_all_interfaces
    "B105": 259,   # hardcoded_password_string
    "B106": 259,   # hardcoded_password_funcarg
    "B107": 259,   # hardcoded_password_default
    "B301": 502,   # pickle
    "B307": 95,    # eval
    "B324": 327,   # weak hashlib
    "B501": 295,   # requests without verify
    "B602": 78,    # subprocess with shell=True
    "B608": 89,    # hardcoded_sql_expressions
    "B701": 1336,  # jinja2 autoescape off
}


class BanditScanner(BaseScanner):
    """SAST-сканер для Python-кода на базе bandit."""

    name = "bandit"

    DEFAULT_TIMEOUT = 120

    def __init__(self, timeout: int | None = None) -> None:
        self.timeout = timeout or self.DEFAULT_TIMEOUT

    def scan(self, target: str) -> list[ScanFinding]:
        """
        Запускает bandit на target и парсит вывод.

        Args:
            target: путь к файлу или директории внутри контейнера.

        Raises:
            ScannerError: если target не существует, bandit упал с
                невосстановимой ошибкой (кроме "нашёл уязвимости" — это exit code 1),
                или вернул битый JSON.
        """
        if not Path(target).exists():
            raise ScannerError(f"Target not found: {target}")

        cmd = [
            "bandit",
            "-f", "json",
            "-q",
            "-r",
            target,
        ]

        logger.info("Running: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise ScannerError(f"Bandit timeout after {self.timeout}s") from e
        except FileNotFoundError as e:
            raise ScannerError("Bandit not installed in container") from e

        # 3. Парсинг JSON
        # bandit возвращает:
        #   exit 0 — чисто
        #   exit 1 — нашёл issues (это не ошибка!)
        #   exit 2 — настоящая ошибка (битый target, краш)
        if result.returncode == 2:
            raise ScannerError(f"Bandit failed: {result.stderr.strip()[:500]}")

        try:
            payload: dict[str, Any] = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise ScannerError(
                f"Bandit returned invalid JSON: {result.stdout[:200]!r}"
            ) from e

        # 4. Нормализация findings
        findings: list[ScanFinding] = []
        for raw in payload.get("results", []):
            findings.append(self._to_finding(raw))

        logger.info("Bandit found %d issues in %s", len(findings), target)
        return findings

    def _to_finding(self, raw: dict[str, Any]) -> ScanFinding:
        """Преобразует одну bandit-находку в ScanFinding."""
        test_id: str = raw.get("test_id", "")
        test_name: str = raw.get("test_name", "unknown")
        issue_text: str = raw.get("issue_text", "")
        severity_str: str = raw.get("issue_severity", "UNDEFINED").upper()
        line_number: int | None = raw.get("line_number")
        filename: str = raw.get("filename", "")
        code: str = raw.get("code", "")
        more_info: str = raw.get("more_info", "")

        severity = _BANDIT_SEVERITY_MAP.get(severity_str, SeverityLevel.INFO)
        cwe = _BANDIT_TO_CWE.get(test_id)

        # title — короткая строка для списка
        title = f"[{test_id}] {issue_text}"[:500]

        # description — подробное описание
        description_parts = [
            issue_text,
            "",
            f"Rule: {test_name} ({test_id})",
            f"File: {filename}:{line_number}",
            f"More info: {more_info}",
        ]
        if code:
            description_parts.extend(["", "Vulnerable code:", code])
        description = "\n".join(description_parts)

        return ScanFinding(
            title=title,
            description=description,
            severity=severity,
            cwe=cwe,
            cvss=None,   # bandit не даёт CVSS
            scanner_metadata={
                "test_id": test_id,
                "test_name": test_name,
                "issue_confidence": raw.get("issue_confidence"),
                "filename": filename,
                "line_number": line_number,
                "line_range": raw.get("line_range"),
                "more_info": more_info,
                "code": code,
            },
        )