"""
Scanner на базе semgrep — мультиязычный SAST (Python/JS/Go/Java...).

Отличия от bandit:
- Формат JSON другой (results[].extra.metadata.cwe и т.д.)
- Severity: INFO / WARNING / ERROR (не LOW/MEDIUM/HIGH)
- Правила грузятся из registry (--config=auto), кешируются в ~/.semgrep
- CWE приходит строкой вида 'CWE-95: ...', нужно распарсить
"""
import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any

from app.models.vulnerability import SeverityLevel
from app.services.scanner.base import BaseScanner, ScanFinding, ScannerError

logger = logging.getLogger(__name__)


# Semgrep severity → наш SeverityLevel.
# INFO — стилистические находки/подозрительное, WARNING — реальная проблема
# средней критичности, ERROR — серьёзная (инъекции, RCE).
_SEMGREP_SEVERITY_MAP = {
    "INFO": SeverityLevel.LOW,
    "WARNING": SeverityLevel.MEDIUM,
    "ERROR": SeverityLevel.HIGH,
}

_CWE_RE = re.compile(r"CWE-(\d+)")


class SemgrepScanner(BaseScanner):
    """SAST-сканер для мультиязычного кода на базе semgrep."""

    name = "semgrep"

    DEFAULT_TIMEOUT = 300

    def __init__(
        self,
        timeout: int | None = None,
        config: str = "auto",
    ) -> None:
        """
        Args:
            timeout: таймаут на запуск.
            config: какой набор правил использовать.
                'auto' — semgrep сам подбирает правила по языкам файлов
                (требует интернет при первом запуске).
                Можно указать 'p/security-audit', 'p/python' и т.д.
        """
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self.config = config

    def scan(self, target: str) -> list[ScanFinding]:
        """
        Запускает semgrep и парсит JSON.
        """
        if not Path(target).exists():
            raise ScannerError(f"Target not found: {target}")

        #  shell=False + список аргументов. Никаких f-строк в команде.
        cmd = [
            "semgrep",
            "--json",
            "--quiet",
            "--config", self.config,
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
            raise ScannerError(f"Semgrep timeout after {self.timeout}s") from e
        except FileNotFoundError as e:
            raise ScannerError("Semgrep not installed in container") from e

        if result.returncode not in (0, 1):
            raise ScannerError(
                f"Semgrep failed (rc={result.returncode}): "
                f"{result.stderr.strip()[:500]}"
            )

        try:
            payload: dict[str, Any] = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise ScannerError(
                f"Semgrep returned invalid JSON: {result.stdout[:200]!r}"
            ) from e

        findings: list[ScanFinding] = []
        for raw in payload.get("results", []):
            findings.append(self._to_finding(raw))

        logger.info("Semgrep found %d issues in %s", len(findings), target)
        return findings

    def _to_finding(self, raw: dict[str, Any]) -> ScanFinding:
        """Преобразует одну semgrep-находку в ScanFinding."""
        check_id: str = raw.get("check_id", "unknown")
        path: str = raw.get("path", "")
        start: dict[str, Any] = raw.get("start", {})
        end: dict[str, Any] = raw.get("end", {})
        extra: dict[str, Any] = raw.get("extra", {})
        metadata: dict[str, Any] = extra.get("metadata", {}) or {}

        message: str = extra.get("message", "")
        severity_str: str = (extra.get("severity") or "INFO").upper()
        lines: str = extra.get("lines", "")

        severity = _SEMGREP_SEVERITY_MAP.get(severity_str, SeverityLevel.LOW)

        # CWE приходит списком строк. Берём первый и парсим число.
        cwe: int | None = None
        raw_cwes = metadata.get("cwe") or []
        if isinstance(raw_cwes, str):
            raw_cwes = [raw_cwes]
        for raw_cwe in raw_cwes:
            m = _CWE_RE.search(str(raw_cwe))
            if m:
                cwe = int(m.group(1))
                break

        line_no = start.get("line")
        title = f"[{check_id}] {message}"[:500]

        description_parts = [
            message,
            "",
            f"Rule: {check_id}",
            f"File: {path}:{line_no}",
        ]
        references = metadata.get("references") or []
        if references:
            description_parts.append(f"References: {', '.join(references[:3])}")
        if lines:
            description_parts.extend(["", "Vulnerable code:", lines])
        description = "\n".join(description_parts)

        return ScanFinding(
            title=title,
            description=description,
            severity=severity,
            cwe=cwe,
            cvss=None,
            scanner_metadata={
                "check_id": check_id,
                "path": path,
                "start": start,
                "end": end,
                "metadata": metadata,
                "lines": lines,
            },
        )