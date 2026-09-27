"""
Юнит-тесты SemgrepScanner.

Subprocess мокается — проверяем только парсинг JSON.
Реальный semgrep запускается в integration-тестах вручную.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from app.models.vulnerability import SeverityLevel
from app.services.scanner import SemgrepScanner, ScannerError


# Пример реального вывода semgrep (упрощён до ключевых полей)
SAMPLE_SEMGREP_JSON = {
    "results": [
        {
            "check_id": "python.lang.security.audit.exec-detected.exec-detected",
            "path": "/app/demo/vulnerable_code.py",
            "start": {"line": 32, "col": 12},
            "end": {"line": 32, "col": 25},
            "extra": {
                "message": "Detected the use of exec().",
                "severity": "WARNING",
                "metadata": {
                    "cwe": [
                        "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"
                    ],
                    "references": ["https://owasp.org/..."],
                },
                "lines": "    return eval(code)",
            },
        },
        {
            "check_id": "python.lang.security.audit.subprocess-shell-true",
            "path": "/app/demo/vulnerable_code.py",
            "start": {"line": 20, "col": 5},
            "end": {"line": 20, "col": 45},
            "extra": {
                "message": "subprocess with shell=True",
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-78"]},
                "lines": "    subprocess.run(cmd, shell=True)",
            },
        },
    ],
    "errors": [],
}

def test_parses_semgrep_findings() -> None:
    findings = _make_scanner_into_findings(SAMPLE_SEMGREP_JSON)
    assert len(findings) == 2


def _make_scanner_into_findings(payload: dict) -> list:
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps(payload)
    mock_result.stderr = ""

    scanner = SemgrepScanner()
    with patch("app.services.scanner.semgrep.subprocess.run", return_value=mock_result):
        with patch("app.services.scanner.semgrep.Path.exists", return_value=True):
            return scanner.scan("/app/demo/vulnerable_code.py")


def test_severity_mapping() -> None:
    """WARNING → medium, ERROR → high."""
    findings = _make_scanner_into_findings(SAMPLE_SEMGREP_JSON)

    severities = {f.severity for f in findings}
    assert SeverityLevel.MEDIUM in severities
    assert SeverityLevel.HIGH in severities


def test_cwe_extraction_from_string() -> None:
    """CWE парсится из строки 'CWE-95: ...'."""
    findings = _make_scanner_into_findings(SAMPLE_SEMGREP_JSON)
    cwes = {f.cwe for f in findings}
    assert 95 in cwes
    assert 78 in cwes


def test_empty_results_returns_empty_list() -> None:
    findings = _make_scanner_into_findings({"results": [], "errors": []})
    assert findings == []


def test_target_not_found_raises() -> None:
    scanner = SemgrepScanner()
    with patch("app.services.scanner.semgrep.Path.exists", return_value=False):
        with pytest.raises(ScannerError, match="Target not found"):
            scanner.scan("/nonexistent/path.py")


def test_invalid_json_raises() -> None:
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "not valid json {{{"
    mock_result.stderr = ""

    scanner = SemgrepScanner()
    with patch("app.services.scanner.semgrep.subprocess.run", return_value=mock_result):
        with patch("app.services.scanner.semgrep.Path.exists", return_value=True):
            with pytest.raises(ScannerError, match="invalid JSON"):
                scanner.scan("/app/demo/vulnerable_code.py")


def test_fatal_returncode_raises() -> None:
    mock_result = MagicMock()
    mock_result.returncode = 2
    mock_result.stdout = ""
    mock_result.stderr = "Semgrep fatal error"

    scanner = SemgrepScanner()
    with patch("app.services.scanner.semgrep.subprocess.run", return_value=mock_result):
        with patch("app.services.scanner.semgrep.Path.exists", return_value=True):
            with pytest.raises(ScannerError, match="Semgrep failed"):
                scanner.scan("/app/demo/vulnerable_code.py")