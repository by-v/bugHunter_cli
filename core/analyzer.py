"""Core analyzer module for bugHunter CLI.

Analyzes fuzzer responses for vulnerability indicators.
Detects SQL injection, XSS, command injection, path traversal.
Uses payload reflection detection for accurate XSS identification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from core.fuzzer import FuzzResult

if TYPE_CHECKING:
    from collections.abc import Sequence


class VulnerabilityType(Enum):
    """Types of detected vulnerabilities."""

    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    XSS_REFLECTED = "xss_reflected"
    FILE_INCLUSION = "file_inclusion"
    PATH_TRAVERSAL = "path_traversal"
    ERROR_EXPOSURE = "error_exposure"
    LATENCY_INJECTION = "latency_injection"
    UNKNOWN = "unknown"


@dataclass
class Detection:
    """Single vulnerability detection result."""

    url: str
    method: str
    param_name: str
    payload: str
    vuln_type: VulnerabilityType
    confidence: float
    evidence: str
    details: dict[str, str] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    """Analysis result for a single fuzz request."""

    fuzz_result: FuzzResult
    detections: list[Detection] = field(default_factory=list)
    is_error: bool = False
    error_type: str | None = None


class Analyzer:
    """Analyze fuzzer responses for vulnerability indicators."""

    SQL_ERROR_PATTERNS = [
        # MySQL errors
        r"(?i)(mysql_num_rows|mysql_fetch|mysqli_fetch|mysqli_query|mysqli_error).*\(.*\)",
        r"(?i)mysql_fetch_(array|assoc|row|object)",
        r"(?i)mysqli_fetch_(array|assoc|row|object)",
        r"(?i)sql syntax.*near.*at line \d+",
        r"(?i)sql syntax.*mysql server version",
        r"(?i)uncaught mysqli_sql_exception",
        # PostgreSQL errors
        r"(?i)pg_(query|exec|fetch|num_rows)",
        r"(?i)postgresql.*error",
        r"(?i)psql.*syntax error",
        # SQLite errors
        r"(?i)sqlite_(query|exec|error)",
        r"(?i)sqlite3_(prepare|step)",
        r"(?i)uncaught sqlite_exception",
        # SQL Server errors
        r"(?i)sqlserver.*syntax",
        r"(?i)sql server.*near.*at line",
        r"(?i)unclosed quotation mark",
        r"(?i)quoted string not properly terminated",
        # Generic SQL patterns (more specific)
        r"(?i)select.*from.*where.*\d+\s*=\s*\d+",
        r"(?i)union\s+select",
        r"(?i)drop\s+table",
        r"(?i)insert\s+into",
        r"(?i)delete\s+from",
    ]

    COMMAND_INJECTION_PATTERNS = [
        r"(?i)sh:\s+\d+:\s+[^:]+:\s+No such file or directory",
        r"(?i)command not found",
        r"(?i)bash:\s+[^:]+:\s+command not found",
        r"(?i)usage:\s+\S+\s+\[.*\]",
        r"(?i)unknown option",
        r"(?i)invalid argument",
        r"(?i)permission denied",
        r"(?i)cannot execute",
        r"(?i)process failed",
    ]

    XSS_PATTERNS = [
        # Script tags (exact reflection)
        r"(?i)<script[^>]*>.*?</script>",
        # Event handlers (exact reflection)
        r"(?i)on\w+\s*=\s*[\"']?[^\"'>\s]+[\"']?",
        # JavaScript URIs (exact reflection)
        r"(?i)javascript\s*:",
        # Image onError (exact reflection)
        r"(?i)<img[^>]+onerror\s*=",
        # SVG onload (exact reflection)
        r"(?i)<svg[^>]+onload\s*=",
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"(?i)/etc/passwd",
        r"(?i)/etc/shadow",
        r"(?i)root:x:\d+:\d+:",
        r"(?i)boot\s+loader",
        r"(?i)windows\s+system32",
        r"(?i)system32\s+drivers",
        r"(?i)access is denied",
        r"(?i)file not found",
        r"(?i)file path too long",
        r"(?i)invalid filename",
        r"(?i)directory not found",
    ]

    def __init__(self, base_latency_ms: float = 100.0, latency_threshold_ms: float = 2000.0) -> None:
        """Initialize analyzer.

        Args:
            base_latency_ms: Expected baseline latency for normal requests.
            latency_threshold_ms: Threshold above base latency indicating possible injection.
        """
        self.base_latency_ms = base_latency_ms
        self.latency_threshold_ms = latency_threshold_ms
        self._sql_patterns = [re.compile(p) for p in self.SQL_ERROR_PATTERNS]
        self._cmd_patterns = [re.compile(p) for p in self.COMMAND_INJECTION_PATTERNS]
        self._xss_patterns = [re.compile(p) for p in self.XSS_PATTERNS]
        self._path_patterns = [re.compile(p) for p in self.PATH_TRAVERSAL_PATTERNS]

    def _has_sql_error(self, response_text: str) -> tuple[bool, str | None]:
        """Check for SQL error patterns in response."""
        for pattern in self._sql_patterns:
            match = pattern.search(response_text)
            if match:
                return True, match.group(0)
        return False, None

    def _has_command_injection(self, response_text: str) -> tuple[bool, str | None]:
        """Check for command injection patterns in response."""
        for pattern in self._cmd_patterns:
            match = pattern.search(response_text)
            if match:
                return True, match.group(0)
        return False, None

    def _has_xss_reflected(self, response_text: str, payload_injected: str) -> tuple[bool, str | None]:
        """Check for reflected XSS payload in response text.

        Only matches if:
        1. Payload is longer than 3 characters
        2. Payload contains XSS special characters (<, >, ", ', script, onerror, onload)
        3. Payload is exactly reflected in the response
        """
        if not payload_injected:
            return False, None

        # Reject micro false positives: payloads shorter than 4 characters
        # Single/double quotes are too common in HTML and cause false positives
        if len(payload_injected) <= 3:
            return False, None

        # Check if payload contains XSS special characters
        has_xss_chars = any(c in payload_injected for c in ['<', '>', '"', "'", 'script', 'onerror', 'onload'])

        # Also check for event handlers pattern
        if not has_xss_chars:
            xss_handlers = ['onerror=', 'onload=', 'onclick=', 'onmouseover=']
            if not any(h in payload_injected.lower() for h in xss_handlers):
                return False, None

        # Check for exact reflection in response
        pattern = re.compile(re.escape(payload_injected), re.IGNORECASE)
        match = pattern.search(response_text)

        if match:
            return True, payload_injected

        return False, None

    def _has_path_traversal(self, response_text: str) -> tuple[bool, str | None]:
        """Check for path traversal patterns in response."""
        for pattern in self._path_patterns:
            match = pattern.search(response_text)
            if match:
                return True, match.group(0)
        return False, None

    def _check_latency_injection(self, latency_ms: float) -> bool:
        """Check if latency suggests time-based injection."""
        return latency_ms > (self.base_latency_ms + self.latency_threshold_ms)

    def _check_status_change(
        self,
        status_code: int,
        normal_status: int = 200,
    ) -> tuple[bool, str | None]:
        """Check for unexpected HTTP status changes."""
        if status_code == 500:
            return True, "Internal Server Error"
        if status_code == 403:
            return True, "Forbidden"
        if status_code == 404:
            return True, "Not Found"
        if status_code == 302 or status_code == 301:
            return True, "Redirect detected"
        if status_code == 0:
            return True, "Connection failed"
        return False, None

    def analyze_response(
        self,
        fuzz_result: FuzzResult,
        normal_status: int = 200,
    ) -> AnalysisResult:
        """Analyze a single fuzz result for vulnerabilities.

        Args:
            fuzz_result: Result from fuzzer.
            normal_status: Expected HTTP status for clean requests.

        Returns:
            Analysis result with detections.
        """
        detections: list[Detection] = []
        is_error = False
        error_type: str | None = None

        payload_injected = fuzz_result.payload

        # Check for SQL injection (error-based)
        has_error, evidence = self._has_sql_error(fuzz_result.response_text)
        if has_error:
            detections.append(
                Detection(
                    url=fuzz_result.original_url,
                    method=fuzz_result.method.name,
                    param_name=fuzz_result.param_name,
                    payload=fuzz_result.payload,
                    vuln_type=VulnerabilityType.SQL_INJECTION,
                    confidence=0.9,
                    evidence=evidence or "SQL error pattern detected",
                    details={
                        "param": fuzz_result.param_name,
                        "payload": fuzz_result.payload,
                        "status_code": str(fuzz_result.status_code),
                    },
                )
            )
            is_error = True
            error_type = "sql_error"

        # Check for command injection
        has_cmd_error, evidence = self._has_command_injection(fuzz_result.response_text)
        if has_cmd_error:
            detections.append(
                Detection(
                    url=fuzz_result.original_url,
                    method=fuzz_result.method.name,
                    param_name=fuzz_result.param_name,
                    payload=fuzz_result.payload,
                    vuln_type=VulnerabilityType.COMMAND_INJECTION,
                    confidence=0.85,
                    evidence=evidence or "Command injection pattern detected",
                    details={
                        "param": fuzz_result.param_name,
                        "payload": fuzz_result.payload,
                        "status_code": str(fuzz_result.status_code),
                    },
                )
            )
            is_error = True
            error_type = "command_error"

        # Check for XSS - ONLY if payload is reflected in response
        has_xss, evidence = self._has_xss_reflected(fuzz_result.response_text, payload_injected)
        if has_xss:
            detections.append(
                Detection(
                    url=fuzz_result.original_url,
                    method=fuzz_result.method.name,
                    param_name=fuzz_result.param_name,
                    payload=fuzz_result.payload,
                    vuln_type=VulnerabilityType.XSS_REFLECTED,
                    confidence=0.95,
                    evidence=f"Payload reflected: {evidence}",
                    details={
                        "param": fuzz_result.param_name,
                        "payload": fuzz_result.payload,
                        "status_code": str(fuzz_result.status_code),
                    },
                )
            )
            is_error = True
            error_type = "xss_reflection"

        # Check for path traversal
        has_path, evidence = self._has_path_traversal(fuzz_result.response_text)
        if has_path:
            detections.append(
                Detection(
                    url=fuzz_result.original_url,
                    method=fuzz_result.method.name,
                    param_name=fuzz_result.param_name,
                    payload=fuzz_result.payload,
                    vuln_type=VulnerabilityType.PATH_TRAVERSAL,
                    confidence=0.8,
                    evidence=evidence or "Path traversal pattern detected",
                    details={
                        "param": fuzz_result.param_name,
                        "payload": fuzz_result.payload,
                        "status_code": str(fuzz_result.status_code),
                    },
                )
            )
            is_error = True
            error_type = "path_traversal"

        # Check for latency-based injection (time-based SQLi)
        if self._check_latency_injection(fuzz_result.latency_ms):
            detections.append(
                Detection(
                    url=fuzz_result.original_url,
                    method=fuzz_result.method.name,
                    param_name=fuzz_result.param_name,
                    payload=fuzz_result.payload,
                    vuln_type=VulnerabilityType.LATENCY_INJECTION,
                    confidence=0.7,
                    evidence=f"Latency: {fuzz_result.latency_ms:.0f}ms (threshold: {self.latency_threshold_ms}ms)",
                    details={
                        "param": fuzz_result.param_name,
                        "payload": fuzz_result.payload,
                        "latency_ms": str(fuzz_result.latency_ms),
                        "threshold_ms": str(self.latency_threshold_ms),
                    },
                )
            )
            is_error = True
            error_type = "latency_injection"

        # Check for status code changes
        is_status_changed, status_reason = self._check_status_change(
            fuzz_result.status_code,
            normal_status,
        )
        if is_status_changed:
            detections.append(
                Detection(
                    url=fuzz_result.original_url,
                    method=fuzz_result.method.name,
                    param_name=fuzz_result.param_name,
                    payload=fuzz_result.payload,
                    vuln_type=VulnerabilityType.ERROR_EXPOSURE,
                    confidence=0.6,
                    evidence=status_reason or "Unexpected status code",
                    details={
                        "param": fuzz_result.param_name,
                        "payload": fuzz_result.payload,
                        "status_code": str(fuzz_result.status_code),
                        "expected_status": str(normal_status),
                    },
                )
            )
            is_error = True
            if error_type is None:
                error_type = "status_change"

        return AnalysisResult(
            fuzz_result=fuzz_result,
            detections=detections,
            is_error=is_error,
            error_type=error_type,
        )

    def analyze_batch(
        self,
        fuzz_results: list[FuzzResult],
        normal_status: int = 200,
    ) -> list[AnalysisResult]:
        """Analyze a batch of fuzz results.

        Args:
            fuzz_results: List of results from fuzzer.
            normal_status: Expected HTTP status for clean requests.

        Returns:
            List of analysis results.
        """
        return [
            self.analyze_response(result, normal_status) for result in fuzz_results
        ]
