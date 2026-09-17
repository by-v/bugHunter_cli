"""Tests for core.analyzer vulnerability detection logic.

Regression coverage for:
- SQL error pattern detection (native DB driver messages).
- Reflected XSS detection with evidence snippet.
- Command injection: shell-context "Permission denied" only (no PHP file-
  inclusion false positive).
- Error-exposure heuristics (5xx vs 4xx/redirect vs 429).
- Latency injection detection.
"""
import unittest

from core.analyzer import Analyzer, VulnerabilityType
from core.fuzzer import FuzzResult, HTTPMethod


class TestAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = Analyzer()

    def _fuzz_result(
        self,
        response_text,
        original_url="https://example.com/page?q=1",
        param_name="q",
        payload="test",
        method=HTTPMethod.GET,
        status_code=200,
        latency_ms=10.0,
        response_size=1024,
    ):
        return FuzzResult(
            original_url=original_url,
            method=method,
            param_name=param_name,
            payload=payload,
            status_code=status_code,
            latency_ms=latency_ms,
            response_size=response_size,
            response_text=response_text,
        )

    def test_sql_error_detection(self):
        fuzz_result = self._fuzz_result(
            response_text="Warning: mysqli_query(): You have an error in your "
            "SQL syntax; check the manual that corresponds to your MySQL "
            "server version for the right syntax to use near ''role=admin'' "
            "at line 1")
        analysis = self.analyzer.analyze_response(fuzz_result, normal_status=200)
        types = {d.vuln_type for d in analysis.detections}
        self.assertIn(VulnerabilityType.SQL_INJECTION, types)

    def test_xss_reflection_detection(self):
        fuzz_result = self._fuzz_result(
            original_url="https://dvwa.local/vulnerabilities/xss_r/?name=test",
            param_name="name",
            payload="<script>alert(1)</script>",
            response_text="<html>Hello <script>alert(1)</script> welcome</html>")
        analysis = self.analyzer.analyze_response(fuzz_result, normal_status=200)
        types = {d.vuln_type for d in analysis.detections}
        self.assertIn(VulnerabilityType.XSS_REFLECTED, types)

    def test_no_false_positives(self):
        fuzz_result = self._fuzz_result(
            response_text="<html><body><h1>Welcome to the site</h1>"
            "<p>Nothing malicious here at all.</p></body></html>")
        analysis = self.analyzer.analyze_response(fuzz_result, normal_status=200)
        self.assertEqual(analysis.detections, [])

    def test_latency_injection_detection(self):
        fuzz_result = self._fuzz_result(response_text="page rendered normally",
                                        latency_ms=12000.0)
        analysis = self.analyzer.analyze_response(fuzz_result, normal_status=200)
        types = {d.vuln_type for d in analysis.detections}
        self.assertIn(VulnerabilityType.LATENCY_INJECTION, types)

    def test_429_not_flagged_as_error_exposure(self):
        fuzz_result = self._fuzz_result(
            response_text="Too Many Requests", status_code=429)
        analysis = self.analyzer.analyze_response(fuzz_result, normal_status=200)
        types = {d.vuln_type for d in analysis.detections}
        self.assertNotIn(VulnerabilityType.ERROR_EXPOSURE, types)

    def test_4xx_and_redirects_not_flagged_as_error_exposure(self):
        for code in (400, 401, 403, 404, 409, 301, 302):
            fuzz_result = self._fuzz_result(
                response_text="client or redirect error", status_code=code)
            analysis = self.analyzer.analyze_response(
                fuzz_result, normal_status=200)
            types = {d.vuln_type for d in analysis.detections}
            self.assertNotIn(VulnerabilityType.ERROR_EXPOSURE, types,
                             f"status {code} should not be error exposure")

    def test_5xx_flagged_as_error_exposure(self):
        fuzz_result = self._fuzz_result(
            response_text="Server Error", status_code=500)
        analysis = self.analyzer.analyze_response(fuzz_result, normal_status=200)
        types = {d.vuln_type for d in analysis.detections}
        self.assertIn(VulnerabilityType.ERROR_EXPOSURE, types)

    def test_xss_detection_evidence_includes_snippet(self):
        payload = "<script>alert(1)</script>"
        fuzz_result = self._fuzz_result(
            original_url="https://dvwa.local/vulnerabilities/xss_r/?name=test",
            param_name="name",
            payload=payload,
            response_text=f"<html>Hello {payload} welcome</html>")
        analysis = self.analyzer.analyze_response(fuzz_result, normal_status=200)
        xss = [d for d in analysis.detections
               if d.vuln_type == VulnerabilityType.XSS_REFLECTED]
        self.assertEqual(len(xss), 1)
        snippet = xss[0].details.get("matched_snippet", "")
        self.assertIn(payload, snippet)

    def test_php_file_inclusion_permission_denied_not_command_injection(self):
        response_text = (
            "Warning: include(C:\\xampp\\htdocs\\dvwa\\vulnerabilities\\fi\\"
            '"bad"): Failed to open stream: Permission denied in '
            "C:\\xampp\\htdocs\\dvwa\\vulnerabilities\\fi\\index.php on line 24")
        fuzz_result = self._fuzz_result(
            original_url="https://dvwa.local/vulnerabilities/fi/?page=bad",
            param_name="page",
            payload="./../../../../etc/passwd",
            response_text=response_text)
        analysis = self.analyzer.analyze_response(fuzz_result, normal_status=200)
        types = {d.vuln_type for d in analysis.detections}
        self.assertNotIn(VulnerabilityType.COMMAND_INJECTION, types)

    def test_shell_permission_denied_is_command_injection(self):
        response_text = "sh: 1: ./id: Permission denied"
        fuzz_result = self._fuzz_result(
            original_url="https://dvwa.local/vulnerabilities/exec/",
            param_name="ip",
            payload="127.0.0.1;./id",
            response_text=response_text)
        analysis = self.analyzer.analyze_response(fuzz_result, normal_status=200)
        types = {d.vuln_type for d in analysis.detections}
        self.assertIn(VulnerabilityType.COMMAND_INJECTION, types)

    def test_bash_permission_denied_is_command_injection(self):
        response_text = "-bash: ./whoami: Permission denied"
        fuzz_result = self._fuzz_result(
            original_url="https://dvwa.local/vulnerabilities/exec/",
            param_name="ip",
            payload="127.0.0.1;./whoami",
            response_text=response_text)
        analysis = self.analyzer.analyze_response(fuzz_result, normal_status=200)
        types = {d.vuln_type for d in analysis.detections}
        self.assertIn(VulnerabilityType.COMMAND_INJECTION, types)

    def test_java_cannot_run_program_permission_denied_is_command_injection(
        self,
    ):
        response_text = ("java.io.IOException: Cannot run program "
                         '"./some_binary": error=13, Permission denied')
        fuzz_result = self._fuzz_result(
            original_url="https://target.local/exec",
            param_name="cmd",
            payload=";./some_binary",
            response_text=response_text)
        analysis = self.analyzer.analyze_response(fuzz_result, normal_status=200)
        types = {d.vuln_type for d in analysis.detections}
        self.assertIn(VulnerabilityType.COMMAND_INJECTION, types)


if __name__ == "__main__":
    unittest.main()
