"""Unit tests for analyzer.py response analysis."""

import unittest

from core.analyzer import Analyzer, VulnerabilityType


class TestAnalyzer(unittest.TestCase):
    """Test Analyzer response analysis."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = Analyzer(base_latency_ms=100.0, latency_threshold_ms=2000.0)

    def test_sql_error_detection(self):
        """Test SQL error pattern detection."""
        response_text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '1'='1' at line 1"
        has_error, evidence = self.analyzer._has_sql_error(response_text)
        self.assertTrue(has_error)
        self.assertIsNotNone(evidence)

    def test_xss_reflection_detection(self):
        """Test XSS reflection detection."""
        response_text = "<script>alert('XSS')</script>"
        has_error, evidence = self.analyzer._has_xss_reflected(response_text, "<script>alert('XSS')</script>")
        self.assertTrue(has_error)
        self.assertIsNotNone(evidence)

    def test_no_false_positives(self):
        """Test that normal responses don't trigger false positives."""
        response_text = "<html><body>Welcome to the site</body></html>"
        has_sql, _ = self.analyzer._has_sql_error(response_text)
        has_xss, _ = self.analyzer._has_xss_reflected(response_text, "<script>alert(1)</script>")
        self.assertFalse(has_sql)
        self.assertFalse(has_xss)

    def test_latency_injection_detection(self):
        """Test latency-based injection detection."""
        self.assertTrue(self.analyzer._check_latency_injection(2500.0))
        self.assertFalse(self.analyzer._check_latency_injection(150.0))


if __name__ == "__main__":
    unittest.main()
