"""Unit tests for main.py URL validation and cookie parsing."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from main import _probe_login_gate, main, parse_cookie_string, run_scan_async


class TestMainURLValidation(unittest.TestCase):
    """Test URL validation in main.py."""

    @patch("main.parse_args")
    def test_valid_http_url(self, mock_args):
        """Test that http:// URL is accepted."""
        mock_args.return_value = type("Args", (), {
            "target": "http://example.com",
            "depth": 3,
            "threads": 10,
            "output": "reports",
            "verbose": False,
            "cookie": "",
        })()
        with patch("main.run_scan_async") as mock_run:
            mock_run.return_value = 0
            result = main()
            self.assertEqual(result, 0)

    @patch("main.parse_args")
    def test_valid_https_url(self, mock_args):
        """Test that https:// URL is accepted."""
        mock_args.return_value = type("Args", (), {
            "target": "https://example.com",
            "depth": 3,
            "threads": 10,
            "output": "reports",
            "verbose": False,
            "cookie": "",
        })()
        with patch("main.run_scan_async") as mock_run:
            mock_run.return_value = 0
            result = main()
            self.assertEqual(result, 0)

    @patch("main.parse_args")
    def test_invalid_url_no_scheme(self, mock_args):
        """Test that URL without scheme is rejected."""
        mock_args.return_value = type("Args", (), {
            "target": "example.com",
            "depth": 3,
            "threads": 10,
            "output": "reports",
            "verbose": False,
            "cookie": "",
        })()
        result = main()
        self.assertEqual(result, 1)

    @patch("main.parse_args")
    def test_invalid_ftp_url(self, mock_args):
        """Test that ftp:// URL is rejected."""
        mock_args.return_value = type("Args", (), {
            "target": "ftp://example.com",
            "depth": 3,
            "threads": 10,
            "output": "reports",
            "verbose": False,
            "cookie": "",
        })()
        result = main()
        self.assertEqual(result, 1)

    @patch("main.parse_args")
    def test_invalid_url_no_netloc(self, mock_args):
        """Test that URL without domain is rejected."""
        mock_args.return_value = type("Args", (), {
            "target": "http://",
            "depth": 3,
            "threads": 10,
            "output": "reports",
            "verbose": False,
            "cookie": "",
        })()
        result = main()
        self.assertEqual(result, 1)


class TestCookieParser(unittest.TestCase):
    """Test --cookie string parsing into an httpx cookie dict."""

    def test_parse_single_cookie(self):
        """Test parsing a single name=value cookie."""
        self.assertEqual(
            parse_cookie_string("PHPSESSID=abc123"),
            {"PHPSESSID": "abc123"},
        )

    def test_parse_multiple_cookies(self):
        """Test parsing multiple cookies separated by semicolons."""
        self.assertEqual(
            parse_cookie_string("SESSION=a1b2; JSESSIONID=x9y8; logged_in=1"),
            {"SESSION": "a1b2", "JSESSIONID": "x9y8", "logged_in": "1"},
        )

    def test_parse_whitespace_and_embedded_equals(self):
        """Test that surrounding spaces are trimmed and inner '=' is kept."""
        self.assertEqual(
            parse_cookie_string("  name1 = val1 ; name2=val=ue  "),
            {"name1": "val1", "name2": "val=ue"},
        )

    def test_parse_empty_and_malformed(self):
        """Test empty input and malformed segments produce an empty/short dict."""
        self.assertEqual(parse_cookie_string(""), {})
        self.assertEqual(parse_cookie_string("   ;  ;  "), {})
        self.assertEqual(parse_cookie_string("onlykey;"), {})
        self.assertEqual(parse_cookie_string("; bogus ; ok=1"), {"ok": "1"})


class TestCookieClientInjection(unittest.TestCase):
    """Test that session cookies reach the shared httpx.AsyncClient."""

    def _run_scan(self, cookies: dict[str, str] | None):
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False
        mock_client.get.return_value = Mock(
            url="http://localhost/", text="<html>Healthy page</html>"
        )

        mock_reporter = MagicMock()
        mock_reporter.export_json.return_value = "reports/test.json"

        with patch("main.httpx.AsyncClient", return_value=mock_client) as mock_cls,              patch("main.do_crawl", AsyncMock(return_value=[])),              patch("main.Reporter", return_value=mock_reporter):
            asyncio.run(
                run_scan_async(
                    target_url="http://localhost",
                    depth=1,
                    threads=2,
                    output_dir="reports",
                    verbose=False,
                    cookies=cookies,
                )
            )
        return mock_cls

    def test_cookies_propagated_to_shared_client(self):
        """Test parsed cookies are passed to the shared AsyncClient."""
        cookies = {"SESSION": "abc", "JSESSIONID": "xyz"}
        mock_cls = self._run_scan(cookies)
        kwargs = mock_cls.call_args.kwargs
        self.assertIn("cookies", kwargs)
        self.assertEqual(kwargs["cookies"], cookies)

    def test_no_cookies_means_none(self):
        """Test the AsyncClient receives cookies=None when none are given."""
        mock_cls = self._run_scan(None)
        self.assertIsNone(mock_cls.call_args.kwargs["cookies"])

class TestLoginGateProbe(unittest.TestCase):
    """Test the session-cookie login-gate sanity probe."""

    def test_probe_detects_login_redirect(self):
        """Test a redirected login page is flagged."""
        response = Mock(url="http://localhost/dvwa/login.php", text="<html>login</html>")
        client = AsyncMock()
        client.get.return_value = response
        description = asyncio.run(
            _probe_login_gate(client, "http://localhost/dvwa/")
        )
        self.assertIsNotNone(description)
        self.assertIn("login", description.lower())

    def test_probe_detects_login_form_body(self):
        """Test an inline login form (password field) is flagged."""
        response = Mock(
            url="http://localhost/dvwa/vulnerabilities/",
            text='<form action="login.php"><input type="password" name="password"></form>',
        )
        client = AsyncMock()
        client.get.return_value = response
        description = asyncio.run(
            _probe_login_gate(client, "http://localhost/dvwa/vulnerabilities/")
        )
        self.assertIsNotNone(description)
        self.assertIn("password", description)

    def test_probe_returns_none_for_normal_page(self):
        """Test a healthy authenticated page produces no warning."""
        response = Mock(
            url="http://localhost/dvwa/vulnerabilities/xss_r/?name=test",
            text="<html>Hello test</html>",
        )
        client = AsyncMock()
        client.get.return_value = response
        description = asyncio.run(
            _probe_login_gate(
                client, "http://localhost/dvwa/vulnerabilities/xss_r/?name=test"
            )
        )
        self.assertIsNone(description)


if __name__ == "__main__":
    unittest.main()