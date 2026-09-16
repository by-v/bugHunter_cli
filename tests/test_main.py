"""Unit tests for main.py URL validation."""

import unittest
from unittest.mock import patch

from main import main


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
        })()
        result = main()
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
