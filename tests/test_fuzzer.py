"""Unit tests for fuzzer.py with mocked timeout and connection errors."""

import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

import httpx

from core.crawler import URLInfo
from core.fuzzer import Fuzzer


class TestFuzzer(unittest.IsolatedAsyncioTestCase):
    """Test Fuzzer graceful degradation with mocked HTTP responses."""

    def setUp(self):
        """Set up test fixtures."""
        self.fuzzer = Fuzzer(timeout=5.0, max_concurrent=10)
        self.url_info = URLInfo(
            url="http://localhost/test?param=value",
            base_url="http://localhost/test",
            params={"param": "value"},
            form_inputs=[{"user": "admin", "_method": "post", "_action": "/login"}]
        )

    async def test_fuzzer_timeout_handling(self):
        """Test fuzzer handles timeout gracefully without crashing."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client

            mock_client.get.side_effect = httpx.TimeoutException("Request timeout")

            results = await self.fuzzer.fuzz_url_params(
                mock_client, self.url_info, ["' OR '1'='1"]
            )

            self.assertGreater(len(results), 0)
            self.assertIn("Timeout", results[0].error)

    async def test_fuzzer_connection_error_handling(self):
        """Test fuzzer handles connection errors gracefully."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client

            mock_client.get.side_effect = httpx.ConnectError("Connection refused")

            results = await self.fuzzer.fuzz_url_params(
                mock_client, self.url_info, ["' OR '1'='1"]
            )

            self.assertGreater(len(results), 0)
            error_found = any("Connection" in r.error for r in results if r.error)
            self.assertTrue(error_found)

    async def test_fuzzer_form_params_timeout(self):
        """Test fuzzer handles timeout for form parameter fuzzing."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client

            mock_client.post.side_effect = httpx.TimeoutException("Request timeout")

            results = await self.fuzzer.fuzz_form_params(
                mock_client, self.url_info, ["<script>alert(1)</script>"]
            )

            self.assertGreater(len(results), 0)

    async def test_fuzzer_graceful_degradation_continues_on_error(self):
        """Test fuzzer continues processing other payloads after errors."""
        call_count = 0

        async def mock_get(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise httpx.TimeoutException("First request failed")
            response = Mock()
            response.status_code = 200
            response.content = b"<html></html>"
            response.text = "<html></html>"
            return response

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = mock_get
            mock_client_class.return_value.__aenter__.return_value = mock_client

            results = await self.fuzzer.fuzz_url_params(
                mock_client, self.url_info, ["payload1", "payload2"]
            )

            self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
