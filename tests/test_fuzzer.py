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

    async def test_fuzzer_absolute_form_action_no_duplication(self):
        """Test fuzzer does not duplicate URL when form action is absolute."""
        fuzzer = Fuzzer(timeout=5.0, max_concurrent=10)
        url_info = URLInfo(
            url="http://127.0.0.1:8000/",
            base_url="http://127.0.0.1:8000/",
            params={},
            form_inputs=[
                {
                    "_method": "post",
                    "_action": "http://127.0.0.1:8000/login",
                    "username": "test",
                    "password": "pass",
                }
            ],
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client

            response = Mock()
            response.status_code = 200
            response.content = b"<html></html>"
            response.text = "<html></html>"
            mock_client.post.return_value = response

            results = await fuzzer.fuzz_form_params(
                mock_client, url_info, ["' OR '1'='1"]
            )

            self.assertGreater(len(results), 0)
            for result in results:
                self.assertEqual(result.original_url, "http://127.0.0.1:8000/login")
                self.assertNotIn("http://127.0.0.1:8000/http://", result.original_url)
    async def test_fuzzer_form_data_includes_csrf_token_and_all_fields(self):
        """Test POST form data forwards the CSRF token and keeps other fields."""
        fuzzer = Fuzzer(timeout=5.0, max_concurrent=10)
        url_info = URLInfo(
            url="http://localhost/",
            base_url="http://localhost/",
            params={},
            form_inputs=[
                {
                    "_method": "post",
                    "_action": "/login",
                    "_csrf_token": "tok123",
                    "user": "admin",
                    "pass": "secret",
                }
            ],
        )
        payload = "' OR '1'='1"
        calls = []

        async def fake_post(url, data=None):
            calls.append({"url": url, "data": data})
            return Mock(status_code=200, content=b"<html></html>", text="<html></html>")

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = fake_post
            mock_client_class.return_value.__aenter__.return_value = mock_client

            results = await fuzzer.fuzz_form_params(mock_client, url_info, [payload])

            self.assertEqual(len(results), 2)
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0]["url"], "http://localhost/login")
            # First fuzz target is "user": payload injected, others preserved.
            self.assertEqual(calls[0]["data"]["_token"], "tok123")
            self.assertEqual(calls[0]["data"]["user"], payload)
            self.assertEqual(calls[0]["data"]["pass"], "secret")
            # Second fuzz target is "pass".
            self.assertEqual(calls[1]["data"]["_token"], "tok123")
            self.assertEqual(calls[1]["data"]["user"], "admin")
            self.assertEqual(calls[1]["data"]["pass"], payload)

    async def test_fuzzer_backoff_retries_on_429_then_succeeds(self):
        """Test fuzzer retries after HTTP 429 with backoff and then succeeds."""
        fuzzer = Fuzzer(
            timeout=2.0,
            max_concurrent=1,
            max_retries=2,
            retry_backoff_base=0.01,
        )
        call_urls = []

        async def fake_get(url):
            call_urls.append(url)
            if len(call_urls) == 1:
                return Mock(status_code=429, content=b"", text="")
            return Mock(status_code=200, content=b"<html></html>", text="<html></html>")

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = fake_get
            mock_client_class.return_value.__aenter__.return_value = mock_client

            results = await fuzzer.fuzz_url_params(
                mock_client, self.url_info, ["payload"]
            )

            self.assertEqual(len(call_urls), 2)
            self.assertEqual(results[0].status_code, 200)
            self.assertIsNone(results[0].error)

    async def test_fuzzer_429_persistent_marks_rate_limited(self):
        """Test persistent HTTP 429 is reported as rate limited after retries."""
        fuzzer = Fuzzer(
            timeout=2.0,
            max_concurrent=1,
            max_retries=2,
            retry_backoff_base=0.01,
        )
        call_urls = []

        async def fake_get(url):
            call_urls.append(url)
            return Mock(status_code=429, content=b"", text="")

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = fake_get
            mock_client_class.return_value.__aenter__.return_value = mock_client

            results = await fuzzer.fuzz_url_params(
                mock_client, self.url_info, ["payload"]
            )

            # initial attempt + max_retries retries
            self.assertEqual(len(call_urls), 3)
            self.assertEqual(results[0].status_code, 429)
            self.assertIn("Rate limited", results[0].error)

    async def test_fuzzer_skips_dead_link_urls(self):
        """Test clean GET returning 4xx skips fuzzing the URL entirely."""
        fuzzer = Fuzzer(timeout=2.0, max_concurrent=10)
        calls = []

        async def fake_get(url):
            calls.append(url)
            return Mock(status_code=404, content=b"", text="")

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = fake_get
            mock_client_class.return_value.__aenter__.return_value = mock_client

            results = await fuzzer.fuzz_all(mock_client, self.url_info, ["payload"])

            self.assertEqual(results, [])
            self.assertEqual(len(calls), 1)

    async def test_fuzzer_get_form_uses_resolved_absolute_url(self):
        """Test GET forms resolve relative actions to absolute URLs."""
        fuzzer = Fuzzer(timeout=5.0, max_concurrent=10)
        url_info = URLInfo(
            url="http://localhost/search",
            base_url="http://localhost/",
            params={},
            form_inputs=[{"_method": "get", "_action": "results", "q": "x"}],
        )
        urls = []

        async def fake_get(url):
            urls.append(url)
            return Mock(status_code=200, content=b"<html></html>", text="<html></html>")

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = fake_get
            mock_client_class.return_value.__aenter__.return_value = mock_client

            results = await fuzzer.fuzz_form_params(mock_client, url_info, ["payload"])

            self.assertEqual(len(results), 1)
            self.assertTrue(all(u.startswith("http://localhost/") for u in urls))

    async def test_fuzzer_get_form_payload_forwarded_in_query(self):
        """Test GET forms send the payload (and other fields) as query string."""
        fuzzer = Fuzzer(timeout=5.0, max_concurrent=10)
        url_info = URLInfo(
            url="http://localhost/dvwa/xss_r/?name=test",
            base_url="http://localhost/dvwa/xss_r/",
            params={},
            form_inputs=[{"_method": "get", "_action": "#", "name": "test"}],
        )
        urls = []

        async def fake_get(url):
            urls.append(url)
            return Mock(status_code=200, content=b"<html></html>", text="<html></html>")

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = fake_get
            mock_client_class.return_value.__aenter__.return_value = mock_client

            results = await fuzzer.fuzz_form_params(
                mock_client, url_info, ["<script>alert(1)</script>"]
            )

            self.assertEqual(len(urls), 1)
            self.assertEqual(len(results), 1)
            from urllib.parse import parse_qs, urlsplit

            parsed = urlsplit(urls[0])
            self.assertEqual(parsed.netloc, "localhost")
            self.assertEqual(parsed.path, "/dvwa/xss_r/")
            query = parse_qs(parsed.query)
            self.assertEqual(query.get("name"), ["<script>alert(1)</script>"])

    async def test_fuzzer_get_form_relative_action_resolved(self):
        """Test relative GET form actions resolve against the page URL."""
        fuzzer = Fuzzer(timeout=5.0, max_concurrent=10)
        url_info = URLInfo(
            url="http://localhost/dvwa/xss_r/?name=test",
            base_url="http://localhost/dvwa/xss_r/",
            params={},
            form_inputs=[{"_method": "get", "_action": "search.php", "q": "x"}],
        )
        urls = []

        async def fake_get(url):
            urls.append(url)
            return Mock(status_code=200, content=b"", text="")

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = fake_get
            mock_client_class.return_value.__aenter__.return_value = mock_client

            await fuzzer.fuzz_form_params(mock_client, url_info, ["p"])

            self.assertTrue(
                urls[0].startswith("http://localhost/dvwa/xss_r/search.php?q=")
            )


if __name__ == "__main__":
    unittest.main()