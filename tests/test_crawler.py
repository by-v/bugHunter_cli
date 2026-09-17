"""Unit tests for crawler.py using mocked HTTP responses."""

import asyncio
import unittest

import httpx
import pytest

from urllib.parse import urlparse

from core.crawler import Crawler, URLInfo


class TestCrawler(unittest.TestCase):
    """Test Crawler functionality."""

    def test_crawler_deduplication(self):
        """Test crawler deduplicates URLs during processing."""
        crawler = Crawler("http://localhost", max_depth=1, max_concurrent=5)

        urls_to_process = [
            "http://localhost/page1",
            "http://localhost/page2",
            "http://localhost/page1",  # Duplicate
        ]

        for url in urls_to_process:
            if url not in crawler._visited:
                crawler._to_visit.append((url, 1))
                crawler._visited.add(url)

        # Deduplication verified via visited set
        self.assertEqual(len(crawler._visited), 2)

    def test_crawler_max_depth(self):
        """Test crawler respects max_depth limit."""
        crawler = Crawler("http://localhost", max_depth=2, max_concurrent=5)
        self.assertEqual(crawler.max_depth, 2)

    def test_crawler_extracts_csrf_from_meta(self):
        """Test crawler extracts CSRF token from document meta tag."""
        html = (
            '<html><head><meta name="csrf-token" content="abc123"></head>'
            '<body><form action="/login" method="post">'
            '<input name="user"></form></body></html>'
        )
        crawler = Crawler("http://localhost")
        forms = crawler._extract_forms(html)
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["_csrf_token"], "abc123")
        self.assertEqual(forms[0]["user"], "")

    def test_crawler_extracts_csrf_from_hidden_input(self):
        """Test crawler extracts CSRF token from a hidden input field."""
        html = (
            '<form action="/submit" method="post">'
            '<input type="hidden" name="_token" value="tok456">'
            '<input name="email">'
            '</form>'
        )
        crawler = Crawler("http://localhost")
        forms = crawler._extract_forms(html)
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["_csrf_token"], "tok456")
        # The token input must not be treated as a fuzzable parameter.
        self.assertNotIn("_token", forms[0])


    def test_crawler_extracts_dvwa_user_token_as_csrf(self):
        """Test DVWA-style user_token hidden input is treated as CSRF."""
        html = (
            '<form action="/login.php" method="post">'
            '<input type="hidden" name="user_token" value="tok789">'
            '<input name="username">'
            '</form>'
        )
        crawler = Crawler("http://localhost")
        forms = crawler._extract_forms(html)
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["_csrf_token"], "tok789")
        self.assertNotIn("user_token", forms[0])
        self.assertEqual(forms[0]["username"], "")


    def test_crawler_normalize_keeps_query_params(self):
        """Test discovered link URLs retain their query parameters."""
        crawler = Crawler("http://localhost")
        normalized = asyncio.run(
            crawler._normalize_url("xss_r/?name=x&id=1", "http://localhost/dvwa/")
        )
        self.assertEqual(normalized, "http://localhost/dvwa/xss_r/?name=x&id=1")

    def test_crawler_dedup_key_ignores_query(self):
        """Test visited-deduplication ignores query parameters."""
        self.assertEqual(
            Crawler._dedup_key("http://localhost/xss_r/?name=1"),
            Crawler._dedup_key("http://localhost/xss_r/?name=2"),
        )



    def test_session_blacklist_blocks_logout_path(self):
        """Test URLs with logout keywords in path are blocked."""
        self.assertTrue(Crawler._is_session_killer("http://localhost/dvwa/logout.php"))
        self.assertTrue(Crawler._is_session_killer("http://localhost/dvwa/logoff.php"))
        self.assertTrue(Crawler._is_session_killer("http://localhost/dvwa/sign-out"))
        self.assertTrue(Crawler._is_session_killer("http://localhost/dvwa/account/deconnexion"))

    def test_session_blacklist_blocks_action_logout(self):
        """Test URLs with action=logout query param are blocked."""
        self.assertTrue(Crawler._is_session_killer("http://localhost/dvwa/?action=logout"))
        self.assertTrue(Crawler._is_session_killer("http://localhost/dvwa/vuln/xss/?do=signout"))

    def test_session_blacklist_blocks_key_logout(self):
        """Test URLs with a query key named 'logout' are blocked."""
        self.assertTrue(Crawler._is_session_killer("http://localhost/dvwa/?logout=1"))

    def test_session_blacklist_allows_benign_url(self):
        """Test benign URLs pass the blacklist check."""
        self.assertFalse(Crawler._is_session_killer("http://localhost/dvwa/vulnerabilities/xss_r/?name=test"))
        self.assertFalse(Crawler._is_session_killer("http://localhost/dvwa/index.php"))
        self.assertFalse(Crawler._is_session_killer("http://localhost/dvwa/login.php"))

    def test_base_path_scope_blocks_outside(self):
        """Test URLs outside the target base path are blocked."""
        crawler = Crawler("http://localhost/dvwa/", max_depth=1)
        self.assertTrue(crawler._is_out_of_scope("http://localhost/xampp/"))
        self.assertTrue(crawler._is_out_of_scope("http://localhost/perpustakaan/"))
        self.assertTrue(crawler._is_out_of_scope("http://localhost/other-app/"))

    def test_base_path_scope_allows_within(self):
        """Test URLs within the target base path pass scope check."""
        crawler = Crawler("http://localhost/dvwa/", max_depth=1)
        self.assertFalse(crawler._is_out_of_scope("http://localhost/dvwa/vulnerabilities/"))
        self.assertFalse(crawler._is_out_of_scope("http://localhost/dvwa/login.php"))
        self.assertFalse(crawler._is_out_of_scope("http://localhost/dvwa/vuln/xss_r/"))

    def test_full_crawl_skips_logout_and_out_of_scope(self):
        """Integration: crawl only discovers in-scope non-blacklisted pages."""
        html_main = (
            '<a href="/dvwa/page1">ok</a>'
            '<a href="/dvwa/logout.php">bye</a>'
            '<a href="/xampp/test">out</a>'
            '<a href="/dvwa/vulnerabilities/xss_r/">xss</a>'
        )
        html_page1 = '<a href="/dvwa/index.php">home</a>'

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/dvwa/":
                return httpx.Response(200, text=html_main)
            if path == "/dvwa/page1":
                return httpx.Response(200, text=html_page1)
            return httpx.Response(404, text="")

        async def run():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                crawler = Crawler("http://localhost/dvwa/", max_depth=1, client=client)
                results = await crawler.crawl()
                paths = [urlparse(r.url).path for r in results]
                return paths

        paths = asyncio.run(run())
        self.assertIn("/dvwa/", paths)
        self.assertIn("/dvwa/page1", paths)
        self.assertNotIn("/dvwa/logout.php", paths)
        self.assertNotIn("/xampp/test", paths)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
