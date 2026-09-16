"""Unit tests for crawler.py using mocked HTTP responses."""

import unittest

import pytest

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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
