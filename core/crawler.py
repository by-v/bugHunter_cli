"""Core crawler module for bugHunter CLI.

Extracts URLs, parses query parameters, collects form inputs.
Implements deduplication and prevents infinite loops.
Strict domain scope enforcement.
Uses httpx.AsyncClient for asynchronous crawling.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, List, Set
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass
class URLInfo:
    """Represents a discovered URL with its parameters."""

    url: str
    base_url: str
    params: dict[str, list[str]] = field(default_factory=dict)
    form_inputs: list[dict[str, str]] = field(default_factory=list)


class Crawler:
    """Crawl a target URL and extract all accessible pages, parameters, and forms."""

    def __init__(
        self,
        target_url: str,
        max_depth: int = 3,
        timeout: float = 10.0,
        follow_subdomains: bool = False,
        on_discover: Callable[[URLInfo], None] | None = None,
        max_concurrent: int = 10,
    ) -> None:
        """Initialize crawler.

        Args:
            target_url: Starting URL for crawling.
            max_depth: Maximum crawl depth.
            timeout: HTTP request timeout in seconds.
            follow_subdomains: Whether to follow URLs on subdomains.
            on_discover: Optional callback when URL discovered.
            max_concurrent: Maximum concurrent requests.
        """
        parsed = urlparse(target_url)
        self.base_domain = parsed.netloc
        self.follow_subdomains = follow_subdomains
        self.max_depth = max_depth
        self.timeout = httpx.Timeout(timeout, connect=timeout)
        self.on_discover = on_discover
        self.max_concurrent = max_concurrent

        self._visited: Set[str] = set()
        self._to_visit: deque[tuple[str, int]] = deque()
        self._discovered: List[URLInfo] = []

        self._to_visit.append((target_url, 0))

    async def _normalize_url(self, url: str, base: str) -> str | None:
        """Normalize and validate URL against target domain."""
        try:
            full_url = urljoin(base, url)
            parsed = urlparse(full_url)

            if parsed.scheme not in ("http", "https"):
                return None

            if parsed.fragment:
                parsed = parsed._replace(fragment="")

            netloc = parsed.netloc.lower()
            if not self.follow_subdomains and netloc != self.base_domain:
                return None
            if netloc != self.base_domain and not netloc.endswith(
                "." + self.base_domain
            ):
                return None

            normalized = parsed._replace(query="").geturl()
            return normalized.rstrip("/") or normalized + "/"

        except Exception:
            return None

    def _extract_params(self, url: str) -> dict[str, list[str]]:
        """Extract query parameters from URL."""
        parsed = urlparse(url)
        return {
            k: v if len(v) > 1 else v[0]
            for k, v in parse_qs(parsed.query).items()
        }

    def _extract_forms(self, html: str) -> list[dict[str, str]]:
        """Extract form inputs from HTML."""
        soup = BeautifulSoup(html, "html.parser")
        forms = []

        for form in soup.find_all("form"):
            form_action = form.get("action", "")
            form_method = (form.get("method") or "get").lower()

            inputs: dict[str, str] = {"_method": form_method, "_action": form_action}

            for input_elem in form.find_all(["input", "textarea", "select"]):
                name = input_elem.get("name")
                if not name:
                    continue

                input_type = input_elem.get("type", "text").lower()
                value = input_elem.get("value", "")

                if input_type in ("submit", "button", "reset"):
                    continue
                if input_type == "checkbox" and input_elem.get("checked") is None:
                    continue

                inputs[name] = value

            forms.append(inputs)

        return forms

    async def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract all links from HTML."""
        soup = BeautifulSoup(html, "html.parser")
        links: list[str] = []

        for tag in soup.find_all(["a", "link", "script", "img", "iframe", "frame"]):
            href = tag.get("href") or tag.get("src")
            if not href:
                continue
            normalized = await self._normalize_url(href, base_url)
            if normalized:
                links.append(normalized)

        return links

    async def _discover(
        self,
        url: str,
        depth: int,
        response: httpx.Response,
    ) -> None:
        """Process a discovered page and extract URLs, params, forms."""
        url_info = URLInfo(
            url=url,
            base_url=url,
            params=self._extract_params(url),
            form_inputs=self._extract_forms(response.text),
        )

        self._discovered.append(url_info)
        if self.on_discover:
            self.on_discover(url_info)

        if depth >= self.max_depth:
            return

        links = await self._extract_links(response.text, url)
        for link in links:
            if link not in self._visited:
                self._to_visit.append((link, depth + 1))

    async def _crawl_single(
        self,
        client: httpx.AsyncClient,
        url: str,
        depth: int,
    ) -> None:
        """Crawl a single URL."""
        if url in self._visited:
            return

        self._visited.add(url)

        try:
            response = await client.get(url, follow_redirects=True)
            response.raise_for_status()
            await self._discover(url, depth, response)
        except httpx.HTTPStatusError:
            pass
        except (httpx.RequestError, httpx.TimeoutException):
            pass

    async def crawl(self) -> List[URLInfo]:
        """Run the crawler asynchronously and return all discovered URLs."""
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            semaphore = asyncio.Semaphore(self.max_concurrent)

            async def crawl_with_semaphore(url: str, depth: int) -> None:
                async with semaphore:
                    await self._crawl_single(client, url, depth)

            while self._to_visit:
                url, depth = self._to_visit.popleft()
                await crawl_with_semaphore(url, depth)

        return self._discovered

    @property
    def discovered(self) -> List[URLInfo]:
        """Return list of discovered URLs."""
        return self._discovered


async def crawl(target_url: str, max_depth: int = 3) -> List[URLInfo]:
    """Convenience async function to crawl a target URL.

    Args:
        target_url: Starting URL for crawling.
        max_depth: Maximum crawl depth.

    Returns:
        List of discovered URLs with parameters and forms.
    """
    crawler = Crawler(target_url, max_depth=max_depth)
    return await crawler.crawl()
