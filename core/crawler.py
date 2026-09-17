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

    _CSRF_INPUT_NAMES = frozenset(
        (
            "_token",
            "csrf_token",
            "csrf-token",
            "authenticity_token",
            "csrfmiddlewaretoken",
            "user_token",
        )
    )

    _SESSION_BLACKLIST = frozenset(
        (
            "logout",
            "logoff",
            "log-out",
            "signout",
            "sign-out",
            "deconnexion",
            "deconnection",
        )
    )

    _ACTION_PARAMS = frozenset(("action", "do", "cmd", "op", "operation", "mode"))

    def __init__(
        self,
        target_url: str,
        max_depth: int = 3,
        timeout: float = 10.0,
        follow_subdomains: bool = False,
        on_discover: Callable[[URLInfo], None] | None = None,
        max_concurrent: int = 10,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Initialize crawler.

        Args:
            target_url: Starting URL for crawling.
            max_depth: Maximum crawl depth.
            timeout: HTTP request timeout in seconds.
            follow_subdomains: Whether to follow URLs on subdomains.
            on_discover: Optional callback when URL discovered.
            max_concurrent: Maximum concurrent requests.
            client: Optional httpx.AsyncClient to reuse (keeps session cookies).
        """
        parsed = urlparse(target_url)
        self.base_domain = parsed.netloc
        self.follow_subdomains = follow_subdomains
        self.max_depth = max_depth
        self.timeout = httpx.Timeout(timeout, connect=timeout)
        self.on_discover = on_discover
        self.max_concurrent = max_concurrent
        self._client = client
        self._owns_client = client is None

        path_parts = [p for p in parsed.path.split("/") if p]
        self._base_path = "/" + path_parts[0] + "/" if path_parts else "/"

        self._visited: Set[str] = set()
        self._to_visit: deque[tuple[str, int]] = deque()
        self._discovered: List[URLInfo] = []

        self._to_visit.append((target_url, 0))

    @staticmethod
    def _is_session_killer(url: str) -> bool:
        """Return True if URL matches destructive session keywords."""
        url_lower = url.lower()
        parsed = urlparse(url_lower)
        for seg in parsed.path.split("/"):
            if any(kw in seg for kw in Crawler._SESSION_BLACKLIST):
                return True
        query = parse_qs(parsed.query)
        for key, values in query.items():
            if key in Crawler._SESSION_BLACKLIST:
                return True
            if key in Crawler._ACTION_PARAMS:
                if any(v in Crawler._SESSION_BLACKLIST for v in values):
                    return True
        return False

    def _is_out_of_scope(self, url: str) -> bool:
        """Return True if URL falls outside the target base path."""
        parsed = urlparse(url)
        return not parsed.path.startswith(self._base_path)

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

            clean_url = parsed.geturl()
            if self._is_out_of_scope(clean_url):
                return None
            if self._is_session_killer(clean_url):
                return None

            normalized = parsed.geturl()
            return normalized.rstrip("/") or normalized + "/"

        except Exception:
            return None

    @staticmethod
    def _dedup_key(url: str) -> str:
        """Return a single-visit key ignoring query and fragment.

        Allows the same page reached through different query strings to be
        crawled once, while discovered URLInfo entries still keep their full
        query parameters for fuzzing.
        """
        parsed = urlparse(url)
        return parsed._replace(query="", fragment="").geturl()

    def _extract_params(self, url: str) -> dict[str, list[str]]:
        """Extract query parameters from URL."""
        parsed = urlparse(url)
        return {
            k: v if len(v) > 1 else v[0]
            for k, v in parse_qs(parsed.query).items()
        }

    @staticmethod
    def _get_csrf_token(soup: BeautifulSoup, form: object) -> str:
        """Extract a CSRF token from the form or a document meta tag.

        Checks hidden inputs (``_token``, ``csrfmiddlewaretoken``, ...) first,
        then falls back to ``<meta name="csrf-token">``.

        Returns:
            The CSRF token value, or an empty string when none is found.
        """
        for input_elem in form.find_all(["input", "select", "textarea"]):
            name = input_elem.get("name", "")
            if name in Crawler._CSRF_INPUT_NAMES:
                value = input_elem.get("value", "")
                if value:
                    return value

        meta = soup.find("meta", attrs={"name": "csrf-token"})
        if meta is None:
            meta = soup.find("meta", attrs={"name": "csrf_token"})
        if meta is not None:
            return meta.get("content", "")

        return ""

    def _extract_forms(self, html: str) -> list[dict[str, str]]:
        """Extract form inputs from HTML."""
        soup = BeautifulSoup(html, "html.parser")
        forms: list[dict[str, str]] = []

        for form in soup.find_all("form"):
            form_action = form.get("action", "")
            form_method = (form.get("method") or "get").lower()

            inputs: dict[str, str] = {
                "_method": form_method,
                "_action": form_action,
                "_csrf_token": self._get_csrf_token(soup, form),
            }

            for input_elem in form.find_all(["input", "textarea", "select"]):
                name = input_elem.get("name")
                if not name:
                    continue
                if name in self._CSRF_INPUT_NAMES:
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
            if self._dedup_key(link) not in self._visited:
                self._to_visit.append((link, depth + 1))

    async def _crawl_single(
        self,
        client: httpx.AsyncClient,
        url: str,
        depth: int,
    ) -> None:
        """Crawl a single URL."""
        key = self._dedup_key(url)
        if key in self._visited:
            return

        self._visited.add(key)

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
        # Use provided client or create a new one
        if self._client is not None:
            client = self._client
            close_client = False
        else:
            client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)
            close_client = True

        try:
            semaphore = asyncio.Semaphore(self.max_concurrent)

            async def crawl_with_semaphore(url: str, depth: int) -> None:
                async with semaphore:
                    await self._crawl_single(client, url, depth)

            while self._to_visit:
                url, depth = self._to_visit.popleft()
                await crawl_with_semaphore(url, depth)

            return self._discovered
        finally:
            if close_client:
                await client.aclose()

    @property
    def discovered(self) -> List[URLInfo]:
        """Return list of discovered URLs."""
        return self._discovered


async def crawl(
    target_url: str,
    max_depth: int = 3,
    client: httpx.AsyncClient | None = None,
) -> List[URLInfo]:
    """Convenience async function to crawl a target URL.

    Args:
        target_url: Starting URL for crawling.
        max_depth: Maximum crawl depth.
        client: Optional httpx.AsyncClient to reuse (keeps session cookies).

    Returns:
        List of discovered URLs with parameters and forms.
    """
    crawler = Crawler(target_url, max_depth=max_depth, client=client)
    return await crawler.crawl()