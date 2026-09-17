"""Core fuzzer module for bugHunter CLI.

Injects payloads into discovered parameters.
Sends HTTP requests and collects status code, latency, raw HTML response.
Uses httpx.AsyncClient for asynchronous fuzzing.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urljoin
from enum import Enum
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from collections.abc import Sequence

    from core.crawler import URLInfo


class HTTPMethod(Enum):
    """Supported HTTP methods."""

    GET = "get"
    POST = "post"


@dataclass
class FuzzResult:
    """Result of a single fuzzing attempt."""

    original_url: str
    method: HTTPMethod
    param_name: str
    payload: str
    status_code: int
    latency_ms: float
    response_size: int
    response_text: str
    error: str | None = None


class Fuzzer:
    """Fuzz discovered parameters with security payloads."""

    def __init__(
        self,
        timeout: float = 10.0,
        max_concurrent: int = 10,
        max_retries: int = 3,
        retry_backoff_base: float = 1.0,
        retry_backoff_max: float = 10.0,
        latency_warning_ms: float = 2000.0,
    ) -> None:
        """Initialize fuzzer.

        Args:
            timeout: HTTP request timeout in seconds.
            max_concurrent: Maximum concurrent requests.
            max_retries: Number of retries after HTTP 429.
            retry_backoff_base: Base delay in seconds for exponential backoff.
            retry_backoff_max: Maximum backoff delay in seconds.
            latency_warning_ms: Latency threshold that triggers a short pause.
        """
        self.timeout = httpx.Timeout(timeout, connect=timeout)
        self.max_concurrent = max_concurrent
        self.max_retries = max_retries
        self.retry_backoff_base = retry_backoff_base
        self.retry_backoff_max = retry_backoff_max
        self.latency_warning_ms = latency_warning_ms
        self._results: list[FuzzResult] = []

    def _build_request_url(
        self,
        base_url: str,
        method: HTTPMethod,
        params: dict[str, list[str]],
        param_name: str,
        payload: str,
    ) -> str:
        """Build URL with payload injected."""
        if method == HTTPMethod.GET:
            updated_params = {}
            for k, v in params.items():
                if k == param_name:
                    if isinstance(v, list):
                        updated_params[k] = [payload if x == v[0] else x for x in v]
                    else:
                        updated_params[k] = payload
                else:
                    updated_params[k] = v
            encoded = urlencode(updated_params, doseq=True)
            return f"{base_url}?{encoded}"
        return base_url

    def _build_form_data(
        self,
        form_inputs: dict[str, str],
        param_name: str,
        payload: str,
    ) -> dict[str, str]:
        """Build POST form data with the payload and preserved session fields.

        All non-target fields are kept so token-protected forms (e.g. CSRF
        ``_token``) remain valid when the payload is injected.
        """
        data: dict[str, str] = {}
        for name, value in form_inputs.items():
            if name.startswith("_"):
                # Skip metadata keys, but forward the CSRF token for POST.
                if name == "_csrf_token" and value:
                    data["_token"] = value
                continue

            data[name] = payload if name == param_name else value
        return data

    @staticmethod
    def _append_query(url: str, data: dict[str, str] | None) -> str:
        """Append form data as an encoded query string to an URL."""
        if not data:
            return url
        encoded = urlencode(data)
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}{encoded}"

    async def _make_request(
        self,
        client: httpx.AsyncClient,
        method: HTTPMethod,
        url: str,
        data: dict[str, str] | None = None,
    ) -> FuzzResult:
        """Execute HTTP request and return result.

        Retries requests that are rate-limited (HTTP 429) using exponential
        backoff, and applies a short pause after high-latency responses so the
        scanner does not overload the target.
        """
        request_error: str | None = None

        for attempt in range(self.max_retries + 1):
            start_time = time.perf_counter()

            try:
                if method == HTTPMethod.GET:
                    response = await client.get(url)
                else:
                    response = await client.post(url, data=data)

                latency_ms = (time.perf_counter() - start_time) * 1000

                # Retry rate-limited responses with exponential backoff.
                if response.status_code == 429 and attempt < self.max_retries:
                    delay = min(
                        self.retry_backoff_base * (2 ** attempt),
                        self.retry_backoff_max,
                    )
                    await asyncio.sleep(delay)
                    continue

                # Ease off when the server is responding slowly.
                if latency_ms > self.latency_warning_ms:
                    await asyncio.sleep(0.5)

                if response.status_code == 429:
                    request_error = (
                        f"Rate limited (429 after {self.max_retries} retries)"
                    )

                return FuzzResult(
                    original_url=url,
                    method=method,
                    param_name="",
                    payload="",
                    status_code=response.status_code,
                    latency_ms=latency_ms,
                    response_size=len(response.content),
                    response_text=response.text,
                    error=request_error,
                )

            except httpx.TimeoutException as e:
                latency_ms = (time.perf_counter() - start_time) * 1000
                return FuzzResult(
                    original_url=url,
                    method=method,
                    param_name="",
                    payload="",
                    status_code=0,
                    latency_ms=latency_ms,
                    response_size=0,
                    response_text="",
                    error=f"Timeout after {self.timeout}: {e}",
                )
            except httpx.RequestError as e:
                return FuzzResult(
                    original_url=url,
                    method=method,
                    param_name="",
                    payload="",
                    status_code=0,
                    latency_ms=0,
                    response_size=0,
                    response_text="",
                    error=f"Connection failed: {e}",
                )

    async def fuzz_url_params(
        self,
        client: httpx.AsyncClient,
        url_info: URLInfo,
        payloads: Sequence[str],
    ) -> list[FuzzResult]:
        """Fuzz URL query parameters.

        Args:
            client: httpx async client instance.
            url_info: Discovered URL with parameters.
            payloads: List of payloads to inject.

        Returns:
            List of fuzz results.
        """
        results: list[FuzzResult] = []

        base_url = url_info.url.split("?")[0]
        params = url_info.params

        for param_name, param_values in params.items():
            for payload in payloads:
                fuzzed_url = self._build_request_url(
                    base_url, HTTPMethod.GET, params, param_name, payload
                )

                result = await self._make_request(client, HTTPMethod.GET, fuzzed_url)
                result.param_name = param_name
                result.payload = payload
                results.append(result)

        return results

    async def fuzz_form_params(
        self,
        client: httpx.AsyncClient,
        url_info: URLInfo,
        payloads: Sequence[str],
    ) -> list[FuzzResult]:
        """Fuzz form input parameters.

        Args:
            client: httpx async client instance.
            url_info: Discovered URL with forms.
            payloads: List of payloads to inject.

        Returns:
            List of fuzz results.
        """
        results: list[FuzzResult] = []

        for form_inputs in url_info.form_inputs:
            form_method_raw = (form_inputs.get("_method") or "post").lower()
            form_method = HTTPMethod.GET if form_method_raw == "get" else HTTPMethod.POST
            raw_action = (form_inputs.get("_action") or "").strip()

            # "#" (or an empty action) means "submit to the current page":
            # target the page itself, dropping any existing query so the fresh
            # form fields can be attached cleanly.
            if not raw_action or raw_action == "#":
                action_url = url_info.url.split("?")[0]
            else:
                action_url = urljoin(url_info.url, raw_action)

            for param_name, param_value in form_inputs.items():
                if param_name.startswith("_"):
                    continue

                for payload in payloads:
                    form_data = self._build_form_data(
                        form_inputs,
                        param_name,
                        payload,
                    )

                    if form_method == HTTPMethod.GET:
                        request_url = self._append_query(action_url, form_data)
                        result = await self._make_request(
                            client, HTTPMethod.GET, request_url
                        )
                    else:
                        request_url = action_url
                        result = await self._make_request(
                            client, HTTPMethod.POST, action_url, form_data
                        )

                    result.original_url = request_url
                    result.param_name = param_name
                    result.payload = payload
                    results.append(result)

        return results

    async def _check_fuzzable(
        self,
        client: httpx.AsyncClient,
        url_info: URLInfo,
    ) -> bool:
        """Probe a discovered URL with a clean request before fuzzing it.

        Client-side errors (4xx) mean the link is dead or was resolved to an
        incorrect path, so fuzzing it would only generate noise. A rate-limit
        response (429) and network failures are not treated as dead links;
        fuzzing proceeds so no analysable data is silently lost.

        Args:
            client: httpx async client instance.
            url_info: Discovered URL to probe.

        Returns:
            True when the URL should be fuzzed.
        """
        try:
            response = await client.get(url_info.url)
        except (httpx.TimeoutException, httpx.RequestError):
            return True

        if 400 <= response.status_code < 500 and response.status_code != 429:
            return False
        return True

    async def fuzz_all(
        self,
        client: httpx.AsyncClient,
        url_info: URLInfo,
        payloads: Sequence[str],
    ) -> list[FuzzResult]:
        """Fuzz both URL parameters and form parameters.

        Before sending any payload, a single clean request verifies the
        discovered URL is reachable; dead or mis-resolved links (HTTP 4xx)
        are skipped entirely so they produce no false findings.

        Args:
            client: httpx async client instance.
            url_info: Discovered URL with parameters and forms.
            payloads: List of payloads to inject.

        Returns:
            List of all fuzz results (empty when the URL is not fuzzable).
        """
        if not await self._check_fuzzable(client, url_info):
            return []

        results = []
        results.extend(await self.fuzz_url_params(client, url_info, payloads))
        results.extend(await self.fuzz_form_params(client, url_info, payloads))
        return results

    async def fuzz_all_batch(
        self,
        client: httpx.AsyncClient,
        url_infos: list[URLInfo],
        payloads: Sequence[str],
    ) -> list[FuzzResult]:
        """Fuzz multiple URLs concurrently.

        Args:
            client: httpx async client instance.
            url_infos: List of discovered URLs.
            payloads: List of payloads to inject.

        Returns:
            List of all fuzz results.
        """
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def fuzz_single(url_info: URLInfo) -> list[FuzzResult]:
            async with semaphore:
                return await self.fuzz_all(client, url_info, payloads)

        tasks = [fuzz_single(ui) for ui in url_infos]
        results = []
        for task in asyncio.as_completed(tasks):
            results.extend(await task)
        return results
