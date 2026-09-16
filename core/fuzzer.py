"""Core fuzzer module for bugHunter CLI.

Injects payloads into discovered parameters.
Sends HTTP requests and collects status code, latency, raw HTML response.
Uses httpx.AsyncClient for asynchronous fuzzing.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
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
    ) -> None:
        """Initialize fuzzer.

        Args:
            timeout: HTTP request timeout in seconds.
            max_concurrent: Maximum concurrent requests.
        """
        self.timeout = httpx.Timeout(timeout, connect=timeout)
        self.max_concurrent = max_concurrent
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
        from urllib.parse import urlencode

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

    def _build_request_data(
        self,
        params: dict[str, list[str]],
        param_name: str,
        payload: str,
    ) -> dict[str, str | list[str]]:
        """Build POST request body with payload."""
        updated = {}
        for k, v in params.items():
            if k == param_name:
                if isinstance(v, list):
                    updated[k] = [payload if x == v[0] else x for x in v]
                else:
                    updated[k] = payload
            else:
                updated[k] = v
        return updated

    async def _make_request(
        self,
        client: httpx.AsyncClient,
        method: HTTPMethod,
        url: str,
        data: dict[str, str] | None = None,
    ) -> FuzzResult:
        """Execute HTTP request and return result."""
        start_time = time.perf_counter()

        try:
            if method == HTTPMethod.GET:
                response = await client.get(url)
            else:
                response = await client.post(url, data=data)

            latency_ms = (time.perf_counter() - start_time) * 1000

            return FuzzResult(
                original_url=url,
                method=method,
                param_name="",
                payload="",
                status_code=response.status_code,
                latency_ms=latency_ms,
                response_size=len(response.content),
                response_text=response.text,
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
            form_action = form_inputs.get("_action", "")
            form_method_raw = form_inputs.get("_method", "post")
            form_method = HTTPMethod.GET if form_method_raw == "get" else HTTPMethod.POST

            if not form_action:
                form_action = url_info.base_url

            action_url = url_info.url.rsplit("/", 1)[0] + "/" + form_action.lstrip("/")
            if form_method == HTTPMethod.GET:
                action_url = form_action

            for param_name, param_value in form_inputs.items():
                if param_name.startswith("_"):
                    continue

                for payload in payloads:
                    fuzzed_data = self._build_request_data(
                        {param_name: [param_value]},
                        param_name,
                        payload,
                    )

                    result = await self._make_request(
                        client, form_method, action_url, fuzzed_data if form_method == HTTPMethod.POST else None
                    )
                    result.original_url = action_url
                    result.param_name = param_name
                    result.payload = payload
                    results.append(result)

        return results

    async def fuzz_all(
        self,
        client: httpx.AsyncClient,
        url_info: URLInfo,
        payloads: Sequence[str],
    ) -> list[FuzzResult]:
        """Fuzz both URL parameters and form parameters.

        Args:
            client: httpx async client instance.
            url_info: Discovered URL with parameters and forms.
            payloads: List of payloads to inject.

        Returns:
            List of all fuzz results.
        """
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
