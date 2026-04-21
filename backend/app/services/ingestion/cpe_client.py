from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import httpx
import structlog

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter
from app.services.http.ssl import get_http_verify

log = structlog.get_logger()


class CPEClient:
    """
    Lightweight wrapper around the NVD CPE 2.0 API.
    Fetches CPE metadata for vendor/product configuration.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_seconds: int | None = None,
        rate_limiter: AsyncRateLimiter | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = (base_url or settings.cpe_base_url).rstrip("/")
        timeout = timeout_seconds or settings.euvd_timeout_seconds
        headers = {
            "User-Agent": settings.ingestion_user_agent,
            "Accept": "application/json",
        }
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        self._client = client or httpx.AsyncClient(
            timeout=timeout,
            headers=headers,
            verify=get_http_verify(),
        )
        self._rate_limiter = rate_limiter or AsyncRateLimiter(settings.nvd_rate_limit_seconds)

    async def iter_cpe_records(
        self,
        *,
        last_modified_after: datetime | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """
        Streams CPE records changed after the given timestamp.
        """
        params: dict[str, Any] = {}
        params["resultsPerPage"] = 2000
        if last_modified_after:
            params["lastModStartDate"] = last_modified_after.isoformat()

        start_index = 0
        results_returned = 1

        while results_returned > 0:
            params["startIndex"] = start_index

            response = await self._request_with_retry(params)

            try:
                payload = response.json()
            except json.JSONDecodeError as exc:
                log.error("cpe_client.json_decode_failed", error=str(exc), start_index=start_index)
                raise
            results = payload.get("products") or []
            if not isinstance(results, list):
                log.warning("cpe_client.invalid_payload", payload_type=type(results))
                break

            results_returned = len(results)
            total_results = payload.get("totalResults", 0)
            log.info(
                "cpe_client.page_fetched",
                start_index=start_index,
                results_returned=results_returned,
                total_results=total_results,
            )

            if results_returned == 0:
                break

            for item in results:
                if isinstance(item, dict):
                    yield item

            results_per_page = payload.get("resultsPerPage")
            if isinstance(results_per_page, int) and results_per_page > 0:
                start_index += results_per_page
            else:
                break

    async def _request_with_retry(
        self,
        params: dict[str, Any],
        *,
        max_retries: int = 3,
        backoff_base: float = 5.0,
    ) -> httpx.Response:
        """GET request with exponential backoff for transient errors."""
        _RETRYABLE = {429, 500, 502, 503, 504}
        last_exc: Exception | None = None

        for attempt in range(max_retries + 1):
            try:
                async with self._rate_limiter.slot():
                    response = await self._client.get(self.base_url, params=params)
                if response.status_code in _RETRYABLE and attempt < max_retries:
                    delay = backoff_base * (2 ** attempt)
                    log.warning(
                        "cpe_client.retrying",
                        status_code=response.status_code,
                        attempt=attempt + 1,
                        delay=delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                response.raise_for_status()
                return response
            except httpx.HTTPError as exc:
                last_exc = exc
                if attempt < max_retries:
                    delay = backoff_base * (2 ** attempt)
                    log.warning(
                        "cpe_client.retrying",
                        error=str(exc),
                        attempt=attempt + 1,
                        delay=delay,
                    )
                    await asyncio.sleep(delay)
                else:
                    log.error("cpe_client.request_failed", error=str(exc), params=params)
                    raise

        raise last_exc  # type: ignore[misc]

    async def close(self) -> None:
        await self._client.aclose()
