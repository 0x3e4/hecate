from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import httpx
import structlog

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter

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

            try:
                async with self._rate_limiter.slot():
                    response = await self._client.get(self.base_url, params=params)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                log.error("cpe_client.request_failed", error=str(exc), params=params)
                raise

            payload = response.json()
            results = payload.get("products") or []
            if not isinstance(results, list):
                log.warning("cpe_client.invalid_payload", payload_type=type(results))
                break

            results_returned = len(results)
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

    async def close(self) -> None:
        await self._client.aclose()
