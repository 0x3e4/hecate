from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
import structlog

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter

log = structlog.get_logger()


class CirclClient:
    """
    Client for the CIRCL Vulnerability Lookup API.
    Fetches CVE details to enrich vulnerability records with vendor/product/version data.

    API documentation: https://vulnerability.circl.lu/api
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_seconds: int | None = None,
        rate_limiter: AsyncRateLimiter | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = (base_url or settings.circl_base_url).rstrip("/")
        timeout = timeout_seconds or settings.circl_timeout_seconds
        headers = {
            "User-Agent": settings.ingestion_user_agent,
            "Accept": "application/json",
        }

        self._client = client or httpx.AsyncClient(
            timeout=timeout,
            headers=headers,
        )
        self._rate_limiter = rate_limiter or AsyncRateLimiter(settings.circl_rate_limit_seconds)

    async def fetch_cve(self, cve_id: str) -> dict[str, Any] | None:
        """
        Fetch details for a specific CVE from CIRCL.
        Returns None if the CVE is not found or request fails.
        """
        url = f"{self.base_url}/cve/{cve_id}"
        try:
            async with self._rate_limiter.slot():
                response = await self._client.get(url)

            if response.status_code == 404:
                log.debug("circl_client.cve_not_found", cve_id=cve_id)
                return None

            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            log.warning("circl_client.fetch_failed", cve_id=cve_id, error=str(exc))
            return None

    async def iter_cve_records(
        self,
        cve_ids: list[str],
    ) -> AsyncIterator[tuple[str, dict[str, Any]]]:
        """
        Iterate over CVE IDs and yield (cve_id, record) tuples for successfully fetched records.
        """
        for cve_id in cve_ids:
            record = await self.fetch_cve(cve_id)
            if record:
                yield cve_id, record

    async def fetch_last_updated(self, limit: int = 30) -> list[dict[str, Any]]:
        """
        Fetch the most recently updated CVEs from CIRCL.
        Returns up to 30 CVEs by default.
        """
        url = f"{self.base_url}/last"
        try:
            async with self._rate_limiter.slot():
                response = await self._client.get(url)
            response.raise_for_status()
            results = response.json()
            if isinstance(results, list):
                return results[:limit]
            return []
        except httpx.HTTPError as exc:
            log.error("circl_client.fetch_last_failed", error=str(exc))
            return []

    async def close(self) -> None:
        await self._client.aclose()
