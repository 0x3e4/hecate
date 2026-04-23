from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import asyncio

import httpx
import structlog

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter
from app.services.http.retry import request_with_retry
from app.services.http.ssl import get_http_verify

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
        max_retries: int | None = None,
        retry_backoff: float | None = None,
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
            verify=get_http_verify(),
        )
        self._rate_limiter = rate_limiter or AsyncRateLimiter(settings.circl_rate_limit_seconds)
        self._max_retries = max_retries if max_retries is not None else settings.circl_max_retries
        self._retry_backoff = retry_backoff if retry_backoff is not None else settings.circl_retry_backoff_seconds

    async def fetch_cve(self, cve_id: str) -> dict[str, Any] | None:
        """
        Fetch details for a specific CVE from CIRCL.
        Also fetches the current EPSS probability from CIRCL's /api/epss endpoint
        and stitches it onto the record as `_epss_probability` (float, 0..1).
        Returns None if the CVE record itself is not found.
        """
        record, epss = await asyncio.gather(
            self._fetch_cve_record(cve_id),
            self._fetch_epss_probability(cve_id),
        )
        if record is None:
            return None
        if epss is not None:
            record["_epss_probability"] = epss
        return record

    async def _fetch_cve_record(self, cve_id: str) -> dict[str, Any] | None:
        url = f"{self.base_url}/cve/{cve_id}"
        response = await request_with_retry(
            self._client,
            "GET",
            url,
            rate_limiter=self._rate_limiter,
            max_retries=self._max_retries,
            backoff_base=self._retry_backoff,
            log_prefix="circl_client",
            validate_json=True,
            context={"cve_id": cve_id, "op": "fetch_cve"},
        )
        if response is None:
            log.warning("circl_client.fetch_failed", cve_id=cve_id)
            return None

        if response.status_code == 404:
            log.debug("circl_client.cve_not_found", cve_id=cve_id)
            return None

        try:
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("circl_client.fetch_failed", cve_id=cve_id, error=str(exc))
            return None

        return response.json()

    async def _fetch_epss_probability(self, cve_id: str) -> float | None:
        """
        Fetch the current EPSS probability from CIRCL's /api/epss/{cve} endpoint.
        Response shape: {"data": [{"cve": "...", "epss": "0.88314", "percentile": "..."}]}
        Returns None on any failure — EPSS is best-effort enrichment.
        """
        url = f"{self.base_url}/epss/{cve_id}"
        response = await request_with_retry(
            self._client,
            "GET",
            url,
            rate_limiter=self._rate_limiter,
            max_retries=self._max_retries,
            backoff_base=self._retry_backoff,
            log_prefix="circl_client",
            validate_json=True,
            context={"cve_id": cve_id, "op": "fetch_epss"},
        )
        if response is None:
            return None
        if response.status_code == 404:
            return None
        try:
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPError as exc:
            log.debug("circl_client.epss_fetch_failed", cve_id=cve_id, error=str(exc))
            return None

        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, list) or not data:
            return None
        entry = data[0]
        if not isinstance(entry, dict):
            return None
        raw = entry.get("epss")
        if raw is None:
            return None
        try:
            score = float(raw)
        except (TypeError, ValueError):
            return None
        if score < 0 or score > 1:
            return None
        return round(score, 4)

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
        response = await request_with_retry(
            self._client,
            "GET",
            url,
            rate_limiter=self._rate_limiter,
            max_retries=self._max_retries,
            backoff_base=self._retry_backoff,
            log_prefix="circl_client",
            validate_json=True,
            context={"op": "fetch_last_updated"},
        )
        if response is None:
            log.error("circl_client.fetch_last_failed")
            return []
        try:
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.error("circl_client.fetch_last_failed", error=str(exc))
            return []

        results = response.json()
        if isinstance(results, list):
            return results[:limit]
        return []

    async def close(self) -> None:
        await self._client.aclose()
