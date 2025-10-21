from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter

log = structlog.get_logger()


class NVDClient:
    """
    Queries NVD (CVE 2.0 API) for supplemental details.
    Useful for fields missing in EUVD payloads.
    """

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        rate_limiter: AsyncRateLimiter | None = None,
        page_size: int | None = None,
    ) -> None:
        headers = {
            "User-Agent": settings.ingestion_user_agent,
            "Accept": "application/json",
        }
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        self._client = client or httpx.AsyncClient(
            base_url=settings.nvd_base_url.rstrip("/"),
            timeout=settings.euvd_timeout_seconds,
            headers=headers,
        )
        self._rate_limiter = rate_limiter or AsyncRateLimiter(settings.nvd_rate_limit_seconds)
        configured_page_size = page_size or settings.nvd_page_size
        self._page_size = max(1, min(configured_page_size, 2000))

    async def fetch_cve(self, cve_id: str) -> dict[str, Any] | None:
        try:
            async with self._rate_limiter.slot():
                response = await self._client.get("/cves/2.0", params={"cveId": cve_id})
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("nvd_client.fetch_failed", vuln_id=cve_id, error=str(exc))
            return None

        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities")
        if isinstance(vulnerabilities, list) and vulnerabilities:
            entry = vulnerabilities[0]
            if isinstance(entry, Mapping):
                return dict(entry)

        log.warning("nvd_client.no_data", vuln_id=cve_id)
        return None

    async def total_results(self) -> int:
        params = {"startIndex": 0, "resultsPerPage": 1}
        try:
            async with self._rate_limiter.slot():
                response = await self._client.get("/cves/2.0", params=params)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.error("nvd_client.total_failed", error=str(exc))
            raise RuntimeError("Failed to fetch NVD total results.") from exc

        payload = response.json()
        total = payload.get("totalResults")
        if isinstance(total, int):
            return total
        log.warning("nvd_client.total_missing", payload_keys=list(payload.keys())[:5])
        return 0

    async def iter_cves(
        self,
        *,
        last_modified_start: datetime | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        start_index = 0
        last_modified_param = self._format_datetime(last_modified_start) if last_modified_start else None
        total_results: int | None = None

        while True:
            params: dict[str, Any] = {
                "startIndex": start_index,
                "resultsPerPage": self._page_size,
            }
            if last_modified_param:
                params["lastModStartDate"] = last_modified_param

            try:
                async with self._rate_limiter.slot():
                    response = await self._client.get("/cves/2.0", params=params)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                log.error("nvd_client.page_failed", start_index=start_index, error=str(exc))
                raise RuntimeError("Failed to iterate NVD CVEs.") from exc

            payload = response.json()
            if total_results is None:
                maybe_total = payload.get("totalResults")
                if isinstance(maybe_total, int):
                    total_results = maybe_total

            vulnerabilities = payload.get("vulnerabilities")
            if not isinstance(vulnerabilities, list) or not vulnerabilities:
                break

            yielded = 0
            for entry in vulnerabilities:
                if isinstance(entry, Mapping):
                    yield dict(entry)
                    yielded += 1

            if yielded == 0:
                break

            start_index += yielded
            if total_results is not None and start_index >= total_results:
                break

    async def close(self) -> None:
        await self._client.aclose()

    @staticmethod
    def _format_datetime(value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        value = value.astimezone(UTC)
        return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
