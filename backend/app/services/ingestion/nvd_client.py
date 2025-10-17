from __future__ import annotations

from collections.abc import Mapping
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

    async def fetch_cve(self, cve_id: str) -> dict[str, Any] | None:
        try:
            async with self._rate_limiter.slot():
                response = await self._client.get("/cves/2.0", params={"cveId": cve_id})
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("nvd_client.fetch_failed", cve_id=cve_id, error=str(exc))
            return None

        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities")
        if isinstance(vulnerabilities, list) and vulnerabilities:
            entry = vulnerabilities[0]
            if isinstance(entry, Mapping):
                return dict(entry)

        log.warning("nvd_client.no_data", cve_id=cve_id)
        return None

    async def close(self) -> None:
        await self._client.aclose()
