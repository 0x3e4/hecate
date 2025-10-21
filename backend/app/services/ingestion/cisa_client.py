from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.core.config import settings

log = structlog.get_logger()


class CisaKevClient:
    """
    Lightweight client for the CISA Known Exploited Vulnerabilities (KEV) catalog.
    """

    DEFAULT_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(
        self,
        *,
        feed_url: str | None = None,
        timeout_seconds: int | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.feed_url = feed_url or self.DEFAULT_URL
        self.timeout = timeout_seconds or 15
        self._client = client or httpx.AsyncClient(
            timeout=self.timeout,
            headers={
                "User-Agent": settings.ingestion_user_agent,
                "Accept": "application/json",
            },
        )
        self._owns_client = client is None

    async def fetch_known_exploited_cves(self) -> set[str]:
        """
        Returns an uppercase set of CVE identifiers listed in the CISA KEV catalog.
        """
        try:
            response = await self._client.get(self.feed_url)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("cisa_kev.fetch_failed", error=str(exc), url=self.feed_url)
            return set()

        try:
            payload = response.json()
        except ValueError as exc:
            log.warning("cisa_kev.invalid_json", error=str(exc))
            return set()

        items: list[dict[str, Any]] = []
        if isinstance(payload, dict):
            for key in ("vulnerabilities", "known_exploited_vulnerabilities", "items", "data"):
                value = payload.get(key)
                if isinstance(value, list):
                    items = [item for item in value if isinstance(item, dict)]
                    break
        elif isinstance(payload, list):
            items = [item for item in payload if isinstance(item, dict)]

        cves: set[str] = set()
        for item in items:
            cve = item.get("cveID") or item.get("cveId") or item.get("cve_id") or item.get("cve")
            if isinstance(cve, str):
                normalized = cve.strip().upper()
                if normalized:
                    cves.add(normalized)
        if not cves:
            log.warning("cisa_kev.no_entries_extracted", keys=list(payload.keys())[:5] if isinstance(payload, dict) else None)
        return cves

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()


async def load_known_exploited_set(client: CisaKevClient | None = None) -> set[str]:
    local_client = client or CisaKevClient()
    try:
        return await local_client.fetch_known_exploited_cves()
    finally:
        if client is None:
            await local_client.close()
