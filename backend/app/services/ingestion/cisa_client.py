from __future__ import annotations

from typing import Any

import httpx
import structlog
from pydantic import ValidationError

from app.core.config import settings
from app.models.kev import CisaKevCatalog

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
        self.feed_url = feed_url or settings.kev_feed_url or self.DEFAULT_URL
        self.timeout = timeout_seconds or 15
        self._client = client or httpx.AsyncClient(
            timeout=self.timeout,
            headers={
                "User-Agent": settings.ingestion_user_agent,
                "Accept": "application/json",
            },
        )
        self._owns_client = client is None

    async def fetch_catalog(self) -> CisaKevCatalog | None:
        try:
            response = await self._client.get(self.feed_url)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("cisa_kev.fetch_failed", error=str(exc), url=self.feed_url)
            return None

        try:
            payload = response.json()
        except ValueError as exc:
            log.warning("cisa_kev.invalid_json", error=str(exc))
            return None

        catalog_payload: dict[str, Any] | None = None
        entries: list[dict[str, Any]] = []

        if isinstance(payload, dict):
            catalog_payload = dict(payload)
            for key in ("vulnerabilities", "known_exploited_vulnerabilities", "items", "data"):
                value = payload.get(key)
                if isinstance(value, list):
                    entries = [item for item in value if isinstance(item, dict)]
                    break
            catalog_payload["vulnerabilities"] = entries
        elif isinstance(payload, list):
            catalog_payload = {"vulnerabilities": [item for item in payload if isinstance(item, dict)]}

        if catalog_payload is None:
            log.warning("cisa_kev.unexpected_payload", payload_type=type(payload).__name__)
            return None

        try:
            catalog = CisaKevCatalog.model_validate(catalog_payload)
        except ValidationError as exc:
            log.warning("cisa_kev.validation_failed", error=str(exc))
            return None

        for idx, entry in enumerate(entries):
            try:
                catalog.vulnerabilities[idx].raw = entry
            except IndexError:
                break

        if not catalog.vulnerabilities:
            log.warning("cisa_kev.no_entries_extracted")
        return catalog

    async def fetch_known_exploited_cves(self) -> set[str]:
        """
        Returns an uppercase set of CVE identifiers listed in the CISA KEV catalog.
        """
        catalog = await self.fetch_catalog()
        if catalog is None:
            return set()

        cves: set[str] = set()
        for entry in catalog.vulnerabilities:
            if entry.cve_id:
                cves.add(entry.cve_id)
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
