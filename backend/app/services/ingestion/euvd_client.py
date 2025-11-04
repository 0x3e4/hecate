from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import httpx
import structlog

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter

log = structlog.get_logger()


class EUVDClient:
    """
    Client for the EUVD public API.
    Fetches paginated vulnerability data and yields raw records.
    """

    SEARCH_PATH = "/search"
    DIRECT_LOOKUP_PATH = "/enisaid"
    MAX_PAGE_SIZE = 100

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_seconds: int | None = None,
        page_size: int | None = None,
        client: httpx.AsyncClient | None = None,
        rate_limiter: AsyncRateLimiter | None = None,
    ) -> None:
        self.base_url = (base_url or settings.euvd_base_url).rstrip("/")
        self.timeout = timeout_seconds or settings.euvd_timeout_seconds
        configured_page_size = page_size or settings.euvd_page_size
        self.page_size = min(configured_page_size, self.MAX_PAGE_SIZE)
        self._rate_limiter = rate_limiter or AsyncRateLimiter(settings.euvd_rate_limit_seconds)
        self._client = client or httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers={
                "User-Agent": settings.ingestion_user_agent,
                "Accept": "application/json",
            },
        )

    async def list_vulnerabilities(
        self,
        *,
        modified_since: datetime | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """
        Iterates through EUVD vulnerabilities using the `/search` endpoint.
        """

        page = 0
        while True:
            params: dict[str, Any] = {
                "page": page,
                "size": self.page_size,
                "fromScore": 0,
                "toScore": 10,
            }
            if modified_since:
                params["fromUpdatedDate"] = modified_since.date().isoformat()

            try:
                async with self._rate_limiter.slot():
                    response = await self._client.get(self.SEARCH_PATH, params=params)
            except httpx.HTTPError as exc:
                log.error(
                    "euvd_client.request_failed",
                    error=str(exc),
                    base_url=self.base_url,
                    params=params,
                )
                raise RuntimeError(
                    "Failed to reach EUVD API. Ensure EUVD_BASE_URL points to a reachable endpoint."
                ) from exc

            response.raise_for_status()
            payload = response.json()

            items = self._extract_items(payload)
            if not items:
                break

            for item in items:
                yield item

            if len(items) < self.page_size:
                break

            page += 1

    async def fetch_single(self, identifier: str) -> dict[str, Any] | None:
        candidate = (identifier or "").strip()
        if not candidate:
            return None

        # Try direct lookup first via /api/enisaid?id={identifier}
        try:
            async with self._rate_limiter.slot():
                response = await self._client.get(self.DIRECT_LOOKUP_PATH, params={"id": candidate})
            response.raise_for_status()
            payload = response.json()
            if isinstance(payload, dict) and payload:
                # Direct lookup returns a single record
                return payload
        except httpx.HTTPError as exc:
            log.debug(
                "euvd_client.direct_lookup_failed",
                identifier=identifier,
                error=str(exc),
            )

        # Fallback to search endpoint
        lookups: list[dict[str, Any]] = [
            {"search": candidate},
            {"queryString": candidate},
        ]

        for params_override in lookups:
            params: dict[str, Any] = {
                "page": 0,
                "size": min(self.page_size, 20),
                "fromScore": 0,
                "toScore": 10,
            }
            params.update(params_override)

            try:
                async with self._rate_limiter.slot():
                    response = await self._client.get(self.SEARCH_PATH, params=params)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                log.warning(
                    "euvd_client.fetch_single_search_failed",
                    identifier=identifier,
                    params=params,
                    error=str(exc),
                )
                continue

            payload = response.json()
            items = self._extract_items(payload)
            if not items:
                continue

            for item in items:
                if not isinstance(item, dict):
                    continue
                if self._matches_identifier(item, candidate):
                    return item

        return None

    @staticmethod
    def _matches_identifier(record: dict[str, Any], identifier: str) -> bool:
        needle = identifier.strip().lower()
        if not needle:
            return False

        id_candidates = [
            record.get("id"),
            record.get("euvdId"),
            record.get("enisaUuid"),
            record.get("uuid"),
            record.get("sourceId"),
            record.get("cveNumber"),
            record.get("cve"),
            record.get("cveId"),
            record.get("cve_id"),
        ]
        for candidate in id_candidates:
            if isinstance(candidate, str) and candidate.strip().lower() == needle:
                return True

        alias_sources = [
            record.get("aliases"),
            record.get("alias"),
            record.get("references"),
        ]
        for source in alias_sources:
            for alias in EUVDClient._iter_alias_values(source):
                if alias.lower() == needle:
                    return True
        return False

    @staticmethod
    def _iter_alias_values(source: Any) -> list[str]:
        values: list[str] = []
        if isinstance(source, str):
            values = [part.strip() for part in source.splitlines() if part.strip()]
        elif isinstance(source, list):
            values = [str(item).strip() for item in source if str(item).strip()]
        elif isinstance(source, dict):
            values = [str(value).strip() for value in source.values() if str(value).strip()]
        return values

    @staticmethod
    def _extract_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
        if "content" in payload and isinstance(payload["content"], list):
            return [item for item in payload["content"] if isinstance(item, dict)]
        if "items" in payload and isinstance(payload["items"], list):
            return [item for item in payload["items"] if isinstance(item, dict)]
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]

        log.warning("euvd_client.unexpected_payload_shape", keys=list(payload.keys())[:5])
        return []

    async def close(self) -> None:
        await self._client.aclose()

    async def total_results(self, *, modified_since: datetime | None = None) -> int:
        params: dict[str, Any] = {
            "page": 0,
            "size": 1,
            "fromScore": 0,
            "toScore": 10,
        }
        if modified_since:
            params["fromUpdatedDate"] = modified_since.date().isoformat()

        try:
            async with self._rate_limiter.slot():
                response = await self._client.get(self.SEARCH_PATH, params=params)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.error("euvd_client.total_failed", error=str(exc))
            raise RuntimeError("Failed to fetch EUVD total results.") from exc

        payload = response.json()
        total = payload.get("total")
        if not isinstance(total, int):
            total = payload.get("totalElements")
        if isinstance(total, int):
            return total

        log.warning("euvd_client.total_missing", keys=list(payload.keys())[:5])
        return 0


async def iter_euvd_records(modified_since: datetime | None = None) -> AsyncIterator[dict[str, Any]]:
    client = EUVDClient()
    try:
        async for record in client.list_vulnerabilities(modified_since=modified_since):
            yield record
    finally:
        await client.close()
