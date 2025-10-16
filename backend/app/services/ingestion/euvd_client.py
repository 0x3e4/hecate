from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import httpx
import structlog

from app.core.config import settings

log = structlog.get_logger()


class EUVDClient:
    """
    Client for the EUVD public API.
    Fetches paginated vulnerability data and yields raw records.
    """

    SEARCH_PATH = "/search"
    MAX_PAGE_SIZE = 100

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_seconds: int | None = None,
        page_size: int | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = (base_url or settings.euvd_base_url).rstrip("/")
        self.timeout = timeout_seconds or settings.euvd_timeout_seconds
        configured_page_size = page_size or settings.euvd_page_size
        self.page_size = min(configured_page_size, self.MAX_PAGE_SIZE)
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


async def iter_euvd_records(modified_since: datetime | None = None) -> AsyncIterator[dict[str, Any]]:
    client = EUVDClient()
    try:
        async for record in client.list_vulnerabilities(modified_since=modified_since):
            yield record
    finally:
        await client.close()
