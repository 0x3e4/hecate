from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import structlog

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter

log = structlog.get_logger()

_LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')


class GhsaClient:
    """
    Client for the GitHub Security Advisories API.
    Fetches reviewed global advisories with cursor-based pagination.

    API documentation: https://docs.github.com/en/rest/security-advisories/global-advisories
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_seconds: int | None = None,
        rate_limiter: AsyncRateLimiter | None = None,
        token: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = (base_url or settings.ghsa_base_url).rstrip("/")
        timeout = timeout_seconds or settings.ghsa_timeout_seconds
        resolved_token = token if token is not None else settings.ghsa_token

        headers: dict[str, str] = {
            "User-Agent": settings.ingestion_user_agent,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if resolved_token:
            headers["Authorization"] = f"Bearer {resolved_token}"

        self._client = client or httpx.AsyncClient(
            timeout=timeout,
            headers=headers,
        )
        self._rate_limiter = rate_limiter or AsyncRateLimiter(settings.ghsa_rate_limit_seconds)

    async def fetch_advisories(
        self,
        *,
        modified_since: str | None = None,
        per_page: int = 100,
        after: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """
        Fetch a page of reviewed advisories.
        Returns (advisories, next_cursor). next_cursor is None on the last page.

        Args:
            modified_since: ISO date string for incremental sync (e.g. "2024-01-01").
                            Filters with modified=">YYYY-MM-DD".
            per_page: Number of advisories per page (max 100).
            after: Cursor for pagination (from previous response).
        """
        params: dict[str, str | int] = {
            "type": "reviewed",
            "per_page": per_page,
        }
        if modified_since:
            params["modified"] = f">{modified_since}"
        if after:
            params["after"] = after

        try:
            async with self._rate_limiter.slot():
                response = await self._client.get(self.base_url, params=params)

            response.raise_for_status()
            advisories = response.json()
            next_cursor = self._parse_next_cursor(response.headers.get("link"))
            return advisories if isinstance(advisories, list) else [], next_cursor

        except httpx.HTTPError as exc:
            log.warning("ghsa_client.fetch_failed", error=str(exc))
            return [], None

    async def iter_all_advisories(
        self,
        *,
        modified_since: str | None = None,
        max_records: int | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """
        Paginate through all reviewed advisories, yielding individual advisory dicts.
        Stops when max_records is reached or no more pages.
        """
        after: str | None = None
        yielded = 0

        while True:
            advisories, next_cursor = await self.fetch_advisories(
                modified_since=modified_since,
                after=after,
            )

            if not advisories:
                break

            for advisory in advisories:
                yield advisory
                yielded += 1
                if max_records is not None and yielded >= max_records:
                    return

            if next_cursor is None:
                break
            after = next_cursor

    @staticmethod
    def _parse_next_cursor(link_header: str | None) -> str | None:
        """Parse the 'after' cursor from GitHub's Link header rel='next'."""
        if not link_header:
            return None
        match = _LINK_NEXT_RE.search(link_header)
        if not match:
            return None
        url = match.group(1)
        qs = parse_qs(urlparse(url).query)
        after_values = qs.get("after")
        if after_values:
            return after_values[0]
        return None

    async def close(self) -> None:
        await self._client.aclose()
