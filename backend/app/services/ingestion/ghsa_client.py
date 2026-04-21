from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import structlog

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter
from app.services.http.ssl import get_http_verify

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

        if not resolved_token:
            log.warning("ghsa_client.no_token", message="No GHSA_TOKEN configured - GitHub API rate limits will be very restrictive (60 req/hr)")

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
            verify=get_http_verify(),
        )
        self._rate_limiter = rate_limiter or AsyncRateLimiter(settings.ghsa_rate_limit_seconds)
        self._has_token = bool(resolved_token)

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
            params["modified"] = f">={modified_since}"
        if after:
            params["after"] = after

        try:
            async with self._rate_limiter.slot():
                response = await self._client.get(self.base_url, params=params)

            # Check for rate limiting before raising
            if response.status_code == 403:
                remaining = response.headers.get("x-ratelimit-remaining", "?")
                reset = response.headers.get("x-ratelimit-reset", "?")
                log.error(
                    "ghsa_client.rate_limited",
                    status=403,
                    remaining=remaining,
                    reset=reset,
                    has_token=self._has_token,
                )
                return [], None

            response.raise_for_status()
            advisories = response.json()
            next_cursor = self._parse_next_cursor(response.headers.get("link"))

            count = len(advisories) if isinstance(advisories, list) else 0
            log.debug(
                "ghsa_client.page_fetched",
                count=count,
                has_next=next_cursor is not None,
                modified_since=modified_since,
            )

            return advisories if isinstance(advisories, list) else [], next_cursor

        except httpx.HTTPStatusError as exc:
            log.error(
                "ghsa_client.http_error",
                status=exc.response.status_code,
                error=str(exc),
                has_token=self._has_token,
            )
            return [], None

        except httpx.HTTPError as exc:
            log.warning("ghsa_client.fetch_failed", error=str(exc), has_token=self._has_token)
            return [], None

    async def fetch_advisory_by_id(
        self,
        ghsa_id: str,
    ) -> dict[str, Any] | None:
        """Fetch a single advisory by its GHSA ID."""
        url = f"{self.base_url}/{ghsa_id}"
        try:
            async with self._rate_limiter.slot():
                response = await self._client.get(url)

            if response.status_code == 404:
                return None

            if response.status_code == 403:
                log.error("ghsa_client.rate_limited", ghsa_id=ghsa_id, status=403)
                return None

            response.raise_for_status()
            data = response.json()
            return data if isinstance(data, dict) else None

        except httpx.HTTPError as exc:
            log.warning("ghsa_client.fetch_single_failed", ghsa_id=ghsa_id, error=str(exc))
            return None

    async def fetch_advisory_by_cve(
        self,
        cve_id: str,
    ) -> dict[str, Any] | None:
        """Fetch a single advisory by its CVE ID."""
        params: dict[str, str | int] = {
            "type": "reviewed",
            "cve_id": cve_id,
            "per_page": 1,
        }
        try:
            async with self._rate_limiter.slot():
                response = await self._client.get(self.base_url, params=params)

            if response.status_code == 403:
                log.error("ghsa_client.rate_limited", cve_id=cve_id, status=403)
                return None

            response.raise_for_status()
            advisories = response.json()
            if isinstance(advisories, list) and advisories:
                return advisories[0]
            return None

        except httpx.HTTPError as exc:
            log.warning("ghsa_client.fetch_by_cve_failed", cve_id=cve_id, error=str(exc))
            return None

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
        page = 0

        while True:
            page += 1
            advisories, next_cursor = await self.fetch_advisories(
                modified_since=modified_since,
                after=after,
            )

            if not advisories:
                if page == 1:
                    log.info(
                        "ghsa_client.no_advisories",
                        modified_since=modified_since,
                        message="First page returned empty - check API token and filters",
                    )
                break

            for advisory in advisories:
                yield advisory
                yielded += 1
                if max_records is not None and yielded >= max_records:
                    log.info("ghsa_client.limit_reached", yielded=yielded, max_records=max_records)
                    return

            if next_cursor is None:
                break
            after = next_cursor

        log.info("ghsa_client.iteration_complete", pages=page, yielded=yielded)

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
