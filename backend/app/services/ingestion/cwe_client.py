from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter

log = structlog.get_logger()


class CWEClient:
    """
    Client for MITRE CWE REST API.
    Fetches Common Weakness Enumeration data for vulnerability analysis.

    API Documentation: https://github.com/CWE-CAPEC/REST-API-wg
    Base URL: https://cwe-api.mitre.org/api/v1/
    """

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        rate_limiter: AsyncRateLimiter | None = None,
    ) -> None:
        """
        Initialize CWE API client.

        Args:
            client: Optional httpx client (for testing/DI)
            rate_limiter: Optional rate limiter (defaults to 1 req/sec to be respectful)
        """
        self._client = client or httpx.AsyncClient(
            base_url=settings.cwe_base_url,
            timeout=settings.cwe_timeout_seconds,
            headers={
                "User-Agent": settings.ingestion_user_agent,
                "Accept": "application/json",
            },
        )
        # Be respectful to free API - configurable rate limit (default 1 req/sec)
        self._rate_limiter = rate_limiter or AsyncRateLimiter(settings.cwe_rate_limit_seconds)

    async def fetch_weakness(self, cwe_id: str | int) -> dict[str, Any] | None:
        """
        Fetch detailed information about a specific CWE weakness.

        Args:
            cwe_id: CWE identifier (e.g., "79", "CWE-79", or 79)

        Returns:
            CWE data dict with fields like Name, Description, ExtendedDescription,
            CommonConsequences, PotentialMitigations, DetectionMethods, etc.
            Returns None if CWE not found or request fails.

        Example:
            cwe_data = await client.fetch_weakness("79")
            # Returns full XSS weakness data
        """
        # Normalize CWE ID (strip "CWE-" prefix if present)
        normalized_id = str(cwe_id).upper().replace("CWE-", "")

        try:
            async with self._rate_limiter.slot():
                response = await self._client.get(f"/cwe/weakness/{normalized_id}")
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                log.debug("cwe_client.not_found", cwe_id=cwe_id)
                return None
            log.warning(
                "cwe_client.fetch_failed",
                cwe_id=cwe_id,
                status=exc.response.status_code,
                error=str(exc),
            )
            return None
        except httpx.HTTPError as exc:
            log.warning("cwe_client.fetch_error", cwe_id=cwe_id, error=str(exc))
            return None

        try:
            data = response.json()
            # The API returns the CWE object directly
            if isinstance(data, dict) and "ID" in data:
                return data
        except Exception as exc:  # pragma: no cover - defensive
            log.error("cwe_client.parse_error", cwe_id=cwe_id, error=str(exc))

        return None

    async def fetch_multiple(self, cwe_ids: list[str | int]) -> dict[str, dict[str, Any]]:
        """
        Fetch multiple CWE weaknesses.

        Note: The API supports comma-separated IDs in a single request,
        but for simplicity and better error handling, we fetch individually.

        Args:
            cwe_ids: List of CWE identifiers

        Returns:
            Dict mapping normalized CWE IDs (e.g., "79") to their data.
            Missing/failed CWEs are omitted from the result.

        Example:
            results = await client.fetch_multiple(["79", "89", "22"])
            # Returns {"79": {...}, "89": {...}, "22": {...}}
        """
        results: dict[str, dict[str, Any]] = {}

        for cwe_id in cwe_ids:
            normalized_id = str(cwe_id).upper().replace("CWE-", "")
            data = await self.fetch_weakness(normalized_id)
            if data:
                results[normalized_id] = data

        return results

    async def get_api_version(self) -> dict[str, Any] | None:
        """
        Get CWE API version information.

        Returns:
            Version info dict with ContentVersion, ContentDate, TotalWeaknesses, etc.
            Example: {"ContentVersion": "4.15", "TotalWeaknesses": 959, "TotalCategories": 409}
        """
        try:
            async with self._rate_limiter.slot():
                response = await self._client.get("/cwe/version")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            log.warning("cwe_client.version_check_failed", error=str(exc))
            return None

    async def fetch_all_weaknesses(self) -> list[dict[str, Any]]:
        """
        Fetch ALL CWE weaknesses from the API.

        This uses the /cwe/weakness/all endpoint which returns all weaknesses
        in a single request (no pagination needed).

        Returns:
            List of CWE weakness dictionaries
        """
        try:
            log.info("cwe_client.fetching_all_weaknesses")
            async with self._rate_limiter.slot():
                response = await self._client.get("/cwe/weakness/all")
            response.raise_for_status()

            data = response.json()
            # API returns {"Weaknesses": [...]}
            if isinstance(data, dict) and "Weaknesses" in data:
                weaknesses = data["Weaknesses"]
                if isinstance(weaknesses, list):
                    log.info("cwe_client.fetched_all_weaknesses", count=len(weaknesses))
                    return weaknesses

            log.warning("cwe_client.unexpected_response_format", data_type=type(data).__name__)
            return []

        except httpx.HTTPError as exc:
            log.error("cwe_client.fetch_all_failed", error=str(exc))
            return []

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
