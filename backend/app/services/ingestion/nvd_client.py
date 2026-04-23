from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter
from app.services.http.retry import request_with_retry
from app.services.http.ssl import get_http_verify

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
        max_retries: int | None = None,
        retry_backoff: float | None = None,
    ) -> None:
        headers = {
            "User-Agent": settings.ingestion_user_agent,
            "Accept": "application/json",
        }
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        self._client = client or httpx.AsyncClient(
            base_url=settings.nvd_base_url.rstrip("/"),
            timeout=httpx.Timeout(settings.nvd_timeout_seconds, connect=10.0),
            headers=headers,
            verify=get_http_verify(),
        )
        self._rate_limiter = rate_limiter or AsyncRateLimiter(settings.nvd_rate_limit_seconds)
        configured_page_size = page_size or settings.nvd_page_size
        self._page_size = max(1, min(configured_page_size, 2000))
        self._max_retries = max_retries if max_retries is not None else settings.nvd_max_retries
        self._retry_backoff = retry_backoff if retry_backoff is not None else settings.nvd_retry_backoff_seconds

    async def _get(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> httpx.Response | None:
        return await request_with_retry(
            self._client,
            "GET",
            url,
            params=params,
            rate_limiter=self._rate_limiter,
            max_retries=self._max_retries,
            backoff_base=self._retry_backoff,
            log_prefix="nvd_client",
            context=context,
        )

    async def fetch_cve(self, cve_id: str) -> dict[str, Any] | None:
        response = await self._get("/cves/2.0", params={"cveId": cve_id}, context={"vuln_id": cve_id})
        if response is None:
            log.warning("nvd_client.fetch_failed", vuln_id=cve_id)
            return None
        try:
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

    async def fetch_cpe_matches(self, cve_id: str) -> list[dict[str, Any]] | None:
        response = await self._get("/cpematch/2.0", params={"cveId": cve_id}, context={"vuln_id": cve_id})
        if response is None:
            log.warning("nvd_client.cpe_match_failed", vuln_id=cve_id)
            return None
        try:
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("nvd_client.cpe_match_failed", vuln_id=cve_id, error=str(exc))
            return None

        payload = response.json()
        match_strings = payload.get("matchStrings")
        if isinstance(match_strings, list):
            return match_strings
        return None

    async def total_results(self) -> int:
        params = {"startIndex": 0, "resultsPerPage": 1}
        response = await self._get("/cves/2.0", params=params)
        if response is None:
            raise RuntimeError("Failed to fetch NVD total results.")
        try:
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
        last_modified_end: datetime | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        last_modified_start_param: str | None = None
        last_modified_end_param: str | None = None

        if last_modified_start:
            safe_start = last_modified_start.astimezone(UTC)
            now = datetime.now(tz=UTC)
            if safe_start > now:
                log.warning(
                    "nvd_client.future_last_modified",
                    requested=safe_start,
                    clamped=now,
                )
                safe_start = now
            last_modified_start_param = self._format_datetime(safe_start)

        if last_modified_end:
            safe_end = last_modified_end.astimezone(UTC)
            now = datetime.now(tz=UTC)
            if safe_end > now:
                log.warning(
                    "nvd_client.future_last_modified_end",
                    requested=safe_end,
                    clamped=now,
                )
                safe_end = now
            last_modified_end_param = self._format_datetime(safe_end)

        # Get total results for the filtered query (if lastModStartDate is set, this returns filtered count)
        params: dict[str, Any] = {
            "startIndex": 0,
            "resultsPerPage": 1,
        }
        if last_modified_start_param:
            params["lastModStartDate"] = last_modified_start_param
        if last_modified_end_param:
            params["lastModEndDate"] = last_modified_end_param

        response = await self._get("/cves/2.0", params=params)
        if response is None:
            raise RuntimeError("Failed to get total NVD CVE count.")
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code if exc.response else None
            if status == 404 and last_modified_start_param:
                log.info(
                    "nvd_client.no_results_for_last_mod_range",
                    last_mod_start=last_modified_start_param,
                    last_mod_end=last_modified_end_param,
                )
                return
            log.error(
                "nvd_client.total_query_failed",
                error=str(exc),
                status=status,
            )
            raise RuntimeError("Failed to get total NVD CVE count.") from exc
        except httpx.HTTPError as exc:
            log.error("nvd_client.total_query_failed", error=str(exc))
            raise RuntimeError("Failed to get total NVD CVE count.") from exc

        payload = response.json()
        total_results = payload.get("totalResults")
        if not isinstance(total_results, int) or total_results == 0:
            log.info("nvd_client.no_results", total_results=total_results)
            return

        # Start from the end (newest entries) and work backwards
        # Note: total_results is already filtered by lastModStartDate/lastModEndDate if provided
        start_index = max(0, total_results - self._page_size)
        log.info(
            "nvd_client.starting_from_newest",
            total_results=total_results,
            start_index=start_index,
            filtered_by_date=last_modified_start_param is not None or last_modified_end_param is not None,
        )

        while start_index >= 0:
            params = {
                "startIndex": start_index,
                "resultsPerPage": self._page_size,
            }
            if last_modified_start_param:
                params["lastModStartDate"] = last_modified_start_param
            if last_modified_end_param:
                params["lastModEndDate"] = last_modified_end_param

            response = await self._get("/cves/2.0", params=params, context={"start_index": start_index})
            if response is None:
                raise RuntimeError("Failed to iterate NVD CVEs.")
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code if exc.response else None
                log.error(
                    "nvd_client.page_failed",
                    start_index=start_index,
                    error=str(exc),
                    status=status,
                )
                raise RuntimeError("Failed to iterate NVD CVEs.") from exc
            except httpx.HTTPError as exc:
                log.error("nvd_client.page_failed", start_index=start_index, error=str(exc))
                raise RuntimeError("Failed to iterate NVD CVEs.") from exc

            payload = response.json()
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

            # Move backwards to process older entries
            start_index -= self._page_size

    async def close(self) -> None:
        await self._client.aclose()

    @staticmethod
    def _format_datetime(value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        value = value.astimezone(UTC)
        return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
