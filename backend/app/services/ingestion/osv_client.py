from __future__ import annotations

import csv
import io
import json
import zipfile
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import httpx
import structlog

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter
from app.services.http.retry import request_with_retry
from app.services.http.ssl import get_http_verify

log = structlog.get_logger()

# GCS bucket base for ecosystem ZIP exports and modified_id.csv
_GCS_BASE = "https://storage.googleapis.com/osv-vulnerabilities"

# OSV REST API for individual record lookups
_API_BASE_DEFAULT = "https://api.osv.dev/v1"

# Ecosystems relevant for Hecate (supply-chain / package managers).
# MAL-* entries live inside these ecosystem ZIPs, not in a separate bucket.
OSV_ECOSYSTEMS = (
    "npm",
    "PyPI",
    "Go",
    "Maven",
    "RubyGems",
    "crates.io",
    "NuGet",
    "Packagist",
    "Pub",
    "Hex",
    "GitHub Actions",
)


class OsvClient:
    """
    Client for OSV.dev vulnerability data.

    Two sync strategies:
    - **Initial sync**: download ``{ecosystem}/all.zip`` from the GCS bucket.
    - **Incremental sync**: read ``{ecosystem}/modified_id.csv`` (sorted newest
      first), stop at the last-sync timestamp, then fetch changed records
      individually via ``GET /v1/vulns/{id}``.

    References
    ----------
    GCS exports : https://google.github.io/osv.dev/data/#data-dumps
    REST API    : https://google.github.io/osv.dev/api/
    """

    def __init__(
        self,
        *,
        api_base_url: str | None = None,
        timeout_seconds: int | None = None,
        rate_limiter: AsyncRateLimiter | None = None,
        client: httpx.AsyncClient | None = None,
        max_retries: int | None = None,
        retry_backoff: float | None = None,
    ) -> None:
        self.api_base = (api_base_url or settings.osv_base_url).rstrip("/")
        timeout = timeout_seconds or settings.osv_timeout_seconds

        self._client = client or httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": settings.ingestion_user_agent},
            follow_redirects=True,
            verify=get_http_verify(),
        )
        # Separate long-timeout client for large ZIP downloads
        self._download_client = httpx.AsyncClient(
            timeout=httpx.Timeout(300.0, connect=30.0),
            headers={"User-Agent": settings.ingestion_user_agent},
            follow_redirects=True,
            verify=get_http_verify(),
        )
        self._rate_limiter = rate_limiter or AsyncRateLimiter(settings.osv_rate_limit_seconds)
        self._max_retries = max_retries if max_retries is not None else settings.osv_max_retries
        self._retry_backoff = retry_backoff if retry_backoff is not None else settings.osv_retry_backoff_seconds

    # ------------------------------------------------------------------
    # GCS bucket helpers
    # ------------------------------------------------------------------

    async def fetch_ecosystem_zip(
        self,
        ecosystem: str,
    ) -> list[dict[str, Any]]:
        """Download and parse ``{ecosystem}/all.zip`` from the GCS bucket."""
        url = f"{_GCS_BASE}/{ecosystem}/all.zip"
        log.info("osv_client.downloading_zip", ecosystem=ecosystem, url=url)

        response = await request_with_retry(
            self._download_client,
            "GET",
            url,
            max_retries=self._max_retries,
            backoff_base=self._retry_backoff,
            log_prefix="osv_client",
            context={"ecosystem": ecosystem, "op": "zip_download"},
        )
        if response is None:
            log.error("osv_client.zip_download_exhausted", ecosystem=ecosystem, url=url)
            return []
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            log.error(
                "osv_client.zip_download_failed",
                ecosystem=ecosystem,
                status=exc.response.status_code,
                error=str(exc),
            )
            return []
        except httpx.HTTPError as exc:
            log.warning("osv_client.zip_download_error", ecosystem=ecosystem, error=str(exc))
            return []

        records: list[dict[str, Any]] = []
        try:
            with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    try:
                        with zf.open(name) as f:
                            record = json.loads(f.read())
                            if isinstance(record, dict) and record.get("id"):
                                records.append(record)
                    except (json.JSONDecodeError, KeyError) as exc:
                        log.debug("osv_client.zip_entry_parse_failed", file=name, error=str(exc))
        except zipfile.BadZipFile as exc:
            log.error("osv_client.bad_zip", ecosystem=ecosystem, error=str(exc))
            return []

        log.info(
            "osv_client.zip_parsed",
            ecosystem=ecosystem,
            records=len(records),
            zip_size_mb=round(len(response.content) / 1024 / 1024, 1),
        )
        return records

    async def fetch_modified_ids(
        self,
        ecosystem: str,
        *,
        since: datetime | None = None,
    ) -> list[str]:
        """
        Download ``{ecosystem}/modified_id.csv`` and return IDs modified
        after *since*.  The CSV is sorted newest-first so we can stop early.
        """
        url = f"{_GCS_BASE}/{ecosystem}/modified_id.csv"
        response = await request_with_retry(
            self._download_client,
            "GET",
            url,
            max_retries=self._max_retries,
            backoff_base=self._retry_backoff,
            log_prefix="osv_client",
            context={"ecosystem": ecosystem, "op": "modified_csv"},
        )
        if response is None:
            log.warning("osv_client.modified_csv_failed", ecosystem=ecosystem)
            return []
        try:
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("osv_client.modified_csv_failed", ecosystem=ecosystem, error=str(exc))
            return []

        ids: list[str] = []
        reader = csv.reader(io.StringIO(response.text))
        for row in reader:
            if len(row) < 2:
                continue
            ts_str, vuln_id = row[0], row[1]
            if since:
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if ts < since:
                        break  # CSV is sorted newest-first; everything below is older
                except (ValueError, TypeError):
                    pass
            ids.append(vuln_id.strip())

        log.info(
            "osv_client.modified_csv_parsed",
            ecosystem=ecosystem,
            ids_after_filter=len(ids),
        )
        return ids

    # ------------------------------------------------------------------
    # REST API helpers
    # ------------------------------------------------------------------

    async def fetch_vulnerability(self, vuln_id: str) -> dict[str, Any] | None:
        """Fetch a single vulnerability by its OSV ID via ``GET /v1/vulns/{id}``."""
        url = f"{self.api_base}/vulns/{vuln_id}"
        response = await request_with_retry(
            self._client,
            "GET",
            url,
            rate_limiter=self._rate_limiter,
            max_retries=self._max_retries,
            backoff_base=self._retry_backoff,
            log_prefix="osv_client",
            validate_json=True,
            context={"vuln_id": vuln_id, "op": "fetch_single"},
        )
        if response is None:
            return None

        if response.status_code == 404:
            return None

        try:
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("osv_client.fetch_single_failed", vuln_id=vuln_id, error=str(exc))
            return None

        data = response.json()
        return data if isinstance(data, dict) else None

    async def query_by_package(
        self,
        *,
        name: str,
        ecosystem: str,
    ) -> list[dict[str, Any]]:
        """Reverse-lookup helper: ``POST /v1/query`` to find every vulnerability
        OSV lists for a given (package, ecosystem).

        OSV has no direct alias-reverse-lookup endpoint. Manual-refresh for
        GHSA-* IDs that are known to OSV **only as aliases of MAL-*** (i.e.
        the GHSA itself 404s on ``/vulns/{id}``) needs this as a fallback to
        pull the underlying MAL-* record. Callers filter the returned list
        by their own criteria (e.g. "aliases contains our GHSA ID").

        Single attempt, no retry: this is a best-effort fallback, and the
        caller can just try again next time the user clicks refresh.
        """
        url = f"{self.api_base}/query"
        payload = {"package": {"name": name, "ecosystem": ecosystem}}
        try:
            if self._rate_limiter is not None:
                async with self._rate_limiter.slot():
                    response = await self._client.post(url, json=payload)
            else:
                response = await self._client.post(url, json=payload)
        except httpx.HTTPError as exc:
            log.warning(
                "osv_client.query_by_package_failed",
                package=name,
                ecosystem=ecosystem,
                error=str(exc),
            )
            return []
        if response.status_code >= 400:
            log.warning(
                "osv_client.query_by_package_http_error",
                package=name,
                ecosystem=ecosystem,
                status=response.status_code,
            )
            return []
        try:
            data = response.json()
        except Exception:  # noqa: BLE001
            return []
        if not isinstance(data, dict):
            return []
        vulns = data.get("vulns")
        return vulns if isinstance(vulns, list) else []

    # ------------------------------------------------------------------
    # High-level iterators
    # ------------------------------------------------------------------

    async def iter_all_vulnerabilities(
        self,
        *,
        modified_since: datetime | None = None,
        max_records: int | None = None,
        ecosystems: tuple[str, ...] | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """
        Iterate through OSV records across ecosystems.

        Strategy
        --------
        - **initial_sync** (``modified_since is None``): download each
          ecosystem's ``all.zip`` and yield every record.
        - **incremental** (``modified_since`` set): read each ecosystem's
          ``modified_id.csv``, collect IDs newer than the cutoff, then
          fetch full records individually via the REST API.
        """
        target_ecosystems = ecosystems or OSV_ECOSYSTEMS
        yielded = 0
        seen_ids: set[str] = set()

        for ecosystem in target_ecosystems:
            if modified_since is None:
                # --- full / initial sync via ZIP download ---
                async for record in self._iter_zip(ecosystem, seen_ids):
                    yield record
                    yielded += 1
                    if max_records is not None and yielded >= max_records:
                        log.info("osv_client.limit_reached", yielded=yielded)
                        return
            else:
                # --- incremental sync via modified_id.csv + API ---
                async for record in self._iter_incremental(
                    ecosystem, modified_since, seen_ids
                ):
                    yield record
                    yielded += 1
                    if max_records is not None and yielded >= max_records:
                        log.info("osv_client.limit_reached", yielded=yielded)
                        return

        log.info(
            "osv_client.iteration_complete",
            ecosystems=len(target_ecosystems),
            yielded=yielded,
        )

    async def _iter_zip(
        self,
        ecosystem: str,
        seen_ids: set[str],
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield records from an ecosystem ZIP (initial sync)."""
        records = await self.fetch_ecosystem_zip(ecosystem)
        ecosystem_yielded = 0
        for record in records:
            vuln_id = record.get("id")
            if not isinstance(vuln_id, str) or not vuln_id.strip():
                continue
            vuln_id = vuln_id.strip()
            if vuln_id in seen_ids:
                continue
            seen_ids.add(vuln_id)
            yield record
            ecosystem_yielded += 1

        log.info(
            "osv_client.ecosystem_complete",
            ecosystem=ecosystem,
            mode="zip",
            total_in_zip=len(records),
            yielded=ecosystem_yielded,
        )

    async def _iter_incremental(
        self,
        ecosystem: str,
        modified_since: datetime,
        seen_ids: set[str],
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield records changed since cutoff via CSV + API (incremental sync).

        We process the CSV **oldest-first** even though OSV ships it
        newest-first. This matters when an upstream pipeline run is
        truncated by the per-run cap or by a timeout: the pipeline saves
        ``max_processed_modified`` as the next ``modified_since``, and that
        watermark advances monotonically only when iteration is oldest-
        first. Newest-first plus a cap silently drops the oldest unprocessed
        rows — the bug that produced a ~9 % MAL-record gap before this fix.
        """
        changed_ids = await self.fetch_modified_ids(ecosystem, since=modified_since)
        # `fetch_modified_ids` returns CSV order (newest-first); reverse to
        # oldest-first so the pipeline's cursor advances row-by-row from
        # near `modified_since` toward `now`.
        changed_ids = list(reversed(changed_ids))
        fetched = 0
        for vuln_id in changed_ids:
            if vuln_id in seen_ids:
                continue
            seen_ids.add(vuln_id)

            record = await self.fetch_vulnerability(vuln_id)
            if record is None:
                continue

            yield record
            fetched += 1

        log.info(
            "osv_client.ecosystem_complete",
            ecosystem=ecosystem,
            mode="incremental",
            changed_ids=len(changed_ids),
            fetched=fetched,
        )

    async def close(self) -> None:
        await self._client.aclose()
        await self._download_client.aclose()
