"""VulnCheck KEV as an exploit signal (opt-in, the operator's own community token).

VulnCheck KEV lists CVEs with public reports of exploitation, usually days or
weeks before CISA's catalogue. Its community licence asks for prominent
attribution and forbids passing the data on for free, so Hecate only fetches it
at runtime with ``VULNCHECK_API_TOKEN`` (off without one), labels it
"VulnCheck KEV" wherever it shows it, and keeps a summary per CVE: dates,
ransomware use and the first report / exploit links, not the records.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
import structlog

from app.core.config import settings
from app.repositories.exploit_signal_repository import ExploitSignalRepository
from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.services.http.retry import request_with_retry
from app.services.http.ssl import get_http_verify
from app.services.ingestion.job_tracker import JobTracker

log = structlog.get_logger()

JOB_NAME = "vulncheck_kev_sync"
JOB_LABEL = "VulnCheck KEV Sync"
SOURCE = "vulncheck_kev"
ATTRIBUTION = "VulnCheck KEV"
ATTRIBUTION_URL = "https://vulncheck.com/kev"

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
_PAGE_SIZE = 500
_MAX_PAGES = 200
_MAX_LINKS = 3
MIN_KEEP_RATIO = 0.5


def _text(value: Any, limit: int = 300) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split())[:limit]
    return cleaned or None


def _links(items: Any, key: str) -> list[str]:
    links: list[str] = []
    for item in items if isinstance(items, list) else []:
        url = item.get(key) if isinstance(item, dict) else None
        if isinstance(url, str) and url.startswith("https://") and len(url) <= 500 and url not in links:
            links.append(url)
        if len(links) >= _MAX_LINKS:
            break
    return links


def summarize_record(record: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    """``(CVE ids, stored summary)`` of one VulnCheck KEV record."""
    cves = [
        c.strip().upper() for c in record.get("cve") or []
        if isinstance(c, str) and _CVE_ID.match(c.strip().upper())
    ]
    xdb = record.get("vulncheck_xdb")
    reports = record.get("vulncheck_reported_exploitation")
    summary = {
        "name": _text(record.get("vulnerabilityName"), 200),
        "vendor": _text(record.get("vendorProject"), 100),
        "product": _text(record.get("product"), 100),
        "date_added": _text(record.get("date_added"), 40),
        "cisa_date_added": _text(record.get("cisa_date_added"), 40),
        "ransomware": _text(record.get("knownRansomwareCampaignUse"), 40),
        "canaries": record.get("reported_exploited_by_vulncheck_canaries") is True,
        "report_count": len(reports) if isinstance(reports, list) else 0,
        "report_urls": _links(reports, "url"),
        "exploit_count": len(xdb) if isinstance(xdb, list) else 0,
        "exploit_urls": _links(xdb, "xdb_url"),
    }
    return cves, summary


def entries_from_records(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        cves, summary = summarize_record(record)
        for cve in cves:
            entries.setdefault(cve, summary)
    return entries


class VulnCheckKevPipeline:
    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._owns_client = client is None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(settings.vulncheck_timeout_seconds, connect=10.0),
                headers={"User-Agent": settings.ingestion_user_agent},
                verify=get_http_verify(),
            )
        return self._client

    async def fetch_records(self) -> list[dict[str, Any]]:
        """Every VulnCheck KEV record, through the cursor pagination of the index API."""
        token = settings.vulncheck_api_token
        if not token:
            raise RuntimeError("VulnCheck KEV needs VULNCHECK_API_TOKEN.")
        client = self._http()
        url = f"{settings.vulncheck_base_url.rstrip('/')}/v3/index/vulncheck-kev"
        # The token goes in the header, never the URL (URLs end up in logs).
        client.headers["Authorization"] = f"Bearer {token}"
        records: list[dict[str, Any]] = []
        params: dict[str, Any] = {"limit": _PAGE_SIZE, "start_cursor": "true"}
        for _ in range(_MAX_PAGES):
            response = await request_with_retry(
                client, "GET", url, params=params, max_retries=3, backoff_base=5.0,
                log_prefix="vulncheck_kev", validate_json=True,
            )
            if response is None:
                raise RuntimeError("VulnCheck KEV did not answer.")
            if response.status_code in (401, 402, 403):
                raise RuntimeError(f"VulnCheck KEV refused the token (HTTP {response.status_code}).")
            if response.status_code != 200:
                raise RuntimeError(f"VulnCheck KEV answered HTTP {response.status_code}.")
            body = response.json() if response.content else {}
            page = body.get("data") if isinstance(body, dict) else None
            records.extend(r for r in page or [] if isinstance(r, dict))
            cursor = ((body.get("_meta") or {}) if isinstance(body, dict) else {}).get("next_cursor")
            if not cursor:
                return records
            params = {"limit": _PAGE_SIZE, "cursor": cursor}
        raise RuntimeError(f"VulnCheck KEV pagination did not end after {_MAX_PAGES} pages.")

    async def sync(self, repository: ExploitSignalRepository | None = None) -> dict[str, Any]:
        repository = repository or await ExploitSignalRepository.create()
        tracker = JobTracker(await IngestionStateRepository.create())
        ctx = await tracker.start(JOB_NAME, label=JOB_LABEL)
        try:
            entries = entries_from_records(await self.fetch_records())
            previous = len(await repository.source_entries(SOURCE))
            if not entries or (previous and len(entries) < previous * MIN_KEEP_RATIO):
                raise RuntimeError(
                    f"VulnCheck KEV lists {len(entries)} CVEs, {previous} known: refusing to drop them."
                )
            result = await repository.replace_source(SOURCE, entries)
        except Exception as exc:
            await tracker.fail(ctx, str(exc))
            raise
        await tracker.finish(ctx, **result)
        log.info("vulncheck_kev.synced", **result)
        return result

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None
