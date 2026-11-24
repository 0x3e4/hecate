"""Which CVEs have a public Nuclei template (projectdiscovery/nuclei-templates, MIT).

The template repository publishes ``cves.json``: one JSON object per line with
the CVE id, the template's name, severity, description and its path. A
template means anyone can check a host for the CVE with one command, which
matters for prioritising (an exposure scan finds it for attackers too). Only the
id, name, severity and path are kept; the template itself is linked, not stored.
"""

from __future__ import annotations

import json
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

JOB_NAME = "nuclei_templates_sync"
JOB_LABEL = "Nuclei Templates Sync"
SOURCE = "nuclei"

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
# A template path inside the repository, e.g. http/cves/2024/CVE-2024-3400.yaml.
_TEMPLATE_PATH = re.compile(r"^[A-Za-z0-9_\-]+(?:/[A-Za-z0-9_.\-]+)+\.ya?ml$")
_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
# Refuse to drop most of the corpus because of one truncated download.
MIN_KEEP_RATIO = 0.5


def parse_index(text: str) -> dict[str, dict[str, Any]]:
    """``{CVE id: {name, severity, path, protocol}}`` from ``cves.json``; bad lines are skipped."""
    entries: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        cve = str(record.get("ID") or "").strip().upper()
        path = str(record.get("file_path") or "").strip()
        if not _CVE_ID.match(cve) or not _TEMPLATE_PATH.match(path) or ".." in path:
            continue
        info = record.get("Info") if isinstance(record.get("Info"), dict) else {}
        name = " ".join(str(info.get("Name") or "").split())[:200]
        severity = str(info.get("Severity") or "").strip().lower()
        entries[cve] = {
            "name": name or cve,
            "severity": severity if severity in _SEVERITIES else "unknown",
            "path": path,
            "protocol": path.split("/", 1)[0],
        }
    return entries


def template_url(path: str) -> str:
    return f"{settings.nuclei_templates_browse_url.rstrip('/')}/{path}"


class NucleiTemplatesPipeline:
    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._owns_client = client is None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(settings.nuclei_templates_timeout_seconds, connect=10.0),
                headers={"User-Agent": settings.ingestion_user_agent},
                verify=get_http_verify(),
                follow_redirects=True,
            )
        return self._client

    async def fetch_index(self) -> dict[str, dict[str, Any]] | None:
        response = await request_with_retry(
            self._http(),
            "GET",
            settings.nuclei_templates_index_url,
            max_retries=3,
            backoff_base=5.0,
            log_prefix="nuclei_templates",
        )
        if response is None or response.status_code != 200:
            return None
        return parse_index(response.text)

    async def sync(self, repository: ExploitSignalRepository | None = None) -> dict[str, Any]:
        repository = repository or await ExploitSignalRepository.create()
        tracker = JobTracker(await IngestionStateRepository.create())
        ctx = await tracker.start(JOB_NAME, label=JOB_LABEL)
        try:
            entries = await self.fetch_index()
            if entries is None:
                raise RuntimeError("Nuclei template index could not be downloaded.")
            previous = len(await repository.source_entries(SOURCE))
            if not entries or (previous and len(entries) < previous * MIN_KEEP_RATIO):
                raise RuntimeError(
                    f"Nuclei template index lists {len(entries)} CVEs, {previous} known: refusing to drop them."
                )
            result = await repository.replace_source(SOURCE, entries)
        except Exception as exc:
            await tracker.fail(ctx, str(exc))
            raise
        await tracker.finish(ctx, **result)
        log.info("nuclei_templates.synced", **result)
        return result

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None
