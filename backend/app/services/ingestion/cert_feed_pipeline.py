from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.core.config import settings
from app.repositories.cert_advisory_repository import CertAdvisoryRepository, advisory_id
from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.services.ingestion.cert_feed_client import (
    CertAdvisoryItem,
    CertFeed,
    CertFeedClient,
    parse_feed_config,
)
from app.services.ingestion.job_tracker import JobTracker

log = structlog.get_logger()

# Older items cannot reach the 7-day dashboard window, so their pages are not worth a request.
PAGE_FETCH_MAX_AGE = timedelta(days=30)


class CertFeedPipeline:
    """
    Records which CVEs the CERTs are warning about. Advisories live in their own
    collection rather than on the vulnerability documents: a mention is a signal
    with a date, not part of the record, and must not stamp `last_change_at`.
    """

    def __init__(self, *, client: CertFeedClient | None = None) -> None:
        self.client = client or CertFeedClient()

    async def sync(self) -> dict[str, Any]:
        repository = await CertAdvisoryRepository.create()
        tracker = JobTracker(await IngestionStateRepository.create())
        feeds = parse_feed_config(settings.cert_feeds, settings.cert_feeds_extra)
        ctx = await tracker.start("cert_feeds_sync", label="CERT Advisory Sync", feeds=len(feeds))

        inserted = 0
        with_cves = 0
        pages = 0
        failed: list[str] = []
        try:
            for feed in feeds:
                items = await self.client.fetch_feed(feed)
                if items is None:
                    failed.append(feed.name)
                    continue
                stats = await self._store_new_items(repository, feed, items)
                inserted += stats["inserted"]
                with_cves += stats["with_cves"]
                pages += stats["pages"]
        except Exception as exc:
            await tracker.fail(ctx, str(exc))
            raise

        result = {
            "feeds": len(feeds),
            "failedFeeds": failed,
            "inserted": inserted,
            "withCves": with_cves,
            "pagesRead": pages,
        }
        if feeds and len(failed) == len(feeds):
            await tracker.fail(ctx, "all_feeds_failed")
        else:
            await tracker.finish(ctx, **result)
        return result

    async def _store_new_items(
        self,
        repository: CertAdvisoryRepository,
        feed: CertFeed,
        items: list[CertAdvisoryItem],
    ) -> dict[str, int]:
        known = await repository.existing_ids(advisory_id(feed.name, item.guid) for item in items)
        now = datetime.now(UTC)
        pages_left = settings.cert_feeds_max_page_fetches_per_run
        read_pages: dict[str, list[str]] = {}
        stats = {"inserted": 0, "with_cves": 0, "pages": 0}

        for item in items:
            if advisory_id(feed.name, item.guid) in known:
                continue
            cve_ids = item.cve_ids
            fresh = item.published is None or now - item.published <= PAGE_FETCH_MAX_AGE
            if not cve_ids and item.url and fresh:
                page = item.url.split("#", 1)[0]
                if page not in read_pages:
                    if pages_left <= 0:
                        # Stays unrecorded, so the next run picks it up.
                        continue
                    pages_left -= 1
                    stats["pages"] += 1
                    found = await self.client.fetch_page_cves(feed, item.url)
                    if found is None:
                        continue
                    read_pages[page] = found
                cve_ids = read_pages[page]
            await repository.insert(feed.name, item, cve_ids)
            stats["inserted"] += 1
            stats["with_cves"] += bool(cve_ids)
        return stats

    async def close(self) -> None:
        await self.client.close()
