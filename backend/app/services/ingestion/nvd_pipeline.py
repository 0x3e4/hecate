from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import settings
from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.ingestion.job_tracker import JobTracker
from app.services.ingestion.nvd_client import NVDClient
from app.services.ingestion.normalizer import build_document_from_nvd

log = structlog.get_logger()

STATE_KEY = "nvd"


class NVDPipeline:
    def __init__(self, *, client: NVDClient | None = None) -> None:
        self.client = client or NVDClient()

    async def sync(
        self,
        *,
        initial_sync: bool = False,
        modified_since: datetime | None = None,
    ) -> dict[str, Any]:
        repository = await VulnerabilityRepository.create()
        state_repo = await IngestionStateRepository.create()
        tracker = JobTracker(state_repo)

        job_name = "nvd_initial_sync" if initial_sync else "nvd_sync"
        label = "NVD Initial Sync" if initial_sync else "NVD Sync"
        ctx = await tracker.start(job_name, label=label, initial_sync=initial_sync)

        last_run = modified_since or await state_repo.get_timestamp(STATE_KEY)
        requested_since = last_run
        run_full = False
        remote_total = None
        local_total_before = await repository.count()

        if initial_sync and modified_since is None:
            remote_total = await self.client.total_results()
            if remote_total > local_total_before:
                run_full = True
                last_run = None

        ingested_new = 0
        updated_existing = 0
        skipped_invalid = 0
        latest_modified: datetime | None = None

        try:
            async for record in self.client.iter_cves(last_modified_start=last_run):
                document = build_document_from_nvd(record, ingested_at=datetime.now(tz=UTC))
                if document is None:
                    skipped_invalid += 1
                    continue

                inserted = await repository.upsert_from_nvd(document, nvd_raw=record)
                if inserted:
                    ingested_new += 1
                else:
                    updated_existing += 1

                if document.modified:
                    ts = document.modified.astimezone(UTC)
                    if not latest_modified or ts > latest_modified:
                        latest_modified = ts

            if latest_modified:
                await state_repo.set_timestamp(STATE_KEY, latest_modified)

            local_total_after = await repository.count()
            result = {
                "ingested_new": ingested_new,
                "updated_existing": updated_existing,
                "skipped_invalid": skipped_invalid,
                "initial_sync": initial_sync,
                "run_full": run_full,
                "local_total_before": local_total_before,
                "local_total_after": local_total_after,
                "remote_total": remote_total,
                "since": requested_since,
            }
            await tracker.finish(ctx, **result)
            log.info("nvd_pipeline.sync_complete", **result)
            return result
        except Exception as exc:  # noqa: BLE001
            await tracker.fail(ctx, str(exc))
            raise
        finally:
            await self.client.close()
