from __future__ import annotations

from datetime import UTC, datetime
import re
from typing import Any

import structlog

from app.core.config import settings
from app.models.vulnerability import VulnerabilityDocument
from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.repositories.ingestion_log_repository import IngestionLogRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.asset_catalog_service import AssetCatalogService
from app.services.ingestion.job_tracker import JobTracker
from app.services.ingestion.euvd_client import EUVDClient
from app.services.ingestion.cisa_client import CisaKevClient
from app.services.ingestion.normalizer import build_document
from app.services.ingestion.nvd_client import NVDClient

log = structlog.get_logger()

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class IngestionPipeline:
    def __init__(
        self,
        *,
        euvd_client: EUVDClient | None = None,
        nvd_client: NVDClient | None = None,
        kev_client: CisaKevClient | None = None,
    ) -> None:
        self.euvd_client = euvd_client or EUVDClient()
        self.nvd_client = nvd_client or NVDClient()
        self.kev_client = kev_client or CisaKevClient()
        self._known_exploited_cache: set[str] | None = None

    async def ingest(
        self,
        *,
        modified_since: datetime | None = None,
        limit: int | None = None,
        initial_sync: bool = False,
    ) -> dict[str, int]:
        repository = await VulnerabilityRepository.create()
        asset_catalog = await AssetCatalogService.create()
        state_repo = await IngestionStateRepository.create()
        tracker = JobTracker(state_repo)
        effective_limit = self._resolve_limit(limit)
        if initial_sync and effective_limit is not None:
            log.info(
                "pipeline.initial_sync_unbounded",
                configured_limit=effective_limit,
            )
            effective_limit = None
        job_name = "euvd_initial_sync" if initial_sync else "euvd_ingestion"
        label = "EUVD Initial Sync" if initial_sync else "EUVD Sync"
        ctx = await tracker.start(
            job_name,
            limit=effective_limit,
            initial_sync=initial_sync,
            label=label,
        )
        user_supplied_since = modified_since is not None
        configured_since: datetime | None = None
        if settings.vulnerability_initial_backfill_since:
            try:
                configured_since = datetime.fromisoformat(
                    settings.vulnerability_initial_backfill_since.replace("Z", "+00:00")
                ).astimezone(UTC)
            except ValueError:
                log.warning(
                    "pipeline.invalid_backfill_since",
                    value=settings.vulnerability_initial_backfill_since,
                )
        requested_since = modified_since
        if not user_supplied_since:
            if modified_since is None:
                modified_since = await state_repo.get_timestamp("euvd")
                requested_since = modified_since
            if modified_since is None and configured_since is not None:
                modified_since = configured_since
                requested_since = configured_since

        local_total_before = await repository.count(source="EUVD")
        remote_total: int | None = None
        run_full = False
        if initial_sync and not user_supplied_since:
            try:
                remote_total = await self.euvd_client.total_results()
            except RuntimeError as exc:
                log.warning("pipeline.euvd_total_failed", error=str(exc))
            if remote_total is not None and remote_total > local_total_before:
                run_full = True
                if configured_since is not None:
                    modified_since = configured_since
                    requested_since = configured_since
                else:
                    modified_since = None
                    requested_since = None
                log.info(
                    "pipeline.euvd_full_resync",
                    remote_total=remote_total,
                    local_total_before=local_total_before,
                    since=requested_since,
                )

        ingested = 0
        updated = 0
        skipped = 0
        processed = 0
        latest_modified: datetime | None = None

        progress_interval = 500
        last_progress_log = datetime.now(tz=UTC)
        log_repo: IngestionLogRepository | None = None

        try:
            if self._known_exploited_cache is not None:
                known_exploited_upper = self._known_exploited_cache
            else:
                fetched = await self.kev_client.fetch_known_exploited_cves()
                self._known_exploited_cache = {value.upper() for value in fetched}
                known_exploited_upper = self._known_exploited_cache
                if known_exploited_upper:
                    log.info("pipeline.known_exploited_loaded", count=len(known_exploited_upper))

            async for record in self.euvd_client.list_vulnerabilities(modified_since=modified_since):
                processed += 1
                identifiers = _extract_identifiers(record)
                if identifiers is None:
                    skipped += 1
                    continue

                cve_id, source_id = identifiers

                supplemental = await self.nvd_client.fetch_cve(cve_id) if _is_cve(cve_id) else None
                document, product_version_map = build_document(
                    cve_id=cve_id,
                    source_id=source_id,
                    euvd_record=record,
                    supplemental_record=supplemental,
                    ingested_at=datetime.now(tz=UTC),
                )
                try:
                    catalog_result = await asset_catalog.record_assets(
                        vendors=document.vendors,
                        product_versions=product_version_map,
                        cpes=document.cpes,
                    )
                    document = document.model_copy(
                        update={
                            "vendor_slugs": catalog_result.vendor_slugs,
                            "product_slugs": catalog_result.product_slugs,
                            "product_versions": catalog_result.version_strings or document.product_versions,
                            "product_version_ids": catalog_result.version_ids,
                        }
                    )
                except Exception as exc:  # noqa: BLE001 - log and continue
                    log.warning("pipeline.asset_catalog_update_failed", vuln_id=cve_id, error=str(exc))

                if not document.exploited:
                    normalized_id = (document.vuln_id or "").strip().upper()
                    if normalized_id and normalized_id in known_exploited_upper:
                        document = document.model_copy(update={"exploited": True})

                inserted = await repository.upsert(document)
                if inserted:
                    ingested += 1
                else:
                    updated += 1

                if document.modified:
                    ts = document.modified.astimezone(UTC)
                    if not latest_modified or ts > latest_modified:
                        latest_modified = ts

                log.info(
                    "pipeline.vulnerability_ingested",
                    vuln_id=cve_id,
                    title=document.title,
                    severity=document.cvss.severity,
                    initial_sync=initial_sync,
                )

                if effective_limit is not None and ingested >= effective_limit:
                    break

                now = datetime.now(tz=UTC)
                if (
                    processed % progress_interval == 0
                    or (now - last_progress_log).total_seconds() >= 60
                ):
                    progress_payload = {
                        "processed": processed,
                        "ingested": ingested,
                        "updated": updated,
                        "skipped": skipped,
                        "limit": effective_limit,
                        "remote_total": remote_total,
                    }
                    await state_repo.update_state(
                        f"job:{ctx.name}",
                        {
                            "status": "running",
                            "progress": progress_payload,
                            "last_progress_at": now,
                        },
                    )
                    if ctx.log_id is not None:
                        if log_repo is None:
                            log_repo = await IngestionLogRepository.create()
                        await log_repo.update_progress(ctx.log_id, progress_payload)
                    log.info(
                        "pipeline.euvd_progress",
                        processed=processed,
                        ingested=ingested,
                        updated=updated,
                        skipped=skipped,
                        limit=effective_limit,
                        initial_sync=initial_sync,
                    )
                    last_progress_log = now

            if latest_modified:
                await state_repo.set_timestamp("euvd", latest_modified)

            local_total_after = await repository.count(source="EUVD")

            result = {
                "ingested": ingested,
                "updated": updated,
                "skipped": skipped,
                "limit": effective_limit,
                "initial_sync": initial_sync,
                "processed": processed,
                "since": requested_since,
                "latest_modified": latest_modified,
                "local_total_before": local_total_before,
                "local_total_after": local_total_after,
                "remote_total": remote_total,
                "run_full": run_full,
            }
            await tracker.finish(ctx, **result)
            return result
        except Exception as exc:  # noqa: BLE001
            await tracker.fail(ctx, str(exc))
            raise

    async def close(self) -> None:
        await self.euvd_client.close()
        await self.nvd_client.close()
        await self.kev_client.close()

    @staticmethod
    def _resolve_limit(explicit_limit: int | None) -> int | None:
        configured_limit = settings.euvd_max_records_per_run
        if configured_limit is not None and configured_limit <= 0:
            configured_limit = None

        if explicit_limit is None:
            return configured_limit
        if explicit_limit <= 0:
            return None
        return explicit_limit


def _extract_identifiers(record: dict[str, Any]) -> tuple[str, str | None] | None:
    cve_candidates = [
        record.get("cveNumber"),
        record.get("cve"),
        record.get("cveId"),
        record.get("cve_id"),
    ]
    cve_id = next((value for value in cve_candidates if isinstance(value, str) and value.strip()), None)

    if not cve_id:
        alias_source = record.get("aliases") or record.get("alias")
        cve_id = _extract_cve_from_alias(alias_source)
    if not cve_id:
        references = record.get("references")
        cve_id = _extract_cve_from_alias(references)

    source_candidates = [
        record.get("id"),
        record.get("euvdId"),
        record.get("uuid"),
        record.get("sourceId"),
    ]
    source_id = next((value for value in source_candidates if isinstance(value, str) and value.strip()), None)

    if not cve_id and not source_id:
        return None

    canonical_id = cve_id or source_id
    return canonical_id, source_id


def _is_cve(identifier: str) -> bool:
    return identifier.upper().startswith("CVE-")


def _extract_cve_from_alias(data: Any) -> str | None:
    values: list[str] = []
    if isinstance(data, str):
        values = [data]
    elif isinstance(data, list):
        values = [str(item) for item in data]
    elif isinstance(data, dict):
        values = [str(value) for value in data.values()]

    for value in values:
        match = CVE_PATTERN.search(value)
        if match:
            return match.group(0).upper()
    return None


async def run_ingestion(
    *,
    modified_since: datetime | None = None,
    limit: int | None = None,
    initial_sync: bool = False,
) -> dict[str, int]:
    pipeline = IngestionPipeline()
    try:
        return await pipeline.ingest(
            modified_since=modified_since,
            limit=limit,
            initial_sync=initial_sync,
        )
    finally:
        await pipeline.close()
