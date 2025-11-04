from __future__ import annotations

from datetime import UTC, datetime
import copy
from typing import Any

import structlog

from app.core.config import settings
from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.repositories.ingestion_log_repository import IngestionLogRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.asset_catalog_service import AssetCatalogService
from app.services.ingestion.job_tracker import JobTracker
from app.services.ingestion.cisa_client import CisaKevClient
from app.services.ingestion.nvd_client import NVDClient
from app.services.ingestion.normalizer import build_document_from_nvd
from app.repositories.kev_repository import KevRepository
from app.models.vulnerability import ExploitationMetadata

log = structlog.get_logger()

STATE_KEY = "nvd"


class NVDPipeline:
    def __init__(
        self,
        *,
        client: NVDClient | None = None,
        kev_client: CisaKevClient | None = None,
    ) -> None:
        self.client = client or NVDClient()
        self.kev_client = kev_client or CisaKevClient()
        self._known_exploited_cache: set[str] | None = None
        self._kev_metadata_cache: dict[str, tuple[ExploitationMetadata, dict[str, Any] | None]] | None = None

    async def sync(
        self,
        *,
        initial_sync: bool = False,
        modified_since: datetime | None = None,
    ) -> dict[str, Any]:
        repository = await VulnerabilityRepository.create()
        asset_catalog = await AssetCatalogService.create()
        state_repo = await IngestionStateRepository.create()
        tracker = JobTracker(state_repo)

        job_name = "nvd_initial_sync" if initial_sync else "nvd_sync"
        label = "NVD Initial Sync" if initial_sync else "NVD Sync"
        ctx = await tracker.start(job_name, label=label, initial_sync=initial_sync)

        user_supplied_since = modified_since is not None
        configured_since: datetime | None = None
        if settings.vulnerability_initial_backfill_since:
            try:
                configured_since = datetime.fromisoformat(
                    settings.vulnerability_initial_backfill_since.replace("Z", "+00:00")
                ).astimezone(UTC)
            except ValueError:
                log.warning(
                    "nvd_pipeline.invalid_backfill_since",
                    value=settings.vulnerability_initial_backfill_since,
                )

        last_run = modified_since
        if not user_supplied_since:
            if last_run is None:
                last_run = await state_repo.get_timestamp(STATE_KEY)
            if last_run is None and configured_since is not None:
                last_run = configured_since

        requested_since = last_run
        run_full = False
        remote_total = None
        local_total_before = await repository.count(source="NVD")

        if initial_sync and not user_supplied_since:
            try:
                remote_total = await self.client.total_results()
            except RuntimeError as exc:
                log.warning("nvd_pipeline.total_failed", error=str(exc))
                remote_total = None
            if remote_total is not None and remote_total > local_total_before:
                run_full = True
                if configured_since is not None:
                    last_run = configured_since
                    requested_since = configured_since
                else:
                    last_run = None
                    requested_since = None
                log.info(
                    "nvd_pipeline.full_resync",
                    remote_total=remote_total,
                    local_total_before=local_total_before,
                    since=requested_since,
                )

        ingested = 0
        updated = 0
        skipped = 0
        processed_total = 0
        last_progress_log = datetime.now(tz=UTC)
        progress_interval = 5000
        latest_modified: datetime | None = None

        log_repo: IngestionLogRepository | None = None

        metadata_cache: dict[str, tuple[ExploitationMetadata, dict[str, Any] | None]] = {}
        try:
            if self._kev_metadata_cache is not None:
                metadata_cache = self._kev_metadata_cache
                known_exploited_upper = set(metadata_cache.keys())
            else:
                kev_repository = await KevRepository.create()
                loaded_metadata = await kev_repository.load_metadata_map()
                if loaded_metadata:
                    metadata_cache = {key.upper(): value for key, value in loaded_metadata.items()}
                    self._kev_metadata_cache = metadata_cache
                    known_exploited_upper = set(metadata_cache.keys())
                    if known_exploited_upper:
                        log.info("nvd_pipeline.known_exploited_loaded", count=len(known_exploited_upper))
                else:
                    fetched_catalog = await self.kev_client.fetch_catalog()
                    if fetched_catalog is not None:
                        temp_cache: dict[str, tuple[ExploitationMetadata, dict[str, Any] | None]] = {}
                        for entry in fetched_catalog.vulnerabilities:
                            if not entry.cve_id:
                                continue
                            metadata = ExploitationMetadata(
                                vendor_project=entry.vendor_project,
                                product=entry.product,
                                vulnerability_name=entry.vulnerability_name,
                                date_added=entry.date_added,
                                short_description=entry.short_description,
                                required_action=entry.required_action,
                                due_date=entry.due_date,
                                known_ransomware_campaign_use=entry.known_ransomware_campaign_use,
                                notes=entry.notes,
                                catalog_version=fetched_catalog.catalog_version,
                                date_released=fetched_catalog.date_released,
                            )
                            temp_cache[entry.cve_id.upper()] = (metadata, entry.raw)
                        if temp_cache:
                            metadata_cache = temp_cache
                            self._kev_metadata_cache = temp_cache
                            known_exploited_upper = set(temp_cache.keys())
                            log.info("nvd_pipeline.known_exploited_loaded", count=len(known_exploited_upper))
                if not metadata_cache:
                    fetched = await self.kev_client.fetch_known_exploited_cves()
                    known_exploited_upper = {value.upper() for value in fetched}
                    self._known_exploited_cache = known_exploited_upper
                    if known_exploited_upper:
                        log.info("nvd_pipeline.known_exploited_loaded", count=len(known_exploited_upper))
            if not known_exploited_upper and self._known_exploited_cache is not None:
                known_exploited_upper = self._known_exploited_cache
            else:
                self._known_exploited_cache = known_exploited_upper

            async for record in self.client.iter_cves(last_modified_start=last_run):
                cve_wrapper = record.get("cve") if isinstance(record, dict) else None
                cve_id = cve_wrapper.get("id") if isinstance(cve_wrapper, dict) else None
                cpe_matches = None
                if isinstance(cve_id, str) and cve_id.strip():
                    cpe_matches = await self.client.fetch_cpe_matches(cve_id)
                result = build_document_from_nvd(
                    record,
                    ingested_at=datetime.now(tz=UTC),
                    cpe_matches=cpe_matches,
                )
                if result is None:
                    skipped += 1
                    continue
                document, product_version_map = result

                try:
                    catalog_result = await asset_catalog.record_assets(
                        vendors=document.vendors,
                        product_versions=product_version_map,
                        cpes=document.cpes,
                        cpe_configurations=document.cpe_configurations,
                    )
                    document = document.model_copy(
                        update={
                            "vendor_slugs": catalog_result.vendor_slugs,
                            "product_slugs": catalog_result.product_slugs,
                            "product_versions": catalog_result.version_strings or document.product_versions,
                            "product_version_ids": catalog_result.version_ids,
                        }
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning("nvd_pipeline.asset_catalog_update_failed", vuln_id=document.vuln_id, error=str(exc))

                normalized_id = (document.vuln_id or "").strip().upper()
                metadata_tuple = metadata_cache.get(normalized_id) if metadata_cache else None
                if metadata_tuple:
                    metadata_model, raw_metadata = metadata_tuple
                    updates: dict[str, Any] = {
                        "exploited": True,
                        "exploitation": metadata_model,
                    }
                    base_raw = copy.deepcopy(document.raw) if isinstance(document.raw, dict) else {}
                    if raw_metadata:
                        base_raw["kev"] = raw_metadata
                        updates["raw"] = base_raw
                    document = document.model_copy(update=updates)
                elif not document.exploited and normalized_id and normalized_id in known_exploited_upper:
                    document = document.model_copy(update={"exploited": True})

                upsert_result = await repository.upsert_from_nvd(document, nvd_raw=record)
                if upsert_result.inserted:
                    ingested += 1
                else:
                    updated += 1
                processed_total += 1

                if document.modified:
                    ts = document.modified.astimezone(UTC)
                    if not latest_modified or ts > latest_modified:
                        latest_modified = ts

                now = datetime.now(tz=UTC)
                if (
                    processed_total % progress_interval == 0
                    or (now - last_progress_log).total_seconds() >= 60
                ):
                    progress_payload = {
                        "processed": processed_total,
                        "ingested": ingested,
                        "updated": updated,
                        "skipped": skipped,
                        "limit": None,
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
                        "nvd_pipeline.progress",
                        processed=processed_total,
                        ingested=ingested,
                        updated=updated,
                        skipped=skipped,
                        limit=None,
                        remote_total=remote_total,
                        initial_sync=initial_sync,
                    )
                    last_progress_log = now

            if latest_modified:
                await state_repo.set_timestamp(STATE_KEY, latest_modified)

            local_total_after = await repository.count(source="NVD")
            result = {
                "ingested": ingested,
                "updated": updated,
                "skipped": skipped,
                "limit": None,
                "initial_sync": initial_sync,
                "run_full": run_full,
                "local_total_before": local_total_before,
                "local_total_after": local_total_after,
                "remote_total": remote_total,
                "since": requested_since,
                "processed": processed_total,
            }
            await tracker.finish(ctx, **result)
            log.info("nvd_pipeline.sync_complete", **result)
            return result
        except Exception as exc:  # noqa: BLE001
            await tracker.fail(ctx, str(exc))
            raise
        finally:
            await self.client.close()
            await self.kev_client.close()
