from __future__ import annotations

from datetime import UTC, datetime, timedelta
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
        limit: int | None = None,
    ) -> dict[str, Any]:
        repository = await VulnerabilityRepository.create()
        asset_catalog = await AssetCatalogService.create()
        state_repo = await IngestionStateRepository.create()
        tracker = JobTracker(state_repo)

        effective_limit = self._resolve_limit(limit)
        if initial_sync and effective_limit is not None:
            log.info(
                "nvd_pipeline.initial_sync_unbounded",
                configured_limit=effective_limit,
            )
            effective_limit = None

        job_name = "nvd_initial_sync" if initial_sync else "nvd_sync"
        label = "NVD Initial Sync" if initial_sync else "NVD Sync"
        ctx = await tracker.start(job_name, label=label, initial_sync=initial_sync, limit=effective_limit)

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
        local_total_before = await repository.count(source="NVD")

        # Always fetch remote_total for accurate progress tracking
        remote_total: int | None = None
        try:
            remote_total = await self.client.total_results()
            log.info("nvd_pipeline.remote_total_fetched", remote_total=remote_total, last_run=last_run)
        except RuntimeError as exc:
            log.warning("nvd_pipeline.total_failed", error=str(exc))

        run_full = False
        if initial_sync and not user_supplied_since:
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

            # For non-initial syncs, use lastModEndDate to limit the range
            # Use last 7 days to ensure we capture recent changes
            last_modified_end = None
            if not initial_sync:
                last_modified_end = datetime.now(tz=UTC)
                # If we have a last_run timestamp, start from there, otherwise go back 7 days
                if last_run is None:
                    last_run = last_modified_end - timedelta(days=7)

            async for record in self.client.iter_cves(
                last_modified_start=last_run,
                last_modified_end=last_modified_end,
            ):
                # Early extraction of CVE ID and timestamps for skip check
                cve_wrapper = record.get("cve") if isinstance(record, dict) else None
                if not isinstance(cve_wrapper, dict):
                    skipped += 1
                    continue

                cve_id = cve_wrapper.get("id")
                if not isinstance(cve_id, str) or not cve_id.strip():
                    skipped += 1
                    continue

                # Parse timestamps early to check if we can skip this CVE
                published_raw = cve_wrapper.get("published")
                modified_raw = cve_wrapper.get("lastModified")

                # Quick timestamp check before expensive operations - single DB query
                if published_raw or modified_raw:
                    # Single optimized query to get both timestamps and source info
                    existing_doc = await repository.collection.find_one(
                        {"_id": cve_id},
                        projection={"published": 1, "modified": 1, "sources": 1}
                    )

                    if existing_doc:
                        from dateutil import parser as date_parser

                        published = None
                        modified = None
                        try:
                            if published_raw:
                                published = date_parser.isoparse(published_raw).astimezone(UTC)
                            if modified_raw:
                                modified = date_parser.isoparse(modified_raw).astimezone(UTC)
                        except (ValueError, TypeError):
                            pass

                        existing_published = existing_doc.get("published")
                        existing_modified = existing_doc.get("modified")

                        # Check if NVD source already exists and extract its raw data
                        existing_nvd_raw = None
                        sources_array = existing_doc.get("sources")
                        if isinstance(sources_array, list):
                            for src in sources_array:
                                if isinstance(src, dict) and src.get("source") == "NVD":
                                    existing_nvd_raw = src.get("raw")
                                    break

                        # Skip if NVD raw data is identical (regardless of timestamp differences)
                        # NVD appears to be updating published/modified timestamps without changing actual data
                        published_matches = _timestamps_match(existing_published, published)
                        modified_matches = _timestamps_match(existing_modified, modified)
                        nvd_raw_matches = existing_nvd_raw is not None and existing_nvd_raw == record

                        if nvd_raw_matches:
                            skipped += 1
                            processed_total += 1
                            log.debug(
                                "nvd_pipeline.vulnerability_skipped_unchanged_early",
                                vuln_id=cve_id,
                                published_matches=published_matches,
                                modified_matches=modified_matches,
                            )
                            continue

                        # Debug: Log why we're not skipping (always log first 50 to understand the issue)
                        if processed_total < 50 or processed_total % 100 == 0:
                            # Check if raw data differs and log some details
                            raw_diff_reason = None
                            if existing_nvd_raw is None:
                                raw_diff_reason = "no_existing_raw"
                            elif existing_nvd_raw != record:
                                # Try to identify what's different
                                import json
                                existing_str = json.dumps(existing_nvd_raw, sort_keys=True, default=str)
                                incoming_str = json.dumps(record, sort_keys=True, default=str)
                                if len(existing_str) != len(incoming_str):
                                    raw_diff_reason = f"size_diff_{len(existing_str)}_vs_{len(incoming_str)}"
                                else:
                                    raw_diff_reason = "content_diff"
                            else:
                                raw_diff_reason = "matches"

                            log.info(
                                "nvd_pipeline.not_skipping_reason",
                                vuln_id=cve_id,
                                has_nvd_source=existing_nvd_raw is not None,
                                nvd_raw_matches=nvd_raw_matches,
                                raw_diff_reason=raw_diff_reason,
                                published_matches=published_matches,
                                modified_matches=modified_matches,
                                existing_published=str(existing_published)[:19] if existing_published else None,
                                incoming_published=str(published)[:19] if published else None,
                                existing_modified=str(existing_modified)[:19] if existing_modified else None,
                                incoming_modified=str(modified)[:19] if modified else None,
                            )

                # CPE configuration data is already included in the bulk CVE response
                # No need to make additional API calls to fetch CPE matches separately
                result = build_document_from_nvd(
                    record,
                    ingested_at=datetime.now(tz=UTC),
                    cpe_matches=None,
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

                # Timestamp check already done early - proceed with KEV metadata enrichment
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

                change_context = {
                    "job_name": job_name,
                    "job_label": label,
                    "metadata": {
                        "trigger": "automated",
                        "provider": "NVD",
                        "initial_sync": initial_sync,
                    },
                }
                upsert_result = await repository.upsert_from_nvd(
                    document, nvd_raw=record, change_context=change_context
                )
                if upsert_result.inserted:
                    ingested += 1
                else:
                    updated += 1
                processed_total += 1

                # Check if we've hit the ingestion limit
                if effective_limit is not None and ingested >= effective_limit:
                    log.info(
                        "nvd_pipeline.limit_reached",
                        ingested=ingested,
                        limit=effective_limit,
                    )
                    break

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
                        "nvd_pipeline.progress",
                        processed=processed_total,
                        ingested=ingested,
                        updated=updated,
                        skipped=skipped,
                        limit=effective_limit,
                        remote_total=remote_total,
                        initial_sync=initial_sync,
                    )
                    last_progress_log = now

            if latest_modified:
                await state_repo.set_timestamp(STATE_KEY, latest_modified)

            local_total_after = await repository.count(source="NVD")

            # Count how many vulnerabilities have NVD source data (including those with EUVD as primary source)
            nvd_source_count = await repository.collection.count_documents({
                "sources.source": "NVD"
            })

            result = {
                "ingested": ingested,
                "updated": updated,
                "skipped": skipped,
                "limit": effective_limit,
                "initial_sync": initial_sync,
                "run_full": run_full,
                "local_total_before": local_total_before,
                "local_total_after": local_total_after,
                "remote_total": remote_total,
                "since": requested_since,
                "processed": processed_total,
                "nvd_source_count": nvd_source_count,
            }
            await tracker.finish(ctx, **result)
            log.info(
                "nvd_pipeline.sync_complete",
                **result,
                coverage_pct=round((nvd_source_count / remote_total * 100), 2) if remote_total else None,
            )
            return result
        except Exception as exc:  # noqa: BLE001
            await tracker.fail(ctx, str(exc))
            raise
        finally:
            await self.client.close()
            await self.kev_client.close()

    @staticmethod
    def _resolve_limit(explicit_limit: int | None) -> int | None:
        configured_limit = settings.nvd_max_records_per_run
        if configured_limit is not None and configured_limit <= 0:
            configured_limit = None

        if explicit_limit is None:
            return configured_limit
        if explicit_limit <= 0:
            return None
        return explicit_limit


def _normalize_timestamp(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _timestamps_match(existing: datetime | None, incoming: datetime | None) -> bool:
    if incoming is None:
        return existing is None
    if existing is None:
        return False
    return _normalize_timestamp(existing) == _normalize_timestamp(incoming)
