from __future__ import annotations

from datetime import UTC, datetime
import copy
import re
from typing import Any

import structlog

from app.core.config import settings
from app.models.vulnerability import ExploitationMetadata, VulnerabilityDocument
from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.repositories.ingestion_log_repository import IngestionLogRepository
from app.repositories.kev_repository import KevRepository
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
        self._kev_metadata_cache: dict[str, tuple[ExploitationMetadata, dict[str, Any] | None]] | None = None

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

        # Always fetch remote_total for accurate progress tracking
        remote_total: int | None = None
        try:
            remote_total = await self.euvd_client.total_results(modified_since=modified_since if not initial_sync else None)
            log.info("pipeline.euvd_remote_total_fetched", remote_total=remote_total, modified_since=modified_since)
        except RuntimeError as exc:
            log.warning("pipeline.euvd_total_failed", error=str(exc))

        run_full = False
        if initial_sync and not user_supplied_since:
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
        requested_since_iso = requested_since.isoformat() if isinstance(requested_since, datetime) else None

        progress_interval = 500
        last_progress_log = datetime.now(tz=UTC)
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
                        log.info("pipeline.known_exploited_loaded", count=len(known_exploited_upper))
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
                            log.info("pipeline.known_exploited_loaded", count=len(known_exploited_upper))
                if not metadata_cache:
                    fetched = await self.kev_client.fetch_known_exploited_cves()
                    known_exploited_upper = {value.upper() for value in fetched}
                    self._known_exploited_cache = known_exploited_upper
                    if known_exploited_upper:
                        log.info("pipeline.known_exploited_loaded", count=len(known_exploited_upper))
            if not known_exploited_upper and self._known_exploited_cache is not None:
                known_exploited_upper = self._known_exploited_cache
            else:
                self._known_exploited_cache = known_exploited_upper

            async for record in self.euvd_client.list_vulnerabilities(modified_since=modified_since):
                processed += 1
                identifiers = _extract_identifiers(record)
                if identifiers is None:
                    skipped += 1
                    continue

                cve_id, source_id = identifiers

                # EUVD pipeline should operate independently - don't fetch from NVD
                # NVD data will be added by the separate NVD sync job
                supplemental = None
                supplemental_cpe_matches = None
                document, product_version_map = build_document(
                    cve_id=cve_id,
                    source_id=source_id,
                    euvd_record=record,
                    supplemental_record=supplemental,
                    supplemental_cpe_matches=supplemental_cpe_matches,
                    ingested_at=datetime.now(tz=UTC),
                )

                candidate_latest = document.modified or document.published
                if candidate_latest:
                    ts = candidate_latest.astimezone(UTC)
                    if not latest_modified or ts > latest_modified:
                        latest_modified = ts

                existing_doc = await repository.collection.find_one(
                    {"_id": document.vuln_id},
                    projection={
                        "impacted_products": 1,
                        "impactedProducts": 1,
                        "cpe_configurations": 1,
                        "cpeConfigurations": 1,
                    },
                )
                existing_impacted = []
                existing_cpe_configs = []
                if isinstance(existing_doc, dict):
                    existing_impacted = existing_doc.get("impacted_products") or existing_doc.get("impactedProducts") or []
                    existing_cpe_configs = existing_doc.get("cpe_configurations") or existing_doc.get("cpeConfigurations") or []

                existing_timestamps = await repository.get_timestamps(document.vuln_id)
                if existing_timestamps:
                    existing_published = existing_timestamps.get("published")
                    existing_modified = existing_timestamps.get("modified")
                    has_reference_timestamp = document.published is not None or document.modified is not None
                    requires_impacted_update = bool(document.impacted_products) and not existing_impacted
                    requires_cpe_config_update = bool(document.cpe_configurations) and not existing_cpe_configs

                    if cve_id and "2024-57254" in cve_id:
                        log.debug(
                            "pipeline.skip_check",
                            vuln_id=cve_id,
                            has_reference_timestamp=has_reference_timestamp,
                            timestamps_match=_timestamps_match(existing_published, document.published) and _timestamps_match(existing_modified, document.modified),
                            requires_impacted_update=requires_impacted_update,
                            requires_cpe_config_update=requires_cpe_config_update,
                            document_cpe_configs_count=len(document.cpe_configurations),
                            existing_cpe_configs_count=len(existing_cpe_configs),
                        )

                    if (
                        has_reference_timestamp
                        and _timestamps_match(existing_published, document.published)
                        and _timestamps_match(existing_modified, document.modified)
                        and not requires_impacted_update
                        and not requires_cpe_config_update
                    ):
                        skipped += 1
                        log.debug(
                            "pipeline.vulnerability_skipped_unchanged",
                            vuln_id=cve_id,
                            source_id=source_id,
                        )
                        continue

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
                except Exception as exc:  # noqa: BLE001 - log and continue
                    log.warning("pipeline.asset_catalog_update_failed", vuln_id=cve_id, error=str(exc))

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

                metadata: dict[str, Any] = {
                    "pipeline": "EUVD",
                    "initial_sync": initial_sync,
                    "document_source": document.source,
                    "vuln_id": document.vuln_id,
                }
                if requested_since_iso:
                    metadata["requested_since"] = requested_since_iso
                limit_value = ctx.metadata.get("limit")
                if limit_value is not None:
                    metadata["limit"] = limit_value
                if document.source_id:
                    metadata["source_id"] = document.source_id

                change_context = {
                    "job_name": ctx.name,
                    "job_label": ctx.metadata.get("label"),
                    "metadata": metadata,
                }

                upsert_result = await repository.upsert(
                    document,
                    change_context=change_context,
                    euvd_raw=record
                )
                if upsert_result.inserted:
                    ingested += 1
                else:
                    updated += 1

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
