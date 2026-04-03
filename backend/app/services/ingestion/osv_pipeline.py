from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import settings
from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.asset_catalog_service import AssetCatalogService
from app.services.ingestion.osv_client import OsvClient
from app.services.ingestion.job_tracker import JobTracker
from app.services.ingestion.normalizer import (
    build_document_from_osv,
    extract_osv_downstream_references,
    _extract_osv_package_info,
    _extract_osv_cvss,
)
from app.utils.strings import slugify

log = structlog.get_logger()

STATE_KEY = "osv"


class OsvPipeline:
    """
    Pipeline for ingesting vulnerabilities from OSV.dev.

    Hybrid approach (mirrors GHSA pipeline):
    - Records with CVE alias: enrich existing CVE documents with OSV data.
    - Records without CVE alias (MAL-*, PYSEC-*, etc.): create new documents.
    """

    def __init__(self, *, client: OsvClient | None = None) -> None:
        self.client = client or OsvClient()

    async def sync(
        self,
        *,
        limit: int | None = None,
        initial_sync: bool = False,
    ) -> dict[str, int]:
        """
        Sync vulnerabilities from OSV.dev API.

        Args:
            limit: Maximum number of records to process.
            initial_sync: If True, fetch all records (no modified_since filter).
        """
        state_repo = await IngestionStateRepository.create()
        tracker = JobTracker(state_repo)
        effective_limit = self._resolve_limit(limit)
        if initial_sync and effective_limit is not None:
            log.info(
                "osv_pipeline.initial_sync_unbounded",
                configured_limit=effective_limit,
            )
            effective_limit = None
        job_name = "osv_initial_sync" if initial_sync else "osv_sync"
        label = "OSV Initial Sync" if initial_sync else "OSV Sync"
        ctx = await tracker.start(
            job_name,
            limit=effective_limit,
            initial_sync=initial_sync,
            label=label,
        )

        created = 0
        enriched = 0
        unchanged = 0
        skipped = 0
        failures = 0

        timeout_minutes = settings.ingestion_running_timeout_minutes
        timeout_seconds = timeout_minutes * 60 if timeout_minutes and timeout_minutes > 0 else None
        timed_out = False

        try:
            repository = await VulnerabilityRepository.create()
            asset_catalog = await AssetCatalogService.create()

            # Determine modified_since for incremental sync
            modified_since: datetime | None = None
            if not initial_sync:
                last_ts = await state_repo.get_timestamp(STATE_KEY)
                if last_ts:
                    modified_since = last_ts
                else:
                    log.warning(
                        "osv_pipeline.no_last_timestamp",
                        message="No previous sync timestamp found - fetching all records",
                    )

            log.info(
                "osv_pipeline.starting",
                initial_sync=initial_sync,
                modified_since=modified_since.isoformat() if modified_since else None,
                limit=effective_limit,
            )

            async with asyncio.timeout(timeout_seconds):
                async for record in self.client.iter_all_vulnerabilities(
                    modified_since=modified_since,
                    max_records=effective_limit,
                ):
                    try:
                        result_status = await self._process_record(
                            record=record,
                            repository=repository,
                            asset_catalog=asset_catalog,
                            job_name=job_name,
                            job_label=label,
                        )

                        if result_status == "created":
                            created += 1
                        elif result_status == "enriched":
                            enriched += 1
                        elif result_status == "unchanged":
                            unchanged += 1
                        elif result_status == "skipped":
                            skipped += 1

                    except Exception as exc:
                        osv_id = record.get("id", "unknown")
                        log.warning(
                            "osv_pipeline.process_failed",
                            osv_id=osv_id,
                            error=str(exc),
                        )
                        failures += 1
                        continue

        except TimeoutError:
            timed_out = True
            log.warning(
                "osv_pipeline.timeout",
                timeout_seconds=timeout_seconds,
                created=created,
                enriched=enriched,
                failures=failures,
            )

        except Exception as exc:
            log.exception("osv_pipeline.sync_failed", error=str(exc))
            await tracker.fail(ctx, str(exc))
            raise

        await state_repo.set_timestamp(STATE_KEY, datetime.now(tz=UTC))

        result = {
            "created": created,
            "enriched": enriched,
            "unchanged": unchanged,
            "skipped": skipped,
            "failures": failures,
            "limit": effective_limit,
            "modified_since": modified_since.isoformat() if modified_since else None,
            "timed_out": timed_out,
        }
        await tracker.finish(ctx, **result)
        log.info("osv_pipeline.sync_complete", **result)
        return result

    async def _process_record(
        self,
        *,
        record: dict[str, Any],
        repository: VulnerabilityRepository,
        asset_catalog: AssetCatalogService,
        job_name: str,
        job_label: str,
    ) -> str:
        """
        Process a single OSV record.
        Returns: 'created', 'enriched', 'unchanged', or 'skipped'
        """
        raw_osv_id = record.get("id")
        if not isinstance(raw_osv_id, str) or not raw_osv_id.strip():
            return "skipped"
        raw_osv_id = raw_osv_id.strip()  # original case — used for OSV URLs

        # Normalize GHSA/MAL/PYSEC prefixed IDs to uppercase to match
        # the convention used by the GHSA pipeline (prevents duplicates)
        _UPPER_PREFIXES = ("GHSA-", "MAL-", "PYSEC-")
        osv_id = raw_osv_id.upper() if raw_osv_id.upper().startswith(_UPPER_PREFIXES) else raw_osv_id

        # Skip withdrawn records
        if record.get("withdrawn") is not None:
            return "skipped"

        # Determine vuln_id from aliases
        aliases_raw = record.get("aliases") or []
        cve_id: str | None = None
        ghsa_alias: str | None = None
        if isinstance(aliases_raw, list):
            for alias in aliases_raw:
                if not isinstance(alias, str) or not alias.strip():
                    continue
                upper = alias.strip().upper()
                if upper.startswith("CVE-") and cve_id is None:
                    cve_id = upper
                elif upper.startswith("GHSA-") and ghsa_alias is None:
                    ghsa_alias = upper

        # Prefer CVE > GHSA > OSV ID as the canonical document ID.
        # MAL-* entries almost always have a GHSA alias; using the GHSA ID
        # allows the GHSA pipeline to enrich the same document.
        has_cve = cve_id is not None
        if has_cve:
            vuln_id = cve_id
        elif ghsa_alias:
            vuln_id = ghsa_alias
        else:
            vuln_id = osv_id

        # Extract package info
        vendors, products, product_versions, product_version_map, impacted_products = _extract_osv_package_info(record)

        # Extract CVSS
        cvss, cvss_metrics = _extract_osv_cvss(record)

        # Extract references
        references: list[str] = []
        refs_raw = record.get("references") or []
        if isinstance(refs_raw, list):
            for ref in refs_raw:
                if isinstance(ref, dict):
                    url = ref.get("url")
                    if isinstance(url, str) and url.strip():
                        references.append(url.strip())
                elif isinstance(ref, str):
                    references.append(ref)

        # Add downstream distro reference URLs (Debian, Ubuntu)
        for downstream_url in extract_osv_downstream_references(record, vuln_id):
            if downstream_url not in references:
                references.append(downstream_url)

        # Extract CWEs
        cwes: list[str] = []
        db_specific = record.get("database_specific") or {}
        cwe_ids = db_specific.get("cwe_ids") or []
        if isinstance(cwe_ids, list):
            for cwe_id_str in cwe_ids:
                if isinstance(cwe_id_str, str) and cwe_id_str.strip():
                    cwes.append(cwe_id_str.strip())

        # Build aliases list (case-insensitive dedup)
        aliases: list[str] = [osv_id]
        seen_upper: set[str] = {osv_id.upper()}
        if has_cve:
            aliases.append(cve_id)
            seen_upper.add(cve_id.upper())
        if isinstance(aliases_raw, list):
            for alias in aliases_raw:
                if isinstance(alias, str) and alias.strip():
                    normed = alias.strip().upper() if alias.strip().upper().startswith(("GHSA-", "MAL-", "PYSEC-", "CVE-")) else alias.strip()
                    if normed.upper() not in seen_upper:
                        seen_upper.add(normed.upper())
                        aliases.append(normed)

        # Record assets
        try:
            catalog_result = await asset_catalog.record_assets(
                vendors=vendors,
                product_versions=product_version_map,
                cpes=[],
                cpe_configurations=None,
            )
        except Exception as exc:
            log.warning("osv_pipeline.asset_catalog_failed", osv_id=osv_id, error=str(exc))
            catalog_result = None

        change_context = {
            "job_name": job_name,
            "job_label": job_label,
            "metadata": {
                "trigger": "automated",
                "provider": "OSV",
            },
        }

        # Build document as fallback for creation mode
        build_result = build_document_from_osv(record, ingested_at=datetime.now(tz=UTC))
        if build_result is None:
            if not has_cve:
                return "skipped"
            document = None
        else:
            document = build_result[0]

        result = await repository.upsert_from_osv(
            vuln_id=vuln_id,
            osv_id=osv_id,
            document=document,
            vendors=vendors,
            products=products,
            product_versions=product_versions,
            vendor_slugs=catalog_result.vendor_slugs if catalog_result else [slugify(v) or v.lower() for v in vendors],
            product_slugs=catalog_result.product_slugs if catalog_result else [slugify(p) or p.lower() for p in products],
            product_version_ids=catalog_result.version_ids if catalog_result else [],
            impacted_products=impacted_products,
            references=references,
            aliases=aliases,
            cwes=cwes,
            cvss=cvss,
            cvss_metrics=cvss_metrics,
            summary=record.get("summary"),
            osv_raw=record,
            change_context=change_context,
        )

        if result == "inserted":
            log.debug("osv_pipeline.created", vuln_id=vuln_id, osv_id=osv_id)
            return "created"
        elif result == "updated":
            log.debug("osv_pipeline.enriched", vuln_id=vuln_id, osv_id=osv_id)
            return "enriched"
        else:
            return "unchanged"

    async def close(self) -> None:
        await self.client.close()

    @staticmethod
    def _resolve_limit(explicit_limit: int | None) -> int | None:
        configured_limit = settings.osv_max_records_per_run
        if configured_limit is not None and configured_limit <= 0:
            configured_limit = None

        if explicit_limit is None:
            return configured_limit
        if explicit_limit <= 0:
            return None
        return explicit_limit
