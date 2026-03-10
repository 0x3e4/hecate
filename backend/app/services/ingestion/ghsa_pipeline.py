from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import settings
from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.asset_catalog_service import AssetCatalogService
from app.services.ingestion.ghsa_client import GhsaClient
from app.services.ingestion.job_tracker import JobTracker
from app.services.ingestion.normalizer import (
    build_document_from_ghsa,
    _extract_ghsa_package_info,
    _extract_ghsa_cvss,
    extract_ghsa_ids,
)
from app.utils.strings import slugify

log = structlog.get_logger()

STATE_KEY = "ghsa"


class GhsaPipeline:
    """
    Pipeline for ingesting GitHub Security Advisories.

    Hybrid approach:
    - Advisories with cve_id: enrich existing CVE documents with package data.
    - Advisories without cve_id: create new VulnerabilityDocument entries.
    """

    def __init__(self, *, client: GhsaClient | None = None) -> None:
        self.client = client or GhsaClient()

    async def sync(
        self,
        *,
        limit: int | None = None,
        initial_sync: bool = False,
    ) -> dict[str, int]:
        """
        Sync advisories from GitHub Security Advisories API.

        Args:
            limit: Maximum number of advisories to process.
            initial_sync: If True, fetch all advisories (no modified_since filter).
        """
        state_repo = await IngestionStateRepository.create()
        tracker = JobTracker(state_repo)
        effective_limit = self._resolve_limit(limit)
        job_name = "ghsa_initial_sync" if initial_sync else "ghsa_sync"
        label = "GHSA Initial Sync" if initial_sync else "GHSA Sync"
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
            modified_since: str | None = None
            if not initial_sync:
                last_ts = await state_repo.get_timestamp(STATE_KEY)
                if last_ts:
                    modified_since = last_ts.strftime("%Y-%m-%d")

            log.info(
                "ghsa_pipeline.starting",
                initial_sync=initial_sync,
                modified_since=modified_since,
                limit=effective_limit,
            )

            async with asyncio.timeout(timeout_seconds):
                async for advisory in self.client.iter_all_advisories(
                    modified_since=modified_since,
                    max_records=effective_limit,
                ):
                    try:
                        result_status = await self._process_advisory(
                            advisory=advisory,
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
                        ghsa_id = advisory.get("ghsa_id", "unknown")
                        log.warning(
                            "ghsa_pipeline.process_failed",
                            ghsa_id=ghsa_id,
                            error=str(exc),
                        )
                        failures += 1
                        continue

        except TimeoutError:
            timed_out = True
            log.warning(
                "ghsa_pipeline.timeout",
                timeout_seconds=timeout_seconds,
                created=created,
                enriched=enriched,
                failures=failures,
            )

        except Exception as exc:
            log.exception("ghsa_pipeline.sync_failed", error=str(exc))
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
            "timed_out": timed_out,
        }
        await tracker.finish(ctx, **result)
        log.info("ghsa_pipeline.sync_complete", **result)
        return result

    async def _process_advisory(
        self,
        *,
        advisory: dict[str, Any],
        repository: VulnerabilityRepository,
        asset_catalog: AssetCatalogService,
        job_name: str,
        job_label: str,
    ) -> str:
        """
        Process a single GHSA advisory.
        Returns: 'created', 'enriched', 'unchanged', or 'skipped'
        """
        ghsa_id = advisory.get("ghsa_id")
        if not isinstance(ghsa_id, str) or not ghsa_id.strip():
            return "skipped"
        ghsa_id = ghsa_id.strip().upper()

        # Skip withdrawn advisories
        if advisory.get("withdrawn_at") is not None:
            return "skipped"

        cve_id = advisory.get("cve_id")
        has_cve = isinstance(cve_id, str) and cve_id.strip()
        vuln_id = cve_id if has_cve else ghsa_id

        # Extract package info
        vendors, products, product_versions, product_version_map, impacted_products = _extract_ghsa_package_info(advisory)

        # Extract CVSS
        cvss, cvss_metrics = _extract_ghsa_cvss(advisory)

        # Extract references
        references: list[str] = []
        refs_raw = advisory.get("references") or []
        if isinstance(refs_raw, list):
            for ref in refs_raw:
                if isinstance(ref, str):
                    references.append(ref)

        # Extract CWEs
        cwes: list[str] = []
        cwes_raw = advisory.get("cwes") or []
        if isinstance(cwes_raw, list):
            for cwe in cwes_raw:
                if isinstance(cwe, dict):
                    cwe_id = cwe.get("cwe_id")
                    if isinstance(cwe_id, str) and cwe_id.strip():
                        cwes.append(cwe_id.strip())

        # Extract aliases (case-insensitive dedup for GHSA/MAL/PYSEC)
        aliases: list[str] = [ghsa_id]
        seen_upper: set[str] = {ghsa_id.upper()}
        if has_cve:
            aliases.append(cve_id)
            seen_upper.add(cve_id.upper())
        identifiers = advisory.get("identifiers") or []
        if isinstance(identifiers, list):
            for ident in identifiers:
                if isinstance(ident, dict):
                    val = ident.get("value")
                    if isinstance(val, str) and val.strip() and val.strip().upper() not in seen_upper:
                        seen_upper.add(val.strip().upper())
                        aliases.append(val.strip())

        # Record assets
        try:
            catalog_result = await asset_catalog.record_assets(
                vendors=vendors,
                product_versions=product_version_map,
                cpes=[],
                cpe_configurations=None,
            )
        except Exception as exc:
            log.warning("ghsa_pipeline.asset_catalog_failed", ghsa_id=ghsa_id, error=str(exc))
            catalog_result = None

        change_context = {
            "job_name": job_name,
            "job_label": job_label,
            "metadata": {
                "trigger": "automated",
                "provider": "GHSA",
            },
        }

        # Build document for creation mode (GHSA-only, no CVE)
        document = None
        if not has_cve:
            build_result = build_document_from_ghsa(advisory, ingested_at=datetime.now(tz=UTC))
            if build_result is None:
                return "skipped"
            document = build_result[0]

        result = await repository.upsert_from_ghsa(
            vuln_id=vuln_id,
            ghsa_id=ghsa_id,
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
            summary=advisory.get("summary"),
            published=None,
            modified=None,
            ghsa_raw=advisory,
            change_context=change_context,
        )

        if result == "inserted":
            log.debug("ghsa_pipeline.created", vuln_id=vuln_id, ghsa_id=ghsa_id)
            return "created"
        elif result == "updated":
            log.debug("ghsa_pipeline.enriched", vuln_id=vuln_id, ghsa_id=ghsa_id)
            return "enriched"
        else:
            return "unchanged"

    async def close(self) -> None:
        await self.client.close()

    @staticmethod
    def _resolve_limit(explicit_limit: int | None) -> int | None:
        configured_limit = settings.ghsa_max_records_per_run
        if configured_limit is not None and configured_limit <= 0:
            configured_limit = None

        if explicit_limit is None:
            return configured_limit
        if explicit_limit <= 0:
            return None
        return explicit_limit
