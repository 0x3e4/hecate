from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import settings
from app.repositories.ingestion_state_repository import IngestionStateRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.asset_catalog_service import AssetCatalogService
from app.services.ingestion.circl_client import CirclClient
from app.services.ingestion.job_tracker import JobTracker

log = structlog.get_logger()

STATE_KEY = "circl"


class CirclPipeline:
    """
    Pipeline for enriching vulnerabilities with vendor/product/version data from CIRCL.

    This pipeline:
    - Only updates existing vulnerabilities (does not create new ones)
    - Only processes vulnerabilities with missing vendor, product, or version data
    - Adds CIRCL as a source entry with raw data
    """

    def __init__(self, *, client: CirclClient | None = None) -> None:
        self.client = client or CirclClient()

    async def sync(self, limit: int | None = None) -> dict[str, int]:
        """
        Sync vulnerabilities from CIRCL to enrich missing product/vendor/version data.

        This is a normal sync only - no initial_sync support as this pipeline
        only enriches existing records.
        """
        state_repo = await IngestionStateRepository.create()
        tracker = JobTracker(state_repo)
        effective_limit = self._resolve_limit(limit)
        job_name = "circl_sync"
        label = "CIRCL Enrichment Sync"
        ctx = await tracker.start(
            job_name,
            limit=effective_limit,
            initial_sync=False,
            label=label,
        )

        enriched = 0
        skipped = 0
        failures = 0
        not_found = 0

        timeout_minutes = settings.ingestion_running_timeout_minutes
        timeout_seconds = timeout_minutes * 60 if timeout_minutes and timeout_minutes > 0 else None
        timed_out = False

        try:
            repository = await VulnerabilityRepository.create()
            asset_catalog = await AssetCatalogService.create()

            # Find vulnerabilities with missing vendor/product/version data
            vuln_ids = await self._find_vulns_needing_enrichment(repository, effective_limit)

            if not vuln_ids:
                log.info("circl_pipeline.no_vulns_to_enrich")
                result = {
                    "enriched": 0,
                    "skipped": 0,
                    "failures": 0,
                    "not_found": 0,
                    "limit": effective_limit,
                    "timed_out": False,
                }
                await tracker.finish(ctx, **result)
                return result

            log.info("circl_pipeline.starting_enrichment", vuln_count=len(vuln_ids))

            async with asyncio.timeout(timeout_seconds):
                async for cve_id, circl_record in self.client.iter_cve_records(vuln_ids):
                    try:
                        result_status = await self._enrich_vulnerability(
                            cve_id=cve_id,
                            circl_record=circl_record,
                            repository=repository,
                            asset_catalog=asset_catalog,
                            job_name=job_name,
                            job_label=label,
                        )

                        if result_status == "enriched":
                            enriched += 1
                        elif result_status == "skipped":
                            skipped += 1
                        elif result_status == "not_found":
                            not_found += 1

                        if effective_limit is not None and (enriched + skipped + not_found) >= effective_limit:
                            break

                    except Exception as exc:
                        log.warning(
                            "circl_pipeline.enrich_failed",
                            cve_id=cve_id,
                            error=str(exc),
                        )
                        failures += 1
                        continue

        except TimeoutError:
            timed_out = True
            log.warning(
                "circl_pipeline.timeout",
                timeout_seconds=timeout_seconds,
                enriched=enriched,
                failures=failures,
            )

        except Exception as exc:
            log.exception("circl_pipeline.sync_failed", error=str(exc), enriched=enriched, failures=failures)
            await tracker.fail(ctx, str(exc))
            raise

        await state_repo.set_timestamp(STATE_KEY, datetime.now(tz=UTC))

        result = {
            "enriched": enriched,
            "skipped": skipped,
            "failures": failures,
            "not_found": not_found,
            "limit": effective_limit,
            "timed_out": timed_out,
        }
        await tracker.finish(ctx, **result)
        log.info("circl_pipeline.sync_complete", **result)
        return result

    async def _find_vulns_needing_enrichment(
        self,
        repository: VulnerabilityRepository,
        limit: int | None,
    ) -> list[str]:
        """
        Find vulnerabilities that are missing vendor, product, or version data.
        Only returns CVE IDs (CIRCL only has CVE data).
        """
        pipeline: list[dict[str, Any]] = [
            {
                "$match": {
                    "vuln_id": {"$regex": "^CVE-"},
                    "$or": [
                        {"vendors": {"$in": [None, []]}},
                        {"products": {"$in": [None, []]}},
                        {"product_versions": {"$in": [None, []]}},
                    ],
                }
            },
            {"$sort": {"ingested_at": -1}},  # Sort first (newest first)
        ]

        if limit:
            pipeline.append({"$limit": limit})

        pipeline.append({"$project": {"_id": 1}})  # Project last

        cursor = repository.collection.aggregate(pipeline)
        results = await cursor.to_list(length=limit or 10000)
        return [doc["_id"] for doc in results if doc.get("_id")]

    async def _enrich_vulnerability(
        self,
        *,
        cve_id: str,
        circl_record: dict[str, Any],
        repository: VulnerabilityRepository,
        asset_catalog: AssetCatalogService,
        job_name: str,
        job_label: str,
    ) -> str:
        """
        Enrich a single vulnerability with CIRCL data.
        Returns: 'enriched', 'skipped', or 'not_found'
        """
        # Extract vendor/product/version data from CIRCL record
        vendors, products, versions, product_version_map = _extract_product_info(circl_record)

        if not vendors and not products and not versions:
            log.debug("circl_pipeline.no_product_info", cve_id=cve_id)
            return "skipped"

        # Update asset catalog
        cpes = _extract_cpes(circl_record)
        try:
            catalog_result = await asset_catalog.record_assets(
                vendors=vendors,
                product_versions=product_version_map,
                cpes=cpes,
                cpe_configurations=None,
            )
        except Exception as exc:
            log.warning(
                "circl_pipeline.asset_catalog_failed",
                cve_id=cve_id,
                error=str(exc),
            )
            catalog_result = None

        # Update the vulnerability in the database
        change_context = {
            "job_name": job_name,
            "job_label": job_label,
            "metadata": {
                "trigger": "automated",
                "provider": "CIRCL",
            },
        }

        result = await repository.upsert_from_circl(
            cve_id=cve_id,
            vendors=vendors,
            products=products,
            product_versions=versions,
            vendor_slugs=catalog_result.vendor_slugs if catalog_result else [],
            product_slugs=catalog_result.product_slugs if catalog_result else [],
            product_version_ids=catalog_result.version_ids if catalog_result else [],
            circl_raw=circl_record,
            change_context=change_context,
        )

        if result == "updated":
            log.debug(
                "circl_pipeline.enriched",
                cve_id=cve_id,
                vendors=vendors,
                products=products,
                versions_count=len(versions),
            )
            return "enriched"
        elif result == "not_found":
            return "not_found"
        else:
            return "skipped"

    async def close(self) -> None:
        await self.client.close()

    @staticmethod
    def _resolve_limit(explicit_limit: int | None) -> int | None:
        configured_limit = settings.circl_max_records_per_run
        if configured_limit is not None and configured_limit <= 0:
            configured_limit = None

        if explicit_limit is None:
            return configured_limit
        if explicit_limit <= 0:
            return None
        return explicit_limit


def _extract_product_info(record: dict[str, Any]) -> tuple[list[str], list[str], list[str], dict[str, set[str]]]:
    """
    Extract vendor, product, and version information from a CIRCL record.
    Supports both CVE 5.x format (containers.cna.affected) and legacy format.
    Returns: (vendors, products, versions, product_version_map)
    """
    vendors: set[str] = set()
    products: set[str] = set()
    versions: set[str] = set()
    product_version_map: dict[str, set[str]] = {}

    # CVE 5.x format: containers.cna.affected[]
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    affected_list = cna.get("affected") or []
    if isinstance(affected_list, list):
        for item in affected_list:
            if not isinstance(item, dict):
                continue
            vendor = item.get("vendor")
            product = item.get("product")
            if isinstance(vendor, str) and vendor.strip():
                vendors.add(vendor.strip())
            if isinstance(product, str) and product.strip():
                product_name = product.strip()
                products.add(product_name)
                # Extract versions from versions array
                versions_list = item.get("versions") or []
                if isinstance(versions_list, list):
                    for ver_item in versions_list:
                        if isinstance(ver_item, dict):
                            version = ver_item.get("version")
                            if isinstance(version, str) and version.strip() and version not in ("*", "-"):
                                versions.add(version.strip())
                                bucket = product_version_map.setdefault(product_name, set())
                                bucket.add(version.strip())

    # Legacy format: vulnerable_product field (CPE URIs)
    vulnerable_products = record.get("vulnerable_product") or []
    if isinstance(vulnerable_products, list):
        for cpe in vulnerable_products:
            if not isinstance(cpe, str):
                continue
            parsed = _parse_cpe_uri(cpe)
            if parsed:
                vendor, product, version = parsed
                if vendor:
                    vendors.add(vendor)
                if product:
                    products.add(product)
                    if version:
                        versions.add(version)
                        bucket = product_version_map.setdefault(product, set())
                        bucket.add(version)

    # Legacy format: vendors field if present
    vendor_list = record.get("vendors") or []
    if isinstance(vendor_list, list):
        for vendor in vendor_list:
            if isinstance(vendor, str) and vendor.strip():
                vendors.add(vendor.strip())

    # Legacy format: products field if present
    product_list = record.get("products") or []
    if isinstance(product_list, list):
        for product in product_list:
            if isinstance(product, str) and product.strip():
                products.add(product.strip())

    # Legacy format: affected_product if present (array of objects)
    affected = record.get("affected_product") or []
    if isinstance(affected, list):
        for item in affected:
            if not isinstance(item, dict):
                continue
            vendor = item.get("vendor")
            product = item.get("product")
            version = item.get("version")
            if isinstance(vendor, str) and vendor.strip():
                vendors.add(vendor.strip())
            if isinstance(product, str) and product.strip():
                products.add(product.strip())
                if isinstance(version, str) and version.strip() and version not in ("*", "-"):
                    versions.add(version.strip())
                    bucket = product_version_map.setdefault(product.strip(), set())
                    bucket.add(version.strip())

    return (
        sorted(vendors),
        sorted(products),
        sorted(versions),
        product_version_map,
    )


def _extract_cpes(record: dict[str, Any]) -> list[str]:
    """Extract CPE URIs from CIRCL record."""
    cpes: list[str] = []
    vulnerable_products = record.get("vulnerable_product") or []
    if isinstance(vulnerable_products, list):
        for cpe in vulnerable_products:
            if isinstance(cpe, str) and cpe.startswith("cpe:"):
                cpes.append(cpe)
    return cpes


def _parse_cpe_uri(cpe: str) -> tuple[str | None, str | None, str | None] | None:
    """
    Parse a CPE URI and extract vendor, product, version.
    CPE format: cpe:2.3:a:vendor:product:version:...
    """
    if not cpe or not isinstance(cpe, str):
        return None

    parts = cpe.split(":")
    if len(parts) < 6:
        return None

    vendor = _clean_cpe_component(parts[3])
    product = _clean_cpe_component(parts[4])
    version = _clean_cpe_component(parts[5])

    return vendor, product, version


def _clean_cpe_component(value: str | None) -> str | None:
    """Clean a CPE component value."""
    if not value:
        return None
    value = value.replace("\\", "").replace("_", " ").strip()
    if value in ("*", "-"):
        return None
    return value
