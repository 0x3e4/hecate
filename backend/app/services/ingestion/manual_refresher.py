from __future__ import annotations

import re
import copy
from collections import Counter
from datetime import UTC, datetime
from typing import Any, Iterable, Tuple

import structlog

from app.core.config import settings
from app.models.vulnerability import ExploitationMetadata, VulnerabilityDocument
from app.repositories.ingestion_log_repository import IngestionLogRepository
from app.repositories.kev_repository import KevRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas.vulnerability import VulnerabilityRefreshStatus
from app.services.asset_catalog_service import AssetCatalogService
from app.services.ingestion.circl_client import CirclClient
from app.services.ingestion.circl_pipeline import _build_impacted_products_from_affected
from app.services.ingestion.euvd_client import EUVDClient
from app.services.ingestion.ghsa_client import GhsaClient
from app.services.ingestion.nvd_client import NVDClient
from app.services.ingestion.osv_client import OsvClient
from app.services.ingestion.normalizer import (
    build_document,
    build_document_from_nvd,
    build_document_from_ghsa,
    build_document_from_osv,
    extract_osv_downstream_references,
    _extract_ghsa_package_info,
    _extract_ghsa_cvss,
    _extract_osv_package_info,
    _extract_osv_cvss,
)
from app.utils.strings import slugify

log = structlog.get_logger()

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
EUVD_PATTERN = re.compile(r"EUVD-\d{4}-\d{4,7}", re.IGNORECASE)
GHSA_PATTERN = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)


class ManualRefresher:
    """
    Fetches individual vulnerabilities from NVD, EUVD, CIRCL, and GHSA on demand.
    Creates reserved placeholders when upstream data is not yet published.
    When NVD is the priority DB, also enriches with CIRCL data for vendor/product/version.
    """

    def __init__(
        self,
        *,
        nvd_client: NVDClient | None = None,
        euvd_client: EUVDClient | None = None,
        circl_client: CirclClient | None = None,
        ghsa_client: GhsaClient | None = None,
    ) -> None:
        self._nvd_client = nvd_client or NVDClient()
        self._euvd_client = euvd_client or EUVDClient()
        self._circl_client = circl_client or CirclClient()
        self._ghsa_client = ghsa_client or GhsaClient()
        self._osv_client = OsvClient()

    async def _resolve_lookup_alias(
        self,
        normalized_identifier: str,
        repository: VulnerabilityRepository,
        preferred_prefixes: tuple[str, ...] = ("GHSA-", "MAL-", "CVE-"),
    ) -> str | None:
        """Look up an existing document by _id and return the best alias for external API lookups."""
        doc = await repository.collection.find_one(
            {"_id": normalized_identifier},
            {"aliases": 1},
        )
        if not doc:
            return None
        aliases = doc.get("aliases")
        if not isinstance(aliases, list):
            return None
        for prefix in preferred_prefixes:
            for alias in aliases:
                if isinstance(alias, str) and alias.upper().startswith(prefix):
                    return alias.strip()
        return None

    async def refresh(
        self,
        identifiers: Iterable[str],
        source: str | None = None,
    ) -> list[VulnerabilityRefreshStatus]:
        prepared = [
            value.strip()
            for value in identifiers
            if isinstance(value, str) and value.strip()
        ]
        if not prepared:
            await self._nvd_client.close()
            await self._euvd_client.close()
            await self._circl_client.close()
            await self._ghsa_client.close()
            return []

        log_repo = await IngestionLogRepository.create()
        started_at = datetime.now(tz=UTC)
        log_id = await log_repo.start_log(
            job_name="manual_refresh",
            started_at=started_at,
            metadata={
                "type": "manual_refresh",
                "label": "Manueller Refresh",
                "requested": prepared,
                "source": source,
            },
        )

        repository = await VulnerabilityRepository.create()
        asset_catalog = await AssetCatalogService.create()
        kev_repository = await KevRepository.create()
        raw_kev_metadata = await kev_repository.load_metadata_map()
        kev_metadata = {key.upper(): value for key, value in raw_kev_metadata.items()}
        statuses: list[VulnerabilityRefreshStatus] = []

        failed = False
        try:
            for original, normalized in self._iterate_identifiers(prepared):
                status = await self._refresh_single(
                    original_identifier=original,
                    normalized_identifier=normalized,
                    repository=repository,
                    asset_catalog=asset_catalog,
                    kev_metadata=kev_metadata,
                    circl_client=self._circl_client,
                    source=source,
                )
                statuses.append(status)
        except Exception as exc:
            failed = True
            finished_at = datetime.now(tz=UTC)
            await log_repo.fail_log(
                log_id,
                started_at=started_at,
                finished_at=finished_at,
                error=str(exc),
            )
            raise
        finally:
            if not failed:
                summary_counts = Counter(status.status for status in statuses)
                finished_at = datetime.now(tz=UTC)
                await log_repo.complete_log(
                    log_id,
                    started_at=started_at,
                    finished_at=finished_at,
                    result={
                        "requested": prepared,
                        "counts": dict(summary_counts),
                        "results": [status.model_dump() for status in statuses],
                    },
                )
            elif statuses:
                summary_counts = Counter(status.status for status in statuses)
                await log_repo.update_progress(
                    log_id,
                    {
                        "requested": prepared,
                        "counts": dict(summary_counts),
                        "results": [status.model_dump() for status in statuses],
                    },
                )
            await self._nvd_client.close()
            await self._euvd_client.close()
            await self._circl_client.close()
            await self._ghsa_client.close()

        return statuses

    async def _refresh_single(
        self,
        *,
        original_identifier: str,
        normalized_identifier: str,
        repository: VulnerabilityRepository,
        asset_catalog: AssetCatalogService,
        kev_metadata: dict[str, tuple[ExploitationMetadata, dict[str, Any] | None]],
        circl_client: CirclClient,
        source: str | None = None,
    ) -> VulnerabilityRefreshStatus:
        upper_normalized = normalized_identifier.upper()
        is_cve = CVE_PATTERN.fullmatch(upper_normalized) is not None
        is_euvd = EUVD_PATTERN.fullmatch(upper_normalized) is not None
        ingested_at = datetime.now(tz=UTC)

        # If a specific source is requested, only fetch from that source
        if source:
            source_upper = source.upper()
            if source_upper == "CIRCL":
                return await self._refresh_from_circl(
                    original_identifier=original_identifier,
                    normalized_identifier=normalized_identifier,
                    repository=repository,
                    asset_catalog=asset_catalog,
                    circl_client=circl_client,
                    is_cve=is_cve,
                )
            elif source_upper == "NVD":
                return await self._refresh_from_nvd(
                    original_identifier=original_identifier,
                    normalized_identifier=normalized_identifier,
                    repository=repository,
                    asset_catalog=asset_catalog,
                    kev_metadata=kev_metadata,
                    is_cve=is_cve,
                    ingested_at=ingested_at,
                )
            elif source_upper == "EUVD":
                return await self._refresh_from_euvd(
                    original_identifier=original_identifier,
                    normalized_identifier=normalized_identifier,
                    repository=repository,
                    asset_catalog=asset_catalog,
                    kev_metadata=kev_metadata,
                    is_cve=is_cve,
                    ingested_at=ingested_at,
                )
            elif source_upper == "GHSA":
                return await self._refresh_from_ghsa(
                    original_identifier=original_identifier,
                    normalized_identifier=normalized_identifier,
                    repository=repository,
                    asset_catalog=asset_catalog,
                    is_cve=is_cve,
                )
            elif source_upper == "OSV":
                return await self._refresh_from_osv(
                    original_identifier=original_identifier,
                    normalized_identifier=normalized_identifier,
                    repository=repository,
                    asset_catalog=asset_catalog,
                    is_cve=is_cve,
                )

        # No specific source requested - use default behavior
        # GHSA IDs are handled directly via the GHSA API
        is_ghsa = GHSA_PATTERN.fullmatch(upper_normalized) is not None
        if is_ghsa:
            return await self._refresh_from_ghsa(
                original_identifier=original_identifier,
                normalized_identifier=normalized_identifier,
                repository=repository,
                asset_catalog=asset_catalog,
                is_cve=is_cve,
            )

        euvd_record = await self._fetch_euvd_record(original_identifier, normalized_identifier)
        canonical_id, source_id = self._resolve_identifiers(
            original_identifier=original_identifier,
            normalized_identifier=normalized_identifier,
            euvd_record=euvd_record,
            is_cve=is_cve,
        )

        nvd_record = None
        nvd_cpe_matches: list[dict[str, Any]] | None = None
        if canonical_id and CVE_PATTERN.fullmatch(canonical_id):
            nvd_record = await self._nvd_client.fetch_cve(canonical_id)
            nvd_cpe_matches = await self._nvd_client.fetch_cpe_matches(canonical_id)

        priority_db = settings.ingestion_priority_vuln_db.upper()
        use_euvd_primary = (
            (priority_db == "EUVD" and euvd_record)
            or (priority_db != "EUVD" and euvd_record and not nvd_record)
        )

        if use_euvd_primary:
            document, product_version_map = build_document(
                cve_id=canonical_id,
                source_id=source_id,
                euvd_record=euvd_record,
                supplemental_record=nvd_record,
                supplemental_cpe_matches=nvd_cpe_matches,
                ingested_at=ingested_at,
            )
            try:
                catalog_result = await asset_catalog.record_assets(
                    vendors=document.vendors,
                    product_versions=product_version_map,
                    cpes=document.cpes,
                    cpe_configurations=document.cpe_configurations,
                )
                if document.vuln_id and "2024-57254" in document.vuln_id:
                    log.debug(
                        "manual_refresher.before_model_copy",
                        vuln_id=document.vuln_id,
                        cpe_configurations_count=len(document.cpe_configurations),
                    )
                document = document.model_copy(
                    update={
                        "vendor_slugs": catalog_result.vendor_slugs,
                        "product_slugs": catalog_result.product_slugs,
                        "product_versions": catalog_result.version_strings or document.product_versions,
                        "product_version_ids": catalog_result.version_ids,
                    }
                )
                if document.vuln_id and "2024-57254" in document.vuln_id:
                    log.debug(
                        "manual_refresher.after_model_copy",
                        vuln_id=document.vuln_id,
                        cpe_configurations_count=len(document.cpe_configurations),
                    )
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "manual_refresher.asset_catalog_update_failed",
                    vuln_id=document.vuln_id,
                    error=str(exc),
                )
            metadata_tuple = None
            if document.vuln_id:
                metadata_tuple = kev_metadata.get(document.vuln_id.upper())
            if metadata_tuple:
                metadata_model, raw_entry = metadata_tuple
                updates: dict[str, Any] = {
                    "exploited": True,
                    "exploitation": metadata_model,
                }
                raw_payload = copy.deepcopy(document.raw) if isinstance(document.raw, dict) else {}
                if raw_entry:
                    raw_payload["kev"] = raw_entry
                updates["raw"] = raw_payload
                document = document.model_copy(update=updates)

            change_context = {
                "job_name": "manual_refresh",
                "job_label": "Manual Refresh",
                "metadata": {
                    "trigger": "manual",
                    "provider": "EUVD",
                    "identifier": original_identifier,
                    "resolved_vuln_id": document.vuln_id,
                    "resolved_source_id": document.source_id,
                },
            }
            upsert_result = await repository.upsert(
                document,
                change_context=change_context,
                euvd_raw=euvd_record,
                nvd_raw=nvd_record,
            )
            message = None
            if document.published is None:
                message = "EUVD record ingested without published date; marked as reserved."

            # Enrich with GHSA data (package/version info)
            ghsa_enriched = False
            if canonical_id and CVE_PATTERN.fullmatch(canonical_id):
                ghsa_enriched = await self._enrich_with_ghsa(
                    cve_id=canonical_id,
                    repository=repository,
                    asset_catalog=asset_catalog,
                )
            if ghsa_enriched:
                message = (message + " " if message else "") + "Enriched with GHSA data."

            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="EUVD",
                status="inserted" if upsert_result.inserted else "updated",
                message=message,
                changed_fields=upsert_result.changed_fields,
            )

        if nvd_record:
            built = build_document_from_nvd(nvd_record, ingested_at=ingested_at, cpe_matches=nvd_cpe_matches)
            if built:
                document, product_version_map = built
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
                    log.warning(
                        "manual_refresher.asset_catalog_update_failed",
                        vuln_id=document.vuln_id,
                        error=str(exc),
                    )
                metadata_tuple = None
                if document.vuln_id:
                    metadata_tuple = kev_metadata.get(document.vuln_id.upper())
                if metadata_tuple:
                    metadata_model, raw_entry = metadata_tuple
                    updates: dict[str, Any] = {
                        "exploited": True,
                        "exploitation": metadata_model,
                    }
                    raw_payload = copy.deepcopy(document.raw) if isinstance(document.raw, dict) else {}
                    if raw_entry:
                        raw_payload["kev"] = raw_entry
                    updates["raw"] = raw_payload
                    document = document.model_copy(update=updates)

                change_context = {
                    "job_name": "manual_refresh",
                    "job_label": "Manual Refresh",
                    "metadata": {
                        "trigger": "manual",
                        "provider": "NVD",
                        "identifier": original_identifier,
                        "resolved_vuln_id": document.vuln_id,
                        "resolved_source_id": document.source_id,
                    },
                }
                upsert_result = await repository.upsert_from_nvd(
                    document,
                    nvd_raw=nvd_record,
                    change_context=change_context,
                )

                # Enrich with CIRCL data if vendors/products/versions are missing
                # or if impactedProducts lacks version range info
                circl_enriched = False
                if document.vuln_id and CVE_PATTERN.fullmatch(document.vuln_id):
                    impacted_has_ranges = any(
                        any(
                            v for v in p.get("versions", [])
                            if "<" in v or ">" in v
                        )
                        for p in (document.impacted_products or [])
                    )
                    needs_enrichment = (
                        not document.vendors
                        or not document.products
                        or not document.product_versions
                        or not impacted_has_ranges
                    )
                    if needs_enrichment:
                        circl_enriched = await self._enrich_with_circl(
                            cve_id=document.vuln_id,
                            circl_client=circl_client,
                            repository=repository,
                            asset_catalog=asset_catalog,
                        )

                # Enrich with GHSA data (package/version info)
                ghsa_enriched = False
                if document.vuln_id and CVE_PATTERN.fullmatch(document.vuln_id):
                    ghsa_enriched = await self._enrich_with_ghsa(
                        cve_id=document.vuln_id,
                        repository=repository,
                        asset_catalog=asset_catalog,
                    )

                message = None
                if document.published is None:
                    message = "NVD record missing published date; stored as reserved."
                if circl_enriched:
                    message = (message + " " if message else "") + "Enriched with CIRCL data."
                if ghsa_enriched:
                    message = (message + " " if message else "") + "Enriched with GHSA data."
                return VulnerabilityRefreshStatus(
                    identifier=original_identifier,
                    provider="NVD",
                    status="inserted" if upsert_result.inserted else "updated",
                    message=message,
                    changed_fields=upsert_result.changed_fields,
                )

        placeholder = self._build_reserved_document(
            canonical_id or normalized_identifier,
            source_id=source_id,
            original_identifier=original_identifier,
            ingested_at=ingested_at,
        )
        change_context = {
            "job_name": "manual_refresh",
            "job_label": "Manual Refresh",
            "metadata": {
                "trigger": "manual",
                "provider": "placeholder",
                "identifier": original_identifier,
                "resolved_vuln_id": placeholder.vuln_id,
                "resolved_source_id": placeholder.source_id,
            },
        }
        upsert_result = await repository.upsert(placeholder, change_context=change_context)
        return VulnerabilityRefreshStatus(
            identifier=original_identifier,
            provider="placeholder",
            status="inserted" if upsert_result.inserted else "updated",
            message="No upstream data available; stored as reserved placeholder.",
            changed_fields=upsert_result.changed_fields,
        )

    async def _refresh_from_nvd(
        self,
        *,
        original_identifier: str,
        normalized_identifier: str,
        repository: VulnerabilityRepository,
        asset_catalog: AssetCatalogService,
        kev_metadata: dict[str, tuple[ExploitationMetadata, dict[str, Any] | None]],
        is_cve: bool,
        ingested_at: datetime,
    ) -> VulnerabilityRefreshStatus:
        """Refresh vulnerability data from NVD only."""
        upper_normalized = normalized_identifier.upper()
        canonical_id = upper_normalized if is_cve else None

        if not canonical_id or not CVE_PATTERN.fullmatch(canonical_id):
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="NVD",
                status="error",
                message="NVD requires a valid CVE identifier.",
            )

        nvd_record = await self._nvd_client.fetch_cve(canonical_id)
        nvd_cpe_matches = await self._nvd_client.fetch_cpe_matches(canonical_id)

        if not nvd_record:
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="NVD",
                status="skipped",
                message="No data found in NVD.",
            )

        built = build_document_from_nvd(nvd_record, ingested_at=ingested_at, cpe_matches=nvd_cpe_matches)
        if not built:
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="NVD",
                status="error",
                message="Failed to build document from NVD data.",
            )

        document, product_version_map = built
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
            log.warning("manual_refresher.asset_catalog_update_failed", vuln_id=document.vuln_id, error=str(exc))

        # Add KEV metadata if available
        if document.vuln_id:
            metadata_tuple = kev_metadata.get(document.vuln_id.upper())
            if metadata_tuple:
                metadata_model, raw_entry = metadata_tuple
                updates: dict[str, Any] = {"exploited": True, "exploitation": metadata_model}
                raw_payload = copy.deepcopy(document.raw) if isinstance(document.raw, dict) else {}
                if raw_entry:
                    raw_payload["kev"] = raw_entry
                updates["raw"] = raw_payload
                document = document.model_copy(update=updates)

        change_context = {
            "job_name": "manual_refresh",
            "job_label": "Manual Refresh",
            "metadata": {"trigger": "manual", "provider": "NVD", "identifier": original_identifier},
        }
        upsert_result = await repository.upsert_from_nvd(document, nvd_raw=nvd_record, change_context=change_context)

        return VulnerabilityRefreshStatus(
            identifier=original_identifier,
            provider="NVD",
            status="inserted" if upsert_result.inserted else "updated",
            changed_fields=upsert_result.changed_fields,
        )

    async def _refresh_from_euvd(
        self,
        *,
        original_identifier: str,
        normalized_identifier: str,
        repository: VulnerabilityRepository,
        asset_catalog: AssetCatalogService,
        kev_metadata: dict[str, tuple[ExploitationMetadata, dict[str, Any] | None]],
        is_cve: bool,
        ingested_at: datetime,
    ) -> VulnerabilityRefreshStatus:
        """Refresh vulnerability data from EUVD only."""
        euvd_record = await self._fetch_euvd_record(original_identifier, normalized_identifier)

        if not euvd_record:
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="EUVD",
                status="skipped",
                message="No data found in EUVD.",
            )

        canonical_id, source_id = self._resolve_identifiers(
            original_identifier=original_identifier,
            normalized_identifier=normalized_identifier,
            euvd_record=euvd_record,
            is_cve=is_cve,
        )

        document, product_version_map = build_document(
            cve_id=canonical_id,
            source_id=source_id,
            euvd_record=euvd_record,
            supplemental_record=None,
            supplemental_cpe_matches=None,
            ingested_at=ingested_at,
        )

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
            log.warning("manual_refresher.asset_catalog_update_failed", vuln_id=document.vuln_id, error=str(exc))

        # Add KEV metadata if available
        if document.vuln_id:
            metadata_tuple = kev_metadata.get(document.vuln_id.upper())
            if metadata_tuple:
                metadata_model, raw_entry = metadata_tuple
                updates: dict[str, Any] = {"exploited": True, "exploitation": metadata_model}
                raw_payload = copy.deepcopy(document.raw) if isinstance(document.raw, dict) else {}
                if raw_entry:
                    raw_payload["kev"] = raw_entry
                updates["raw"] = raw_payload
                document = document.model_copy(update=updates)

        change_context = {
            "job_name": "manual_refresh",
            "job_label": "Manual Refresh",
            "metadata": {"trigger": "manual", "provider": "EUVD", "identifier": original_identifier},
        }
        upsert_result = await repository.upsert(document, change_context=change_context, euvd_raw=euvd_record)

        return VulnerabilityRefreshStatus(
            identifier=original_identifier,
            provider="EUVD",
            status="inserted" if upsert_result.inserted else "updated",
            changed_fields=upsert_result.changed_fields,
        )

    async def _refresh_from_ghsa(
        self,
        *,
        original_identifier: str,
        normalized_identifier: str,
        repository: VulnerabilityRepository,
        asset_catalog: AssetCatalogService,
        is_cve: bool,
    ) -> VulnerabilityRefreshStatus:
        """Refresh vulnerability data from GitHub Security Advisories."""
        upper_normalized = normalized_identifier.upper()
        is_ghsa = GHSA_PATTERN.fullmatch(upper_normalized) is not None

        # Fetch advisory - by GHSA ID directly or by CVE ID
        advisory = None
        if is_ghsa:
            advisory = await self._ghsa_client.fetch_advisory_by_id(upper_normalized)
        elif is_cve:
            advisory = await self._ghsa_client.fetch_advisory_by_cve(upper_normalized)
        elif EUVD_PATTERN.fullmatch(upper_normalized):
            # EUVD IDs are not recognized by GHSA API; resolve via stored aliases
            resolved = await self._resolve_lookup_alias(
                normalized_identifier, repository, preferred_prefixes=("GHSA-", "CVE-"),
            )
            if resolved:
                resolved_upper = resolved.upper()
                if GHSA_PATTERN.fullmatch(resolved_upper):
                    advisory = await self._ghsa_client.fetch_advisory_by_id(resolved_upper)
                elif CVE_PATTERN.fullmatch(resolved_upper):
                    advisory = await self._ghsa_client.fetch_advisory_by_cve(resolved_upper)

        # When enriching an EUVD document, keep its _id as vuln_id target
        euvd_target_id = normalized_identifier if EUVD_PATTERN.fullmatch(upper_normalized) else None

        if not advisory:
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="GHSA",
                status="skipped",
                message="No advisory found in GitHub Security Advisories.",
            )

        ghsa_id = advisory.get("ghsa_id")
        if not isinstance(ghsa_id, str) or not ghsa_id.strip():
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="GHSA",
                status="skipped",
                message="Advisory has no GHSA ID.",
            )
        ghsa_id = ghsa_id.strip().upper()

        cve_id = advisory.get("cve_id")
        has_cve = isinstance(cve_id, str) and cve_id.strip()
        if euvd_target_id:
            vuln_id = euvd_target_id
        elif has_cve:
            vuln_id = cve_id
        else:
            vuln_id = ghsa_id

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

        # Extract aliases (case-insensitive dedup)
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
        catalog_result = None
        try:
            catalog_result = await asset_catalog.record_assets(
                vendors=vendors,
                product_versions=product_version_map,
                cpes=[],
                cpe_configurations=None,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("manual_refresher.ghsa_asset_catalog_failed", ghsa_id=ghsa_id, error=str(exc))

        change_context = {
            "job_name": "manual_refresh",
            "job_label": "Manual Refresh",
            "metadata": {"trigger": "manual", "provider": "GHSA", "identifier": original_identifier},
        }

        # Build document as fallback for creation mode.
        # For CVE-linked advisories, serves as fallback when CVE doesn't exist yet in MongoDB.
        build_result = build_document_from_ghsa(advisory, ingested_at=datetime.now(tz=UTC))
        document = build_result[0] if build_result is not None else None

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

        resolved = vuln_id if vuln_id != original_identifier.upper() else None

        if result == "inserted":
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="GHSA",
                status="inserted",
                message="Created from GHSA advisory.",
                resolved_id=resolved,
            )
        elif result == "updated":
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="GHSA",
                status="updated",
                message="Enriched with GHSA data.",
                resolved_id=resolved,
            )
        return VulnerabilityRefreshStatus(
            identifier=original_identifier,
            provider="GHSA",
            status="skipped",
            message="No new data from GHSA.",
        )

    async def _refresh_from_circl(
        self,
        *,
        original_identifier: str,
        normalized_identifier: str,
        repository: VulnerabilityRepository,
        asset_catalog: AssetCatalogService,
        circl_client: CirclClient,
        is_cve: bool,
    ) -> VulnerabilityRefreshStatus:
        """Refresh vulnerability data from CIRCL only (enrichment for existing records)."""
        upper_normalized = normalized_identifier.upper()
        canonical_id = upper_normalized if is_cve else None

        if not canonical_id or not CVE_PATTERN.fullmatch(canonical_id):
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="CIRCL",
                status="error",
                message="CIRCL requires a valid CVE identifier.",
            )

        circl_record = await circl_client.fetch_cve(canonical_id)
        if not circl_record:
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="CIRCL",
                status="skipped",
                message="No data found in CIRCL.",
            )

        vendors, products, versions, product_version_map, cpes = _extract_circl_product_info(circl_record)

        if not vendors and not products and not versions:
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="CIRCL",
                status="skipped",
                message="CIRCL record has no vendor/product/version data.",
            )

        catalog_result = None
        try:
            catalog_result = await asset_catalog.record_assets(
                vendors=vendors,
                product_versions=product_version_map,
                cpes=cpes,
                cpe_configurations=None,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("manual_refresher.circl_asset_catalog_failed", cve_id=canonical_id, error=str(exc))

        change_context = {
            "job_name": "manual_refresh",
            "job_label": "Manual Refresh",
            "metadata": {"trigger": "manual", "provider": "CIRCL", "identifier": original_identifier},
        }

        impacted_products = _build_impacted_products_from_affected(circl_record)

        result = await repository.upsert_from_circl(
            cve_id=canonical_id,
            vendors=vendors,
            products=products,
            product_versions=versions,
            vendor_slugs=catalog_result.vendor_slugs if catalog_result else [],
            product_slugs=catalog_result.product_slugs if catalog_result else [],
            product_version_ids=catalog_result.version_ids if catalog_result else [],
            cpes=cpes,
            impacted_products=impacted_products,
            circl_raw=circl_record,
            change_context=change_context,
        )

        if result == "not_found":
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="CIRCL",
                status="skipped",
                message="Vulnerability not found in database. CIRCL can only enrich existing records.",
            )
        elif result == "unchanged":
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="CIRCL",
                status="skipped",
                message="No new data from CIRCL (fields already populated).",
            )

        return VulnerabilityRefreshStatus(
            identifier=original_identifier,
            provider="CIRCL",
            status="updated",
            message="Enriched with CIRCL data.",
        )

    async def _refresh_from_osv(
        self,
        *,
        original_identifier: str,
        normalized_identifier: str,
        repository: VulnerabilityRepository,
        asset_catalog: AssetCatalogService,
        is_cve: bool,
    ) -> VulnerabilityRefreshStatus:
        """Refresh vulnerability data from OSV.dev (supports CVE, GHSA, MAL, PYSEC IDs)."""
        # EUVD IDs are not known to OSV; resolve via stored aliases
        lookup_id = normalized_identifier
        euvd_target_id: str | None = None
        if EUVD_PATTERN.fullmatch(normalized_identifier.upper()):
            resolved = await self._resolve_lookup_alias(
                normalized_identifier, repository, preferred_prefixes=("GHSA-", "MAL-", "CVE-"),
            )
            if resolved:
                lookup_id = resolved
                # Remember the EUVD doc ID so the upsert enriches the correct document
                euvd_target_id = normalized_identifier

        # OSV API is case-sensitive for GHSA IDs (requires lowercase)
        if lookup_id.upper().startswith("GHSA-"):
            lookup_id = lookup_id.lower()

        record = await self._osv_client.fetch_vulnerability(lookup_id)

        if not record:
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="OSV",
                status="skipped",
                message="No record found in OSV.dev.",
            )

        osv_id = record.get("id")
        if not isinstance(osv_id, str) or not osv_id.strip():
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="OSV",
                status="skipped",
                message="OSV record has no ID.",
            )
        raw_osv_id = osv_id.strip()

        # Normalize for lookup
        _UPPER_PREFIXES = ("GHSA-", "MAL-", "PYSEC-")
        osv_id_normalized = raw_osv_id.upper() if raw_osv_id.upper().startswith(_UPPER_PREFIXES) else raw_osv_id

        # Determine vuln_id from aliases (prefer CVE > GHSA > OSV ID)
        cve_alias: str | None = None
        ghsa_alias: str | None = None
        aliases_raw = record.get("aliases") or []
        if isinstance(aliases_raw, list):
            for alias in aliases_raw:
                if not isinstance(alias, str) or not alias.strip():
                    continue
                upper = alias.strip().upper()
                if upper.startswith("CVE-") and cve_alias is None:
                    cve_alias = upper
                elif upper.startswith("GHSA-") and ghsa_alias is None:
                    ghsa_alias = upper

        has_cve = cve_alias is not None
        if euvd_target_id:
            # Enriching an existing EUVD document — keep its _id as vuln_id
            vuln_id = euvd_target_id
        elif has_cve:
            vuln_id = cve_alias
        elif ghsa_alias:
            vuln_id = ghsa_alias
        else:
            vuln_id = osv_id_normalized

        # Extract data
        vendors, products, product_versions, product_version_map, impacted_products = _extract_osv_package_info(record)
        cvss, cvss_metrics = _extract_osv_cvss(record)

        # References
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

        # CWEs
        cwes: list[str] = []
        db_specific = record.get("database_specific") or {}
        cwe_ids = db_specific.get("cwe_ids") or []
        if isinstance(cwe_ids, list):
            for cwe_id in cwe_ids:
                if isinstance(cwe_id, str) and cwe_id.strip():
                    cwes.append(cwe_id.strip())

        # Aliases
        aliases: list[str] = [osv_id_normalized]
        seen_upper: set[str] = {osv_id_normalized.upper()}
        if has_cve and cve_alias.upper() not in seen_upper:
            aliases.append(cve_alias)
            seen_upper.add(cve_alias.upper())
        if ghsa_alias and ghsa_alias.upper() not in seen_upper:
            aliases.append(ghsa_alias)
            seen_upper.add(ghsa_alias.upper())
        if isinstance(aliases_raw, list):
            for alias in aliases_raw:
                if isinstance(alias, str) and alias.strip():
                    normed = alias.strip().upper() if alias.strip().upper().startswith(_UPPER_PREFIXES + ("CVE-",)) else alias.strip()
                    if normed.upper() not in seen_upper:
                        seen_upper.add(normed.upper())
                        aliases.append(normed)

        # Record assets
        catalog_result = None
        try:
            catalog_result = await asset_catalog.record_assets(
                vendors=vendors,
                product_versions=product_version_map,
                cpes=[],
                cpe_configurations=None,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("manual_refresher.osv_asset_catalog_failed", osv_id=raw_osv_id, error=str(exc))

        change_context = {
            "job_name": "manual_refresh",
            "job_label": "Manual Refresh",
            "metadata": {"trigger": "manual", "provider": "OSV", "identifier": original_identifier},
        }

        build_result = build_document_from_osv(record, ingested_at=datetime.now(tz=UTC))
        document = build_result[0] if build_result is not None else None

        result = await repository.upsert_from_osv(
            vuln_id=vuln_id,
            osv_id=osv_id_normalized,
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

        resolved = vuln_id if vuln_id != original_identifier.upper() else None

        if result == "inserted":
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="OSV",
                status="inserted",
                message="Created from OSV record.",
                resolved_id=resolved,
            )
        elif result == "updated":
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="OSV",
                status="updated",
                message="Enriched with OSV data.",
                resolved_id=resolved,
            )
        return VulnerabilityRefreshStatus(
            identifier=original_identifier,
            provider="OSV",
            status="skipped",
            message="No new data from OSV.",
        )

    async def _enrich_with_circl(
        self,
        *,
        cve_id: str,
        circl_client: CirclClient,
        repository: VulnerabilityRepository,
        asset_catalog: AssetCatalogService,
    ) -> bool:
        """
        Enrich a vulnerability with CIRCL data for vendor/product/version.
        Returns True if enrichment was successful, False otherwise.
        """
        try:
            circl_record = await circl_client.fetch_cve(cve_id)
            if not circl_record:
                return False

            # Extract vendor/product/version from CIRCL
            vendors, products, versions, product_version_map, cpes = _extract_circl_product_info(circl_record)

            if not vendors and not products and not versions:
                return False

            # Update asset catalog
            catalog_result = None
            try:
                catalog_result = await asset_catalog.record_assets(
                    vendors=vendors,
                    product_versions=product_version_map,
                    cpes=cpes,
                    cpe_configurations=None,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "manual_refresher.circl_asset_catalog_failed",
                    cve_id=cve_id,
                    error=str(exc),
                )

            # Update the vulnerability
            change_context = {
                "job_name": "manual_refresh",
                "job_label": "Manual Refresh",
                "metadata": {
                    "trigger": "manual",
                    "provider": "CIRCL",
                },
            }

            impacted_products = _build_impacted_products_from_affected(circl_record)

            result = await repository.upsert_from_circl(
                cve_id=cve_id,
                vendors=vendors,
                products=products,
                product_versions=versions,
                vendor_slugs=catalog_result.vendor_slugs if catalog_result else [],
                product_slugs=catalog_result.product_slugs if catalog_result else [],
                product_version_ids=catalog_result.version_ids if catalog_result else [],
                cpes=cpes,
                impacted_products=impacted_products,
                circl_raw=circl_record,
                change_context=change_context,
            )

            return result == "updated"

        except Exception as exc:  # noqa: BLE001
            log.warning(
                "manual_refresher.circl_enrichment_failed",
                cve_id=cve_id,
                error=str(exc),
            )
            return False

    async def _enrich_with_ghsa(
        self,
        *,
        cve_id: str,
        repository: VulnerabilityRepository,
        asset_catalog: AssetCatalogService,
    ) -> bool:
        """
        Enrich a vulnerability with GHSA data for package/version info.
        Returns True if enrichment was successful, False otherwise.
        """
        try:
            advisory = await self._ghsa_client.fetch_advisory_by_cve(cve_id)
            if not advisory:
                return False

            ghsa_id = advisory.get("ghsa_id")
            if not isinstance(ghsa_id, str) or not ghsa_id.strip():
                return False
            ghsa_id = ghsa_id.strip().upper()

            cve_from_advisory = advisory.get("cve_id")
            has_cve = isinstance(cve_from_advisory, str) and cve_from_advisory.strip()
            vuln_id = cve_from_advisory if has_cve else ghsa_id

            vendors, products, product_versions, product_version_map, impacted_products = _extract_ghsa_package_info(advisory)
            cvss, cvss_metrics = _extract_ghsa_cvss(advisory)

            references: list[str] = []
            refs_raw = advisory.get("references") or []
            if isinstance(refs_raw, list):
                for ref in refs_raw:
                    if isinstance(ref, str):
                        references.append(ref)

            cwes: list[str] = []
            cwes_raw = advisory.get("cwes") or []
            if isinstance(cwes_raw, list):
                for cwe in cwes_raw:
                    if isinstance(cwe, dict):
                        cwe_id = cwe.get("cwe_id")
                        if isinstance(cwe_id, str) and cwe_id.strip():
                            cwes.append(cwe_id.strip())

            aliases: list[str] = [ghsa_id]
            seen_upper: set[str] = {ghsa_id.upper()}
            if has_cve:
                aliases.append(cve_from_advisory)
                seen_upper.add(cve_from_advisory.upper())
            identifiers = advisory.get("identifiers") or []
            if isinstance(identifiers, list):
                for ident in identifiers:
                    if isinstance(ident, dict):
                        val = ident.get("value")
                        if isinstance(val, str) and val.strip() and val.strip().upper() not in seen_upper:
                            seen_upper.add(val.strip().upper())
                            aliases.append(val.strip())

            catalog_result = None
            try:
                catalog_result = await asset_catalog.record_assets(
                    vendors=vendors,
                    product_versions=product_version_map,
                    cpes=[],
                    cpe_configurations=None,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("manual_refresher.ghsa_enrichment_asset_catalog_failed", cve_id=cve_id, error=str(exc))

            change_context = {
                "job_name": "manual_refresh",
                "job_label": "Manual Refresh",
                "metadata": {"trigger": "manual", "provider": "GHSA"},
            }

            # Build document as fallback in case vuln doesn't exist yet
            build_result = build_document_from_ghsa(advisory, ingested_at=datetime.now(tz=UTC))
            document = build_result[0] if build_result is not None else None

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

            return result == "updated"

        except Exception as exc:  # noqa: BLE001
            log.warning(
                "manual_refresher.ghsa_enrichment_failed",
                cve_id=cve_id,
                error=str(exc),
            )
            return False

    async def _fetch_euvd_record(self, original_identifier: str, normalized_identifier: str) -> dict | None:
        record = await self._euvd_client.fetch_single(normalized_identifier)
        if record:
            return record
        if normalized_identifier != original_identifier:
            return await self._euvd_client.fetch_single(original_identifier)
        return None

    @staticmethod
    def _resolve_identifiers(
        *,
        original_identifier: str,
        normalized_identifier: str,
        euvd_record: dict | None,
        is_cve: bool,
    ) -> Tuple[str, str | None]:
        source_id: str | None = None
        cve_id: str | None = normalized_identifier.upper() if is_cve else None

        if euvd_record:
            source_candidates = [
                euvd_record.get("id"),
                euvd_record.get("euvdId"),
                euvd_record.get("sourceId"),
                euvd_record.get("enisaUuid"),
                euvd_record.get("uuid"),
            ]
            source_id = next(
                (value.strip() for value in source_candidates if isinstance(value, str) and value.strip()),
                None,
            )

            if not cve_id:
                cve_candidates = [
                    euvd_record.get("cveNumber"),
                    euvd_record.get("cve"),
                    euvd_record.get("cveId"),
                    euvd_record.get("cve_id"),
                ]
                cve_id = next(
                    (value.strip().upper() for value in cve_candidates if isinstance(value, str) and value.strip()),
                    None,
                )
            if not cve_id:
                cve_alias = ManualRefresher._extract_cve_from_aliases(
                    euvd_record.get("aliases")
                    or euvd_record.get("alias")
                    or euvd_record.get("references")
                )
                if cve_alias:
                    cve_id = cve_alias

        canonical = cve_id or source_id or normalized_identifier or original_identifier
        return canonical, source_id

    @staticmethod
    def _extract_cve_from_aliases(source: object) -> str | None:
        if source is None:
            return None
        candidates: list[str] = []
        if isinstance(source, str):
            candidates = [source]
        elif isinstance(source, list):
            candidates = [str(value) for value in source]
        elif isinstance(source, dict):
            candidates = [str(value) for value in source.values()]
        for candidate in candidates:
            match = CVE_PATTERN.search(candidate)
            if match:
                return match.group(0).upper()
        return None

    @staticmethod
    def _build_reserved_document(
        canonical_identifier: str,
        *,
        source_id: str | None,
        original_identifier: str,
        ingested_at: datetime,
    ) -> VulnerabilityDocument:
        is_cve = CVE_PATTERN.fullmatch(canonical_identifier) is not None
        title = canonical_identifier
        summary = (
            "This identifier is reserved. Details will be provided once the vulnerability is published."
        )
        aliases: list[str] = []
        if original_identifier != canonical_identifier:
            aliases.append(original_identifier)
        return VulnerabilityDocument(
            vuln_id=canonical_identifier,
            source_id=source_id if source_id and source_id != canonical_identifier else None,
            source="NVD" if is_cve else "EUVD",
            title=title,
            summary=summary,
            aliases=aliases,
            published=None,
            modified=None,
            ingested_at=ingested_at.astimezone(UTC),
            raw={"reserved": True, "requested": original_identifier},
        )

    @staticmethod
    def _iterate_identifiers(identifiers: Iterable[str]) -> Iterable[Tuple[str, str]]:
        for identifier in identifiers:
            normalized = (identifier or "").strip()
            if not normalized:
                continue
            upper = normalized.upper()
            if CVE_PATTERN.fullmatch(upper):
                yield identifier, upper
            elif EUVD_PATTERN.fullmatch(upper):
                yield identifier, upper
            else:
                yield identifier, normalized


def _extract_circl_product_info(
    record: dict[str, Any],
) -> tuple[list[str], list[str], list[str], dict[str, set[str]], list[str]]:
    """
    Extract vendor, product, and version information from a CIRCL record.
    Supports both CVE 5.x format (containers.cna.affected) and legacy format.
    Returns: (vendors, products, versions, product_version_map, cpes)
    """
    vendors: set[str] = set()
    products: set[str] = set()
    versions: set[str] = set()
    product_version_map: dict[str, set[str]] = {}
    cpes: set[str] = set()

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
            vendor_name = vendor.strip() if isinstance(vendor, str) and vendor.strip() else None
            product_name = product.strip() if isinstance(product, str) and product.strip() else None

            if vendor_name:
                vendors.add(vendor_name)
            if product_name:
                products.add(product_name)

                # Extract versions from versions array (CVE 5.x format)
                versions_list = item.get("versions") or []
                if isinstance(versions_list, list):
                    for ver_item in versions_list:
                        if isinstance(ver_item, dict):
                            status = ver_item.get("status", "affected")
                            if status == "unaffected":
                                continue

                            # Collect all concrete version strings for search/filtering
                            for field in ("version", "lessThan", "lessThanOrEqual"):
                                val = ver_item.get(field)
                                if isinstance(val, str) and val.strip() and val.strip() not in ("*", "-", "unspecified"):
                                    ver_str = val.strip()
                                    versions.add(ver_str)
                                    bucket = product_version_map.setdefault(product_name, set())
                                    bucket.add(ver_str)

                            # Also extract version strings from changes array
                            changes = ver_item.get("changes")
                            if isinstance(changes, list):
                                for change in changes:
                                    if isinstance(change, dict):
                                        at_ver = change.get("at")
                                        if isinstance(at_ver, str) and at_ver.strip() and at_ver.strip() not in ("*", "-", "unspecified"):
                                            versions.add(at_ver.strip())
                                            bucket = product_version_map.setdefault(product_name, set())
                                            bucket.add(at_ver.strip())

                            # Build CPE from affected data
                            version = ver_item.get("version")
                            if vendor_name and isinstance(version, str) and version.strip() and version not in ("*", "-"):
                                cpe = _build_circl_cpe(vendor_name, product_name, version.strip())
                                if cpe:
                                    cpes.add(cpe)

    # Legacy format: vulnerable_product field (CPE URIs)
    vulnerable_products = record.get("vulnerable_product") or []
    if isinstance(vulnerable_products, list):
        for cpe in vulnerable_products:
            if not isinstance(cpe, str):
                continue
            if cpe.startswith("cpe:"):
                cpes.add(cpe)
            parsed = _parse_circl_cpe_uri(cpe)
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
        sorted(cpes),
    )


def _build_circl_cpe(vendor: str, product: str, version: str) -> str | None:
    """Build a CPE 2.3 URI from vendor, product, and version."""
    if not vendor or not product:
        return None
    # Normalize for CPE format (lowercase, replace spaces with underscores)
    v = vendor.lower().replace(" ", "_").replace(":", "\\:")
    p = product.lower().replace(" ", "_").replace(":", "\\:")
    ver = version.replace(" ", "_").replace(":", "\\:") if version else "*"
    return f"cpe:2.3:a:{v}:{p}:{ver}:*:*:*:*:*:*:*"


def _parse_circl_cpe_uri(cpe: str) -> tuple[str | None, str | None, str | None] | None:
    """
    Parse a CPE URI and extract vendor, product, version.
    CPE format: cpe:2.3:a:vendor:product:version:...
    """
    if not cpe or not isinstance(cpe, str):
        return None

    parts = cpe.split(":")
    if len(parts) < 6:
        return None

    vendor = _clean_circl_cpe_component(parts[3])
    product = _clean_circl_cpe_component(parts[4])
    version = _clean_circl_cpe_component(parts[5])

    return vendor, product, version


def _clean_circl_cpe_component(value: str | None) -> str | None:
    """Clean a CPE component value."""
    if not value:
        return None
    value = value.replace("\\", "").replace("_", " ").strip()
    if value in ("*", "-"):
        return None
    return value
