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
from app.services.ingestion.euvd_client import EUVDClient
from app.services.ingestion.nvd_client import NVDClient
from app.services.ingestion.normalizer import build_document, build_document_from_nvd

log = structlog.get_logger()

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
EUVD_PATTERN = re.compile(r"EUVD-\d{4}-\d{4,7}", re.IGNORECASE)


class ManualRefresher:
    """
    Fetches individual vulnerabilities from NVD, EUVD, and CIRCL on demand.
    Creates reserved placeholders when upstream data is not yet published.
    When NVD is the priority DB, also enriches with CIRCL data for vendor/product/version.
    """

    def __init__(
        self,
        *,
        nvd_client: NVDClient | None = None,
        euvd_client: EUVDClient | None = None,
        circl_client: CirclClient | None = None,
    ) -> None:
        self._nvd_client = nvd_client or NVDClient()
        self._euvd_client = euvd_client or EUVDClient()
        self._circl_client = circl_client or CirclClient()

    async def refresh(self, identifiers: Iterable[str]) -> list[VulnerabilityRefreshStatus]:
        prepared = [
            value.strip()
            for value in identifiers
            if isinstance(value, str) and value.strip()
        ]
        if not prepared:
            await self._nvd_client.close()
            await self._euvd_client.close()
            await self._circl_client.close()
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
    ) -> VulnerabilityRefreshStatus:
        upper_normalized = normalized_identifier.upper()
        is_cve = CVE_PATTERN.fullmatch(upper_normalized) is not None
        is_euvd = EUVD_PATTERN.fullmatch(upper_normalized) is not None
        ingested_at = datetime.now(tz=UTC)

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
                circl_enriched = False
                if document.vuln_id and CVE_PATTERN.fullmatch(document.vuln_id):
                    needs_enrichment = (
                        not document.vendors
                        or not document.products
                        or not document.product_versions
                    )
                    if needs_enrichment:
                        circl_enriched = await self._enrich_with_circl(
                            cve_id=document.vuln_id,
                            circl_client=circl_client,
                            repository=repository,
                            asset_catalog=asset_catalog,
                        )

                message = None
                if document.published is None:
                    message = "NVD record missing published date; stored as reserved."
                if circl_enriched:
                    message = (message + " " if message else "") + "Enriched with CIRCL data."
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
            vendors, products, versions, product_version_map, cpes, impacted_products = _extract_circl_product_info(circl_record)

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
) -> tuple[list[str], list[str], list[str], dict[str, set[str]], list[str], list[dict[str, Any]]]:
    """
    Extract vendor, product, and version information from a CIRCL record.
    Supports both CVE 5.x format (containers.cna.affected) and legacy format.
    Returns: (vendors, products, versions, product_version_map, cpes, impacted_products)
    """
    vendors: set[str] = set()
    products: set[str] = set()
    versions: set[str] = set()
    product_version_map: dict[str, set[str]] = {}
    cpes: set[str] = set()
    impacted_products: list[dict[str, Any]] = []

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

                # Extract versions from versions array
                item_versions: list[str] = []
                versions_list = item.get("versions") or []
                if isinstance(versions_list, list):
                    for ver_item in versions_list:
                        if isinstance(ver_item, dict):
                            version = ver_item.get("version")
                            if isinstance(version, str) and version.strip() and version not in ("*", "-"):
                                ver_str = version.strip()
                                versions.add(ver_str)
                                item_versions.append(ver_str)
                                bucket = product_version_map.setdefault(product_name, set())
                                bucket.add(ver_str)

                                # Build CPE from affected data
                                if vendor_name:
                                    cpe = _build_circl_cpe(vendor_name, product_name, ver_str)
                                    if cpe:
                                        cpes.add(cpe)

                # Build impacted_product entry if we have vendor and product
                if vendor_name and product_name:
                    impacted_product = {
                        "vendor": {"name": vendor_name, "slug": _slugify_circl(vendor_name)},
                        "product": {"name": product_name, "slug": _slugify_circl(product_name)},
                        "versions": item_versions,
                        "vulnerable": True,
                        "environments": [],
                    }
                    impacted_products.append(impacted_product)

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
        impacted_products,
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


def _slugify_circl(value: str) -> str:
    """Convert a string to a URL-friendly slug."""
    import re
    slug = value.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug)
    return slug.strip("-")


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
