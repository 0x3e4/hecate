from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime
from typing import Iterable, Tuple

import structlog

from app.models.vulnerability import VulnerabilityDocument
from app.repositories.ingestion_log_repository import IngestionLogRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas.vulnerability import VulnerabilityRefreshStatus
from app.services.asset_catalog_service import AssetCatalogService
from app.services.ingestion.euvd_client import EUVDClient
from app.services.ingestion.nvd_client import NVDClient
from app.services.ingestion.normalizer import build_document, build_document_from_nvd

log = structlog.get_logger()

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
EUVD_PATTERN = re.compile(r"EUVD-\d{4}-\d{4,7}", re.IGNORECASE)


class ManualRefresher:
    """
    Fetches individual vulnerabilities from NVD and EUVD on demand.
    Creates reserved placeholders when upstream data is not yet published.
    """

    def __init__(
        self,
        *,
        nvd_client: NVDClient | None = None,
        euvd_client: EUVDClient | None = None,
    ) -> None:
        self._nvd_client = nvd_client or NVDClient()
        self._euvd_client = euvd_client or EUVDClient()

    async def refresh(self, identifiers: Iterable[str]) -> list[VulnerabilityRefreshStatus]:
        prepared = [
            value.strip()
            for value in identifiers
            if isinstance(value, str) and value.strip()
        ]
        if not prepared:
            await self._nvd_client.close()
            await self._euvd_client.close()
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
        statuses: list[VulnerabilityRefreshStatus] = []

        failed = False
        try:
            for original, normalized in self._iterate_identifiers(prepared):
                status = await self._refresh_single(
                    original_identifier=original,
                    normalized_identifier=normalized,
                    repository=repository,
                    asset_catalog=asset_catalog,
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

        return statuses

    async def _refresh_single(
        self,
        *,
        original_identifier: str,
        normalized_identifier: str,
        repository: VulnerabilityRepository,
        asset_catalog: AssetCatalogService,
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
        if canonical_id and CVE_PATTERN.fullmatch(canonical_id) and not is_euvd:
            nvd_record = await self._nvd_client.fetch_cve(canonical_id)

        if euvd_record:
            document, product_version_map = build_document(
                cve_id=canonical_id,
                source_id=source_id,
                euvd_record=euvd_record,
                supplemental_record=nvd_record,
                ingested_at=ingested_at,
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
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "manual_refresher.asset_catalog_update_failed",
                    vuln_id=document.vuln_id,
                    error=str(exc),
                )
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
            inserted = await repository.upsert(document, change_context=change_context)
            message = None
            if document.published is None:
                message = "EUVD record ingested without published date; marked as reserved."
            return VulnerabilityRefreshStatus(
                identifier=original_identifier,
                provider="EUVD",
                status="inserted" if inserted else "updated",
                message=message,
            )

        if nvd_record:
            built = build_document_from_nvd(nvd_record, ingested_at=ingested_at)
            if built:
                document, product_version_map = built
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
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "manual_refresher.asset_catalog_update_failed",
                        vuln_id=document.vuln_id,
                        error=str(exc),
                    )
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
                inserted = await repository.upsert_from_nvd(
                    document,
                    nvd_raw=nvd_record,
                    change_context=change_context,
                )
                message = None
                if document.published is None:
                    message = "NVD record missing published date; stored as reserved."
                return VulnerabilityRefreshStatus(
                    identifier=original_identifier,
                    provider="NVD",
                    status="inserted" if inserted else "updated",
                    message=message,
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
        inserted = await repository.upsert(placeholder, change_context=change_context)
        return VulnerabilityRefreshStatus(
            identifier=original_identifier,
            provider="placeholder",
            status="inserted" if inserted else "updated",
            message="No upstream data available; stored as reserved placeholder.",
        )

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
