from __future__ import annotations

from datetime import UTC, datetime
import re
from typing import Any

import structlog

from app.models.vulnerability import VulnerabilityDocument
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.ingestion.euvd_client import EUVDClient
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
    ) -> None:
        self.euvd_client = euvd_client or EUVDClient()
        self.nvd_client = nvd_client or NVDClient()

    async def ingest(self, *, modified_since: datetime | None = None, limit: int | None = None) -> dict[str, int]:
        repository = await VulnerabilityRepository.create()
        ingested = 0
        skipped = 0

        async for record in self.euvd_client.list_vulnerabilities(modified_since=modified_since):
            identifiers = _extract_identifiers(record)
            if identifiers is None:
                skipped += 1
                continue

            cve_id, source_id = identifiers

            supplemental = await self.nvd_client.fetch_cve(cve_id) if _is_cve(cve_id) else None
            document = build_document(
                cve_id=cve_id,
                source_id=source_id,
                euvd_record=record,
                supplemental_record=supplemental,
                ingested_at=datetime.now(tz=UTC),
            )

            await repository.upsert(document)
            ingested += 1

            log.info(
                "pipeline.vulnerability_ingested",
                cve_id=cve_id,
                title=document.title,
                severity=document.cvss.severity,
            )

            if limit is not None and ingested >= limit:
                break

        return {"ingested": ingested, "skipped": skipped}

    async def close(self) -> None:
        await self.euvd_client.close()
        await self.nvd_client.close()


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


async def run_ingestion(*, modified_since: datetime | None = None, limit: int | None = None) -> dict[str, int]:
    pipeline = IngestionPipeline()
    try:
        return await pipeline.ingest(modified_since=modified_since, limit=limit)
    finally:
        await pipeline.close()
