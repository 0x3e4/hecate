from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import ValidationError

from app.models.vulnerability import VulnerabilityDocument
from app.repositories.cpe_repository import CPERepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas.backup import (
    BackupRestoreSummary,
    CPEBackupMetadata,
    CPEBackupPayload,
    VulnerabilityBackupMetadata,
    VulnerabilityBackupPayload,
)
from app.schemas.cpe import CPEEntry


log = structlog.get_logger()

VULNERABILITY_SOURCES = {"NVD", "EUVD"}


class BackupService:
    def __init__(self, vulnerability_repo: VulnerabilityRepository, cpe_repo: CPERepository) -> None:
        self.vulnerability_repo = vulnerability_repo
        self.cpe_repo = cpe_repo

    async def export_vulnerabilities(self, source: str) -> VulnerabilityBackupPayload:
        normalized_source = source.upper()
        if normalized_source not in VULNERABILITY_SOURCES:
            raise ValueError(f"Unsupported vulnerability source '{source}'. Expected one of {sorted(VULNERABILITY_SOURCES)}.")

        cursor = self.vulnerability_repo.collection.find({"source": normalized_source})
        items: list[dict[str, Any]] = []
        async for raw_doc in cursor:
            payload = dict(raw_doc)
            payload.pop("_id", None)
            try:
                document = VulnerabilityDocument.model_validate(payload)
            except ValidationError as exc:
                log.warning(
                    "backup.skip_invalid_vulnerability",
                    source=normalized_source,
                    error=str(exc),
                    identifier=payload.get("vuln_id") or payload.get("source_id"),
                )
                continue
            items.append(document.model_dump(mode="python"))

        metadata = VulnerabilityBackupMetadata(
            source=normalized_source,
            exported_at=datetime.now(tz=UTC),
            item_count=len(items),
        )
        return VulnerabilityBackupPayload(metadata=metadata, items=items)

    async def restore_vulnerabilities(self, payload: VulnerabilityBackupPayload) -> BackupRestoreSummary:
        normalized_source = payload.metadata.source.upper()
        inserted = 0
        updated = 0
        skipped = 0

        for item in payload.items:
            try:
                document = VulnerabilityDocument.model_validate(item)
            except ValidationError as exc:
                log.warning(
                    "backup.restore_vulnerability_validation_failed",
                    source=normalized_source,
                    error=str(exc),
                    identifier=item.get("vuln_id") or item.get("source_id"),
                )
                skipped += 1
                continue

            if document.source.upper() != normalized_source:
                log.warning(
                    "backup.restore_vulnerability_source_mismatch",
                    expected=normalized_source,
                    actual=document.source,
                    identifier=document.vuln_id,
                )
                skipped += 1
                continue

            change_context = {
                "job_name": f"backup_restore_{normalized_source.lower()}",
                "job_label": "Backup Restore",
                "metadata": {
                    "source": normalized_source,
                    "identifier": document.vuln_id,
                    "source_id": document.source_id,
                },
            }

            try:
                was_inserted = await self.vulnerability_repo.upsert(document, change_context=change_context)
            except Exception as exc:  # noqa: BLE001 - surface as skipped
                log.error(
                    "backup.restore_vulnerability_failed",
                    source=normalized_source,
                    error=str(exc),
                    identifier=document.vuln_id,
                )
                skipped += 1
                continue

            if was_inserted:
                inserted += 1
            else:
                updated += 1

        total = inserted + updated
        return BackupRestoreSummary(
            dataset="vulnerabilities",
            source=normalized_source,
            inserted=inserted,
            updated=updated,
            skipped=skipped,
            total=total,
        )

    async def export_cpe(self) -> CPEBackupPayload:
        cursor = self.cpe_repo.collection.find({})
        items: list[dict[str, Any]] = []
        async for raw_doc in cursor:
            payload = dict(raw_doc)
            payload.pop("_id", None)
            try:
                entry = CPEEntry.model_validate(payload)
            except ValidationError as exc:
                log.warning("backup.skip_invalid_cpe", error=str(exc), identifier=payload.get("cpeName"))
                continue
            items.append(entry.model_dump(mode="python"))

        metadata = CPEBackupMetadata(
            exported_at=datetime.now(tz=UTC),
            item_count=len(items),
        )
        return CPEBackupPayload(metadata=metadata, items=items)

    async def restore_cpe(self, payload: CPEBackupPayload) -> BackupRestoreSummary:
        inserted = 0
        updated = 0
        skipped = 0

        for item in payload.items:
            try:
                entry = CPEEntry.model_validate(item)
            except ValidationError as exc:
                log.warning("backup.restore_cpe_validation_failed", error=str(exc), identifier=item.get("cpe_name"))
                skipped += 1
                continue

            document = entry.model_dump(by_alias=True, exclude_none=True)

            try:
                was_inserted = await self.cpe_repo.upsert(document)
            except Exception as exc:  # noqa: BLE001
                log.error("backup.restore_cpe_failed", error=str(exc), identifier=entry.cpe_name)
                skipped += 1
                continue

            if was_inserted:
                inserted += 1
            else:
                updated += 1

        total = inserted + updated
        return BackupRestoreSummary(
            dataset="cpe",
            source=None,
            inserted=inserted,
            updated=updated,
            skipped=skipped,
            total=total,
        )


async def get_backup_service() -> BackupService:
    vulnerability_repo = await VulnerabilityRepository.create()
    cpe_repo = await CPERepository.create()
    return BackupService(vulnerability_repo, cpe_repo)
