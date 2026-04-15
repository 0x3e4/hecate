from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import ValidationError

from app.models.vulnerability import VulnerabilityDocument
from app.repositories.inventory_repository import InventoryRepository
from app.repositories.saved_search_repository import SavedSearchRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas.backup import (
    BackupRestoreSummary,
    InventoryBackupMetadata,
    InventoryBackupPayload,
    SavedSearchBackupMetadata,
    SavedSearchBackupPayload,
    VulnerabilityBackupMetadata,
    VulnerabilityBackupPayload,
)


log = structlog.get_logger()

VULNERABILITY_SOURCES = {"NVD", "EUVD"}


class BackupService:
    def __init__(
        self,
        vulnerability_repo: VulnerabilityRepository,
        saved_search_repo: SavedSearchRepository,
        inventory_repo: InventoryRepository,
    ) -> None:
        self.vulnerability_repo = vulnerability_repo
        self.saved_search_repo = saved_search_repo
        self.inventory_repo = inventory_repo

    async def stream_vulnerability_export(self, source: str) -> AsyncIterator[str]:
        """Stream vulnerability backup as JSON chunks to avoid timeouts on large datasets."""
        normalized_source = source.upper()

        if normalized_source == "ALL":
            filter_query: dict[str, Any] = {"source": {"$in": list(VULNERABILITY_SOURCES)}}
        elif normalized_source in VULNERABILITY_SOURCES:
            filter_query = {"source": normalized_source}
        else:
            raise ValueError(f"Unsupported vulnerability source '{source}'. Expected one of {sorted(VULNERABILITY_SOURCES)} or 'ALL'.")

        item_count = await self.vulnerability_repo.collection.count_documents(filter_query)

        metadata = VulnerabilityBackupMetadata(
            source=normalized_source,
            exported_at=datetime.now(tz=UTC),
            item_count=item_count,
        )
        metadata_json = json.dumps(
            metadata.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        yield f'{{"metadata":{metadata_json},"items":['

        cursor = self.vulnerability_repo.collection.find(filter_query)
        first = True
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

            item_json = json.dumps(
                document.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
            )
            if first:
                yield item_json
                first = False
            else:
                yield f",{item_json}"

        yield "]}"

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

            if normalized_source != "ALL" and document.source.upper() != normalized_source:
                log.warning(
                    "backup.restore_vulnerability_source_mismatch",
                    expected=normalized_source,
                    actual=document.source,
                    identifier=document.vuln_id,
                )
                skipped += 1
                continue

            if normalized_source == "ALL" and document.source.upper() not in VULNERABILITY_SOURCES:
                log.warning(
                    "backup.restore_vulnerability_invalid_source",
                    source=document.source,
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
                result = await self.vulnerability_repo.upsert(document, change_context=change_context)
            except Exception as exc:  # noqa: BLE001 - surface as skipped
                log.error(
                    "backup.restore_vulnerability_failed",
                    source=normalized_source,
                    error=str(exc),
                    identifier=document.vuln_id,
                )
                skipped += 1
                continue

            if result.inserted:
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

    async def export_saved_searches(self) -> SavedSearchBackupPayload:
        documents = await self.saved_search_repo.list_all()
        items: list[dict[str, Any]] = []
        for doc in documents:
            item = {
                "name": doc.get("name", ""),
                "queryParams": doc.get("queryParams", ""),
                "dqlQuery": doc.get("dqlQuery"),
                "createdAt": doc.get("createdAt", datetime.now(tz=UTC)).isoformat() if isinstance(doc.get("createdAt"), datetime) else doc.get("createdAt"),
                "updatedAt": doc.get("updatedAt", datetime.now(tz=UTC)).isoformat() if isinstance(doc.get("updatedAt"), datetime) else doc.get("updatedAt"),
            }
            items.append(item)

        metadata = SavedSearchBackupMetadata(
            exported_at=datetime.now(tz=UTC),
            item_count=len(items),
        )
        return SavedSearchBackupPayload(metadata=metadata, items=items)

    async def restore_saved_searches(self, payload: SavedSearchBackupPayload) -> BackupRestoreSummary:
        inserted = 0
        skipped = 0

        for item in payload.items:
            name = item.get("name", "").strip()
            query_params = item.get("queryParams", "").strip()
            dql_query = item.get("dqlQuery")

            if not name:
                log.warning("backup.restore_saved_search_missing_name", item=item)
                skipped += 1
                continue

            try:
                await self.saved_search_repo.insert(
                    name=name,
                    query_params=query_params,
                    dql_query=dql_query.strip() if isinstance(dql_query, str) else None,
                )
                inserted += 1
            except Exception as exc:  # noqa: BLE001
                log.error("backup.restore_saved_search_failed", error=str(exc), name=name)
                skipped += 1
                continue

        return BackupRestoreSummary(
            dataset="saved_searches",
            source=None,
            inserted=inserted,
            updated=0,
            skipped=skipped,
            total=inserted,
        )

    # ------------------------------------------------------------------
    # Environment Inventory
    # ------------------------------------------------------------------

    async def export_inventory(self) -> InventoryBackupPayload:
        """Export every environment-inventory item as a backup payload.

        Preserves the original `_id` (under the key ``id``) and the
        ``created_at``/``updated_at`` timestamps so a later restore round-trips
        to the same documents rather than creating duplicates.
        """
        documents = await self.inventory_repo.list_all()
        items: list[dict[str, Any]] = []
        for doc in documents:
            item = {
                "id": str(doc.get("_id")) if doc.get("_id") is not None else None,
                "name": doc.get("name", ""),
                "vendor_slug": doc.get("vendor_slug", ""),
                "product_slug": doc.get("product_slug", ""),
                "vendor_name": doc.get("vendor_name"),
                "product_name": doc.get("product_name"),
                "version": doc.get("version", ""),
                "deployment": doc.get("deployment", "onprem"),
                "environment": doc.get("environment", "prod"),
                "instance_count": int(doc.get("instance_count", 1) or 1),
                "owner": doc.get("owner"),
                "notes": doc.get("notes"),
                "created_at": (
                    doc.get("created_at").isoformat()
                    if isinstance(doc.get("created_at"), datetime)
                    else doc.get("created_at")
                ),
                "updated_at": (
                    doc.get("updated_at").isoformat()
                    if isinstance(doc.get("updated_at"), datetime)
                    else doc.get("updated_at")
                ),
            }
            items.append(item)

        metadata = InventoryBackupMetadata(
            exported_at=datetime.now(tz=UTC),
            item_count=len(items),
        )
        return InventoryBackupPayload(metadata=metadata, items=items)

    async def restore_inventory(self, payload: InventoryBackupPayload) -> BackupRestoreSummary:
        """Restore environment-inventory items from a backup payload.

        Semantics:
        - Items with an ``id`` that already exists are **updated** in place
          (mutable fields overwritten, original ``created_at`` preserved).
        - Items with an ``id`` that doesn't exist are **inserted** with that
          same ID.
        - Items with no ``id`` get a fresh UUID and are inserted.
        - Rows missing one of the required fields (name, vendor_slug,
          product_slug, version) are **skipped** with a warning.
        """
        from uuid import uuid4

        inserted = 0
        updated = 0
        skipped = 0

        for item in payload.items:
            name = (item.get("name") or "").strip()
            vendor_slug = (item.get("vendor_slug") or "").strip().lower()
            product_slug = (item.get("product_slug") or "").strip().lower()
            version = (item.get("version") or "").strip()

            if not name or not vendor_slug or not product_slug or not version:
                log.warning(
                    "backup.restore_inventory_missing_required_fields",
                    item=item,
                )
                skipped += 1
                continue

            def _coerce_instance_count(value: Any) -> int:
                try:
                    count = int(value) if value is not None else 1
                except (TypeError, ValueError):
                    return 1
                return max(1, count)

            data = {
                "name": name,
                "vendor_slug": vendor_slug,
                "product_slug": product_slug,
                "vendor_name": item.get("vendor_name"),
                "product_name": item.get("product_name"),
                "version": version,
                "deployment": item.get("deployment") or "onprem",
                "environment": item.get("environment") or "prod",
                "instance_count": _coerce_instance_count(item.get("instance_count")),
                "owner": item.get("owner"),
                "notes": item.get("notes"),
            }

            item_id = (item.get("id") or "").strip() if isinstance(item.get("id"), str) else None

            try:
                if item_id:
                    existing = await self.inventory_repo.get(item_id)
                    if existing:
                        await self.inventory_repo.update(item_id, data)
                        updated += 1
                        continue
                    # Preserve the exported ID when no conflict.
                    await self.inventory_repo.insert(item_id, data)
                else:
                    await self.inventory_repo.insert(str(uuid4()), data)
                inserted += 1
            except Exception as exc:  # noqa: BLE001
                log.error(
                    "backup.restore_inventory_failed",
                    error=str(exc),
                    name=name,
                    id=item_id,
                )
                skipped += 1
                continue

        return BackupRestoreSummary(
            dataset="inventory",
            source=None,
            inserted=inserted,
            updated=updated,
            skipped=skipped,
            total=inserted + updated,
        )


async def get_backup_service() -> BackupService:
    vulnerability_repo = await VulnerabilityRepository.create()
    saved_search_repo = await SavedSearchRepository.create()
    inventory_repo = await InventoryRepository.create()
    return BackupService(vulnerability_repo, saved_search_repo, inventory_repo)
