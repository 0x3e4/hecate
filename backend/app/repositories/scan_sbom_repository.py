from __future__ import annotations

from typing import Any

import structlog
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.errors import PyMongoError

from app.core.config import settings
from app.db.mongo import get_database
from app.models.scan import ScanSbomComponentDocument

log = structlog.get_logger()


class ScanSbomRepository:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "ScanSbomRepository":
        database = await get_database()
        collection = database[settings.mongo_scan_sbom_collection]
        await collection.create_index("scan_id")
        await collection.create_index("target_id")
        await collection.create_index("purl")
        return cls(collection)

    async def bulk_insert(self, components: list[ScanSbomComponentDocument]) -> int:
        """Insert multiple SBOM components. Returns count of inserted documents."""
        if not components:
            return 0
        payloads = [c.model_dump(mode="python") for c in components]
        try:
            result = await self.collection.insert_many(payloads, ordered=False)
            return len(result.inserted_ids)
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.bulk_insert_failed", count=len(components), error=str(exc))
            return 0

    async def list_by_scan(
        self,
        scan_id: str,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        query: dict[str, Any] = {"scan_id": scan_id}
        if search:
            query["name"] = {"$regex": search, "$options": "i"}

        try:
            total = await self.collection.count_documents(query)
            cursor = (
                self.collection.find(query)
                .sort([("name", 1), ("version", 1)])
                .skip(offset)
                .limit(limit)
            )
            items = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                items.append(doc)
            return total, items
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.list_by_scan_failed", scan_id=scan_id, error=str(exc))
            return 0, []

    async def delete_by_scan(self, scan_id: str) -> int:
        try:
            result = await self.collection.delete_many({"scan_id": scan_id})
            return result.deleted_count
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.delete_by_scan_failed", scan_id=scan_id, error=str(exc))
            return 0

    async def delete_by_target(self, target_id: str) -> int:
        try:
            result = await self.collection.delete_many({"target_id": target_id})
            return result.deleted_count
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.delete_by_target_failed", target_id=target_id, error=str(exc))
            return 0
