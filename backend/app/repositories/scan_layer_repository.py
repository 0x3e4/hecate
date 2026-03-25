from __future__ import annotations

from typing import Any

import structlog
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.errors import PyMongoError

from app.core.config import settings
from app.db.mongo import get_database
from app.models.scan import ScanLayerAnalysisDocument

log = structlog.get_logger()


class ScanLayerRepository:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "ScanLayerRepository":
        database = await get_database()
        collection = database[settings.mongo_scan_layers_collection]
        await collection.create_index("scan_id", unique=True)
        await collection.create_index("target_id")
        return cls(collection)

    async def insert(self, doc: ScanLayerAnalysisDocument) -> bool:
        """Insert a layer analysis document. Returns True on success."""
        try:
            await self.collection.insert_one(doc.model_dump(mode="python"))
            return True
        except PyMongoError as exc:
            log.warning("scan_layer_repository.insert_failed", scan_id=doc.scan_id, error=str(exc))
            return False

    async def get_by_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Get layer analysis for a scan."""
        try:
            doc = await self.collection.find_one({"scan_id": scan_id})
            if doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except PyMongoError as exc:
            log.warning("scan_layer_repository.get_by_scan_failed", scan_id=scan_id, error=str(exc))
            return None

    async def delete_by_scan(self, scan_id: str) -> int:
        try:
            result = await self.collection.delete_many({"scan_id": scan_id})
            return result.deleted_count
        except PyMongoError as exc:
            log.warning("scan_layer_repository.delete_by_scan_failed", scan_id=scan_id, error=str(exc))
            return 0

    async def delete_by_target(self, target_id: str) -> int:
        try:
            result = await self.collection.delete_many({"target_id": target_id})
            return result.deleted_count
        except PyMongoError as exc:
            log.warning("scan_layer_repository.delete_by_target_failed", target_id=target_id, error=str(exc))
            return 0
