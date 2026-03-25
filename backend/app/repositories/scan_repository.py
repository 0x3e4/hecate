from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.errors import PyMongoError

from app.core.config import settings
from app.db.mongo import get_database
from app.models.scan import ScanDocument, ScanSummary

log = structlog.get_logger()


class ScanRepository:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "ScanRepository":
        database = await get_database()
        collection = database[settings.mongo_scans_collection]
        await collection.create_index("target_id")
        await collection.create_index("status")
        await collection.create_index([("created_at", -1)])
        await collection.create_index([("target_id", 1), ("created_at", -1)])
        return cls(collection)

    async def insert(self, scan: ScanDocument) -> str:
        """Insert a new scan record. Returns the scan _id as string."""
        payload = scan.model_dump(mode="python")
        payload["created_at"] = datetime.now(tz=UTC)
        try:
            result = await self.collection.insert_one(payload)
            return str(result.inserted_id)
        except PyMongoError as exc:
            log.error("scan_repository.insert_failed", error=str(exc))
            raise

    async def update_status(
        self,
        scan_id: str,
        status: str,
        *,
        finished_at: datetime | None = None,
        duration_seconds: float | None = None,
        summary: ScanSummary | None = None,
        sbom_component_count: int | None = None,
        error: str | None = None,
    ) -> None:
        update: dict[str, Any] = {"status": status}
        if finished_at is not None:
            update["finished_at"] = finished_at
        if duration_seconds is not None:
            update["duration_seconds"] = duration_seconds
        if summary is not None:
            update["summary"] = summary.model_dump(mode="python")
        if sbom_component_count is not None:
            update["sbom_component_count"] = sbom_component_count
        if error is not None:
            update["error"] = error

        try:
            await self.collection.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": update},
            )
        except PyMongoError as exc:
            log.warning("scan_repository.update_status_failed", scan_id=scan_id, error=str(exc))

    async def update_fields(self, scan_id: str, fields: dict[str, Any]) -> None:
        """Update arbitrary fields on a scan document."""
        if not fields:
            return
        try:
            await self.collection.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": fields},
            )
        except PyMongoError as exc:
            log.warning("scan_repository.update_fields_failed", scan_id=scan_id, error=str(exc))

    async def get(self, scan_id: str) -> dict[str, Any] | None:
        try:
            doc = await self.collection.find_one({"_id": ObjectId(scan_id)})
            if doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except (PyMongoError, Exception) as exc:
            log.warning("scan_repository.get_failed", scan_id=scan_id, error=str(exc))
            return None

    async def list_by_target(
        self, target_id: str, limit: int = 20, offset: int = 0
    ) -> tuple[int, list[dict[str, Any]]]:
        query = {"target_id": target_id}
        try:
            total = await self.collection.count_documents(query)
            cursor = (
                self.collection.find(query)
                .sort("created_at", -1)
                .skip(offset)
                .limit(limit)
            )
            items = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                items.append(doc)
            return total, items
        except PyMongoError as exc:
            log.warning("scan_repository.list_by_target_failed", target_id=target_id, error=str(exc))
            return 0, []

    async def list_all(
        self,
        target_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        query: dict[str, Any] = {}
        if target_id:
            query["target_id"] = target_id
        if status:
            query["status"] = status

        try:
            total = await self.collection.count_documents(query)
            cursor = (
                self.collection.find(query)
                .sort("created_at", -1)
                .skip(offset)
                .limit(limit)
            )
            items = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                items.append(doc)
            return total, items
        except PyMongoError as exc:
            log.warning("scan_repository.list_all_failed", error=str(exc))
            return 0, []

    async def get_latest_by_target(self, target_id: str) -> dict[str, Any] | None:
        try:
            cursor = (
                self.collection.find({"target_id": target_id, "status": "completed"})
                .sort("created_at", -1)
                .limit(1)
            )
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                return doc
            return None
        except PyMongoError as exc:
            log.warning("scan_repository.get_latest_failed", target_id=target_id, error=str(exc))
            return None

    async def has_running_scan(self, target_id: str) -> bool:
        """Check if a target has any running or pending scan."""
        try:
            count = await self.collection.count_documents(
                {"target_id": target_id, "status": {"$in": ["running", "pending"]}},
                limit=1,
            )
            return count > 0
        except PyMongoError as exc:
            log.warning("scan_repository.has_running_failed", target_id=target_id, error=str(exc))
            return False

    async def get_history(
        self, target_id: str, limit: int = 30
    ) -> list[dict[str, Any]]:
        """Return scan history for charting (most recent completed scans with summaries)."""
        try:
            cursor = (
                self.collection.find(
                    {"target_id": target_id, "status": "completed"},
                    {"_id": 1, "started_at": 1, "status": 1, "summary": 1, "duration_seconds": 1},
                )
                .sort("created_at", -1)
                .limit(limit)
            )
            items = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                items.append(doc)
            items.reverse()
            return items
        except PyMongoError as exc:
            log.warning("scan_repository.get_history_failed", target_id=target_id, error=str(exc))
            return []

    async def delete(self, scan_id: str) -> bool:
        try:
            result = await self.collection.delete_one({"_id": ObjectId(scan_id)})
            return result.deleted_count > 0
        except PyMongoError as exc:
            log.warning("scan_repository.delete_failed", scan_id=scan_id, error=str(exc))
            return False

    async def delete_by_target(self, target_id: str) -> int:
        try:
            result = await self.collection.delete_many({"target_id": target_id})
            return result.deleted_count
        except PyMongoError as exc:
            log.warning("scan_repository.delete_by_target_failed", target_id=target_id, error=str(exc))
            return 0
