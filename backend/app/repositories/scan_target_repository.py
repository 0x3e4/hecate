from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.errors import PyMongoError

from app.core.config import settings
from app.db.mongo import get_database
from app.models.scan import ScanTargetDocument

log = structlog.get_logger()


class ScanTargetRepository:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "ScanTargetRepository":
        database = await get_database()
        collection = database[settings.mongo_scan_targets_collection]
        await collection.create_index("type")
        await collection.create_index("updated_at")
        return cls(collection)

    async def upsert(self, target: ScanTargetDocument) -> str:
        """Insert or update a scan target. Returns 'inserted', 'updated', or 'unchanged'."""
        payload = target.model_dump(mode="python")
        payload["_id"] = target.target_id
        payload.pop("target_id", None)
        now = datetime.now(tz=UTC)
        payload["updated_at"] = now

        try:
            existing = await self.collection.find_one({"_id": target.target_id})
        except PyMongoError as exc:
            log.warning("scan_target_repository.lookup_failed", target_id=target.target_id, error=str(exc))
            existing = None

        if existing is not None:
            # Preserve created_at from existing
            payload["created_at"] = existing.get("created_at", now)
            payload["scan_count"] = existing.get("scan_count", 0)
            payload["last_scan_at"] = existing.get("last_scan_at")
            # Preserve user-set auto_scan flag — don't override with model default
            if "auto_scan" in existing:
                payload["auto_scan"] = existing["auto_scan"]
            # Preserve scanners from first scan — don't override on subsequent scans
            if existing.get("scanners"):
                payload["scanners"] = existing["scanners"]
            # Preserve fingerprint data for change detection
            if "last_image_digest" in existing:
                payload["last_image_digest"] = existing["last_image_digest"]
            if "last_commit_sha" in existing:
                payload["last_commit_sha"] = existing["last_commit_sha"]

        try:
            result = await self.collection.replace_one(
                {"_id": target.target_id},
                payload,
                upsert=True,
            )
        except PyMongoError as exc:
            log.error("scan_target_repository.upsert_failed", target_id=target.target_id, error=str(exc))
            raise

        if result.upserted_id is not None:
            return "inserted"
        elif result.modified_count > 0:
            return "updated"
        return "unchanged"

    async def get(self, target_id: str) -> dict[str, Any] | None:
        try:
            doc = await self.collection.find_one({"_id": target_id})
            if doc:
                doc["target_id"] = doc.pop("_id")
            return doc
        except PyMongoError as exc:
            log.warning("scan_target_repository.get_failed", target_id=target_id, error=str(exc))
            return None

    async def list_targets(
        self,
        type_filter: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        query: dict[str, Any] = {}
        if type_filter:
            query["type"] = type_filter

        try:
            total = await self.collection.count_documents(query)
            cursor = (
                self.collection.find(query)
                .sort("updated_at", -1)
                .skip(offset)
                .limit(limit)
            )
            items = []
            async for doc in cursor:
                doc["target_id"] = doc.pop("_id")
                items.append(doc)
            return total, items
        except PyMongoError as exc:
            log.warning("scan_target_repository.list_failed", error=str(exc))
            return 0, []

    async def update_last_scan(self, target_id: str, scan_at: datetime) -> None:
        try:
            await self.collection.update_one(
                {"_id": target_id},
                {
                    "$set": {"last_scan_at": scan_at, "updated_at": datetime.now(tz=UTC)},
                    "$inc": {"scan_count": 1},
                },
            )
        except PyMongoError as exc:
            log.warning("scan_target_repository.update_last_scan_failed", target_id=target_id, error=str(exc))

    async def decrement_scan_count(self, target_id: str) -> None:
        """Decrement the scan count for a target (minimum 0)."""
        try:
            # Use aggregation-pipeline update to clamp at zero
            await self.collection.update_one(
                {"_id": target_id},
                [{"$set": {"scan_count": {"$max": [0, {"$subtract": [{"$ifNull": ["$scan_count", 0]}, 1]}]}}}],
            )
        except PyMongoError as exc:
            log.warning("scan_target_repository.decrement_scan_count_failed", target_id=target_id, error=str(exc))

    async def update_auto_scan(self, target_id: str, auto_scan: bool) -> bool:
        try:
            result = await self.collection.update_one(
                {"_id": target_id},
                {"$set": {"auto_scan": auto_scan, "updated_at": datetime.now(tz=UTC)}},
            )
            return result.modified_count > 0
        except PyMongoError as exc:
            log.warning("scan_target_repository.update_auto_scan_failed", target_id=target_id, error=str(exc))
            return False

    async def update_scanners(self, target_id: str, scanners: list[str]) -> bool:
        try:
            result = await self.collection.update_one(
                {"_id": target_id},
                {"$set": {"scanners": scanners, "updated_at": datetime.now(tz=UTC)}},
            )
            return result.modified_count > 0
        except PyMongoError as exc:
            log.warning("scan_target_repository.update_scanners_failed", target_id=target_id, error=str(exc))
            return False

    async def update_last_fingerprint(
        self, target_id: str, image_digest: str | None = None, commit_sha: str | None = None,
    ) -> None:
        """Store the latest image digest or commit SHA for change detection."""
        update: dict[str, Any] = {"updated_at": datetime.now(tz=UTC)}
        if image_digest is not None:
            update["last_image_digest"] = image_digest
        if commit_sha is not None:
            update["last_commit_sha"] = commit_sha
        try:
            await self.collection.update_one({"_id": target_id}, {"$set": update})
        except PyMongoError as exc:
            log.warning("scan_target_repository.update_fingerprint_failed", target_id=target_id, error=str(exc))

    async def list_auto_scan_targets(self) -> list[dict[str, Any]]:
        """List all targets where auto_scan is enabled (or not set, defaulting to True)."""
        try:
            cursor = self.collection.find(
                {"$or": [{"auto_scan": True}, {"auto_scan": {"$exists": False}}]}
            )
            items = []
            async for doc in cursor:
                doc["target_id"] = doc.pop("_id")
                items.append(doc)
            return items
        except PyMongoError as exc:
            log.warning("scan_target_repository.list_auto_scan_failed", error=str(exc))
            return []

    async def delete(self, target_id: str) -> bool:
        try:
            result = await self.collection.delete_one({"_id": target_id})
            return result.deleted_count > 0
        except PyMongoError as exc:
            log.warning("scan_target_repository.delete_failed", target_id=target_id, error=str(exc))
            return False
