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
        await collection.create_index("group")
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
            # Preserve group unless explicitly set on the new payload
            if not payload.get("group") and existing.get("group"):
                payload["group"] = existing["group"]
            # Preserve fingerprint data for change detection
            if "last_image_digest" in existing:
                payload["last_image_digest"] = existing["last_image_digest"]
            if "last_commit_sha" in existing:
                payload["last_commit_sha"] = existing["last_commit_sha"]
            # Preserve denormalized scan state
            for field in ("latest_summary", "latest_scan_id", "has_running_scan", "running_scan_id", "running_scan_status"):
                if field in existing:
                    payload[field] = existing[field]

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
        group_filter: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        query: dict[str, Any] = {}
        if type_filter:
            query["type"] = type_filter
        if group_filter is not None:
            if group_filter == "":
                query["$or"] = [{"group": None}, {"group": {"$exists": False}}, {"group": ""}]
            else:
                query["group"] = group_filter

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

    async def update_group(self, target_id: str, group: str | None) -> bool:
        normalized = group.strip() if isinstance(group, str) else None
        if normalized == "":
            normalized = None
        try:
            result = await self.collection.update_one(
                {"_id": target_id},
                {"$set": {"group": normalized, "updated_at": datetime.now(tz=UTC)}},
            )
            return result.matched_count > 0
        except PyMongoError as exc:
            log.warning("scan_target_repository.update_group_failed", target_id=target_id, error=str(exc))
            return False

    async def list_groups(self) -> list[dict[str, Any]]:
        """Aggregate distinct group values with target counts."""
        try:
            cursor = self.collection.aggregate([
                {"$group": {"_id": "$group", "count": {"$sum": 1}}},
                {"$sort": {"_id": 1}},
            ])
            return [{"group": doc.get("_id"), "target_count": int(doc.get("count", 0))} async for doc in cursor]
        except PyMongoError as exc:
            log.warning("scan_target_repository.list_groups_failed", error=str(exc))
            return []

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

    async def update_last_check(
        self,
        target_id: str,
        *,
        verdict: str,
        current_fingerprint: str | None,
        error: str | None,
    ) -> None:
        """Persist the most recent /check probe result on the target doc.

        Powers the auto-scan diagnostics table on the SCA Scans → Scanner
        tab so users can see when a target was last probed, what fingerprint
        the scanner returned, and why the scheduler decided to scan or skip.
        Always called from ``ScanService.check_target_changed`` regardless
        of verdict — including on /check failure — so the UI never goes blind.
        """
        try:
            await self.collection.update_one(
                {"_id": target_id},
                {"$set": {
                    "last_check_at": datetime.now(tz=UTC),
                    "last_check_verdict": verdict,
                    "last_check_current_fingerprint": current_fingerprint,
                    "last_check_error": error,
                    "updated_at": datetime.now(tz=UTC),
                }},
            )
        except PyMongoError as exc:
            log.warning(
                "scan_target_repository.update_last_check_failed",
                target_id=target_id,
                error=str(exc),
            )

    async def update_scan_state(
        self,
        target_id: str,
        latest_summary: dict[str, int] | None,
        latest_scan_id: str | None,
        has_running_scan: bool = False,
        running_scan_id: str | None = None,
        running_scan_status: str | None = None,
    ) -> None:
        """Atomically update all denormalized scan state fields on a target."""
        try:
            await self.collection.update_one(
                {"_id": target_id},
                {"$set": {
                    "latest_summary": latest_summary,
                    "latest_scan_id": latest_scan_id,
                    "has_running_scan": has_running_scan,
                    "running_scan_id": running_scan_id,
                    "running_scan_status": running_scan_status,
                    "updated_at": datetime.now(tz=UTC),
                }},
            )
        except PyMongoError as exc:
            log.warning("scan_target_repository.update_scan_state_failed", target_id=target_id, error=str(exc))

    async def update_running_state(
        self,
        target_id: str,
        has_running_scan: bool,
        running_scan_id: str | None = None,
        running_scan_status: str | None = None,
    ) -> None:
        """Update only the running-scan-related denormalized fields."""
        try:
            await self.collection.update_one(
                {"_id": target_id},
                {"$set": {
                    "has_running_scan": has_running_scan,
                    "running_scan_id": running_scan_id,
                    "running_scan_status": running_scan_status,
                    "updated_at": datetime.now(tz=UTC),
                }},
            )
        except PyMongoError as exc:
            log.warning("scan_target_repository.update_running_state_failed", target_id=target_id, error=str(exc))

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
