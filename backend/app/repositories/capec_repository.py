from __future__ import annotations

from datetime import UTC, datetime

import structlog
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.errors import PyMongoError

from app.core.config import settings
from app.db.mongo import get_database
from app.models.capec import CAPECEntry

log = structlog.get_logger()


class CAPECRepository:
    """Repository for CAPEC (Common Attack Pattern Enumeration and Classification) data persistence."""

    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "CAPECRepository":
        database = await get_database()
        collection = database[settings.mongo_capec_collection]
        await collection.create_index("capec_id", unique=True)
        await collection.create_index("fetched_at")
        return cls(collection)

    async def get_by_id(self, capec_id: str) -> CAPECEntry | None:
        normalized_id = capec_id.upper().replace("CAPEC-", "").strip()

        try:
            document = await self.collection.find_one({"capec_id": normalized_id})
            if document:
                document.pop("_id", None)
                return CAPECEntry.model_validate(document)
        except (PyMongoError, Exception) as exc:
            log.warning("capec_repository.get_failed", capec_id=normalized_id, error=str(exc))

        return None

    async def get_multiple(self, capec_ids: list[str]) -> dict[str, CAPECEntry]:
        normalized_ids = [cid.upper().replace("CAPEC-", "").strip() for cid in capec_ids]
        results: dict[str, CAPECEntry] = {}

        try:
            cursor = self.collection.find({"capec_id": {"$in": normalized_ids}})
            async for document in cursor:
                document.pop("_id", None)
                try:
                    entry = CAPECEntry.model_validate(document)
                    results[entry.capec_id] = entry
                except Exception as exc:
                    log.warning(
                        "capec_repository.parse_error",
                        capec_id=document.get("capec_id"),
                        error=str(exc),
                    )
        except PyMongoError as exc:
            log.warning("capec_repository.get_multiple_failed", error=str(exc))

        return results

    async def upsert_entry(self, entry: CAPECEntry) -> str:
        payload = entry.model_dump(mode="python", by_alias=False)
        payload["_id"] = entry.capec_id
        payload["capec_id"] = entry.capec_id

        if isinstance(payload.get("fetched_at"), datetime):
            dt = payload["fetched_at"]
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            payload["fetched_at"] = dt.astimezone(UTC)

        try:
            result = await self.collection.update_one(
                {"_id": entry.capec_id},
                {"$set": payload},
                upsert=True,
            )

            if result.upserted_id is not None:
                return "inserted"
            elif result.modified_count > 0:
                return "updated"
            else:
                return "unchanged"

        except PyMongoError as exc:
            log.error(
                "capec_repository.upsert_failed",
                capec_id=entry.capec_id,
                error=str(exc),
            )
            raise

    async def bulk_upsert(self, entries: list[CAPECEntry]) -> dict[str, int]:
        if not entries:
            return {"inserted": 0, "updated": 0, "unchanged": 0}

        counts = {"inserted": 0, "updated": 0, "unchanged": 0}

        for entry in entries:
            try:
                action = await self.upsert_entry(entry)
                counts[action] = counts.get(action, 0) + 1
            except Exception as exc:
                log.warning(
                    "capec_repository.bulk_upsert_item_failed",
                    capec_id=entry.capec_id,
                    error=str(exc),
                )

        return counts

    async def count(self) -> int:
        try:
            return await self.collection.count_documents({})
        except PyMongoError as exc:
            log.warning("capec_repository.count_failed", error=str(exc))
            return 0

    async def delete_old_entries(self, before: datetime) -> int:
        try:
            result = await self.collection.delete_many({"fetched_at": {"$lt": before}})
            return result.deleted_count
        except PyMongoError as exc:
            log.warning("capec_repository.delete_old_failed", error=str(exc))
            return 0
