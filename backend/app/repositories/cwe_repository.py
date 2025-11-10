from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.errors import PyMongoError

from app.core.config import settings
from app.db.mongo import get_database
from app.models.cwe import CWEEntry

log = structlog.get_logger()


class CWERepository:
    """Repository for CWE (Common Weakness Enumeration) data persistence."""

    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "CWERepository":
        database = await get_database()
        collection = database[settings.mongo_cwe_collection]
        # Create unique index on CWE ID
        await collection.create_index("cwe_id", unique=True)
        # Create index on fetched_at for cache management
        await collection.create_index("fetched_at")
        return cls(collection)

    async def get_by_id(self, cwe_id: str) -> CWEEntry | None:
        """
        Retrieve a CWE entry by its ID.

        Args:
            cwe_id: Normalized CWE ID (e.g., "79")

        Returns:
            CWEEntry if found, None otherwise
        """
        normalized_id = cwe_id.upper().replace("CWE-", "").strip()

        try:
            document = await self.collection.find_one({"cwe_id": normalized_id})
            if document:
                document.pop("_id", None)  # Remove MongoDB _id field
                return CWEEntry.model_validate(document)
        except (PyMongoError, Exception) as exc:
            log.warning("cwe_repository.get_failed", cwe_id=normalized_id, error=str(exc))

        return None

    async def get_multiple(self, cwe_ids: list[str]) -> dict[str, CWEEntry]:
        """
        Retrieve multiple CWE entries by their IDs.

        Args:
            cwe_ids: List of CWE IDs

        Returns:
            Dict mapping normalized CWE IDs to their entries
        """
        normalized_ids = [cwe_id.upper().replace("CWE-", "").strip() for cwe_id in cwe_ids]
        results: dict[str, CWEEntry] = {}

        try:
            cursor = self.collection.find({"cwe_id": {"$in": normalized_ids}})
            async for document in cursor:
                document.pop("_id", None)
                try:
                    entry = CWEEntry.model_validate(document)
                    results[entry.cwe_id] = entry
                except Exception as exc:
                    log.warning(
                        "cwe_repository.parse_error",
                        cwe_id=document.get("cwe_id"),
                        error=str(exc)
                    )
        except PyMongoError as exc:
            log.warning("cwe_repository.get_multiple_failed", error=str(exc))

        return results

    async def upsert_entry(self, entry: CWEEntry) -> str:
        """
        Insert or update a CWE entry.

        Args:
            entry: CWEEntry to persist

        Returns:
            The action taken: "inserted" or "updated"
        """
        payload = entry.model_dump(mode="python", by_alias=False)
        payload["_id"] = entry.cwe_id
        payload["cwe_id"] = entry.cwe_id

        # Ensure datetime is UTC
        if isinstance(payload.get("fetched_at"), datetime):
            dt = payload["fetched_at"]
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            payload["fetched_at"] = dt.astimezone(UTC)

        try:
            result = await self.collection.update_one(
                {"_id": entry.cwe_id},
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
                "cwe_repository.upsert_failed",
                cwe_id=entry.cwe_id,
                error=str(exc)
            )
            raise

    async def bulk_upsert(self, entries: list[CWEEntry]) -> dict[str, int]:
        """
        Bulk upsert multiple CWE entries.

        Args:
            entries: List of CWEEntry objects

        Returns:
            Dict with counts: {"inserted": N, "updated": M, "unchanged": K}
        """
        if not entries:
            return {"inserted": 0, "updated": 0, "unchanged": 0}

        counts = {"inserted": 0, "updated": 0, "unchanged": 0}

        for entry in entries:
            try:
                action = await self.upsert_entry(entry)
                counts[action] = counts.get(action, 0) + 1
            except Exception as exc:
                log.warning(
                    "cwe_repository.bulk_upsert_item_failed",
                    cwe_id=entry.cwe_id,
                    error=str(exc)
                )

        return counts

    async def existing_cwe_ids(self) -> set[str]:
        """
        Get all existing CWE IDs in the collection.

        Returns:
            Set of CWE IDs (normalized)
        """
        identifiers: set[str] = set()

        try:
            cursor = self.collection.find({}, {"cwe_id": 1})
            async for document in cursor:
                cwe_id = document.get("cwe_id")
                if isinstance(cwe_id, str):
                    identifiers.add(cwe_id)
        except PyMongoError as exc:
            log.warning("cwe_repository.fetch_ids_failed", error=str(exc))

        return identifiers

    async def count(self) -> int:
        """Get total count of CWE entries in the collection."""
        try:
            return await self.collection.count_documents({})
        except PyMongoError as exc:
            log.warning("cwe_repository.count_failed", error=str(exc))
            return 0

    async def delete_old_entries(self, before: datetime) -> int:
        """
        Delete CWE entries older than the specified date.

        Args:
            before: Delete entries fetched before this datetime

        Returns:
            Number of deleted entries
        """
        try:
            result = await self.collection.delete_many({"fetched_at": {"$lt": before}})
            return result.deleted_count
        except PyMongoError as exc:
            log.warning("cwe_repository.delete_old_failed", error=str(exc))
            return 0
