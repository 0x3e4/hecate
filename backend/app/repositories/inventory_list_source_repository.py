from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ASCENDING
from pymongo.errors import DuplicateKeyError

from app.core.config import settings
from app.db.mongo import get_database


def source_key(source: str) -> str:
    return source.strip().casefold()


class ListSourceTaken(ValueError):
    """Another list source already uses this name."""


class InventoryListSourceRepository:
    """Server lists Hecate fetches itself (``inventory_list_sources``), ``_id`` a UUID.

    ``source_key`` is unique: the name is what the systems carry in
    ``list_sources``, so two sources with one name would retire each other's
    systems in replace mode. The credential (``auth_header_value``) is stored
    here and never leaves the backend.
    """

    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> InventoryListSourceRepository:
        database = await get_database()
        collection = database[settings.mongo_inventory_list_sources_collection]
        await collection.create_index([("source_key", ASCENDING)], unique=True)
        return cls(collection)

    async def list_all(self) -> list[dict[str, Any]]:
        return [doc async for doc in self.collection.find({}).sort("source_key", ASCENDING)]

    async def get(self, source_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"_id": source_id})

    async def count(self) -> int:
        return await self.collection.count_documents({})

    async def insert(self, source_id: str, data: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(tz=UTC)
        payload = {"_id": source_id, **data, "source_key": source_key(data["source"]), "created_at": now, "updated_at": now}
        try:
            await self.collection.insert_one(payload)
        except DuplicateKeyError as exc:
            raise ListSourceTaken(data["source"]) from exc
        return payload

    async def update(self, source_id: str, fields: dict[str, Any], *, touch: bool = True) -> dict[str, Any] | None:
        """Set fields and return the document. ``touch=False`` for run bookkeeping, which is no edit."""
        set_fields = dict(fields)
        if touch:
            set_fields["updated_at"] = datetime.now(tz=UTC)
        if "source" in set_fields:
            set_fields["source_key"] = source_key(set_fields["source"])
        try:
            result = await self.collection.update_one({"_id": source_id}, {"$set": set_fields})
        except DuplicateKeyError as exc:
            raise ListSourceTaken(str(fields.get("source", ""))) from exc
        if result.matched_count == 0:
            return None
        return await self.get(source_id)

    async def delete(self, source_id: str) -> dict[str, Any] | None:
        existing = await self.get(source_id)
        if existing is None:
            return None
        await self.collection.delete_one({"_id": source_id})
        return existing
