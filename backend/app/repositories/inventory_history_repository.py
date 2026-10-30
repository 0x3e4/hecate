from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ASCENDING, DESCENDING

from app.core.config import settings
from app.db.mongo import get_database

# Stored field -> wire field. Display names are captured from the slugs and
# would only repeat a slug change, so they stay out of the history.
TRACKED_FIELDS: dict[str, str] = {
    "name": "name",
    "vendor_slug": "vendorSlug",
    "product_slug": "productSlug",
    "version": "version",
    "deployment": "deployment",
    "environment": "environment",
    "instance_count": "instanceCount",
    "owner": "owner",
    "notes": "notes",
    "eol_product": "eolProduct",
}


def diff_tracked_fields(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    """List the tracked fields *after* really changes against *before*.

    The UI sends the whole form on every edit, so presence in *after* says
    nothing; an empty string and a missing value count as the same thing.
    """
    changes: list[dict[str, Any]] = []
    for field, wire in TRACKED_FIELDS.items():
        if field not in after:
            continue
        old = before.get(field) or None
        new = after.get(field) or None
        if old != new:
            changes.append({"field": wire, "old": old, "new": new})
    return changes


class InventoryHistoryRepository:
    """Append-only change log of inventory items.

    A collection of its own rather than an array on the item: the history of a
    deleted item stays readable, and a cross-item feed is one indexed sort.
    """

    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> InventoryHistoryRepository:
        database = await get_database()
        collection = database[settings.mongo_environment_inventory_history_collection]
        await collection.create_index([("item_id", ASCENDING), ("created_at", DESCENDING)])
        await collection.create_index([("created_at", DESCENDING)])
        return cls(collection)

    async def record(
        self,
        *,
        item_id: str,
        item_name: str,
        action: str,
        source: str,
        changes: list[dict[str, Any]] | None = None,
        actor: str | None = None,
    ) -> dict[str, Any]:
        entry = {
            "_id": str(uuid4()),
            "item_id": item_id,
            "item_name": item_name,
            "action": action,
            "source": source,
            "actor": actor,
            "changes": changes or [],
            "created_at": datetime.now(tz=UTC),
        }
        await self.collection.insert_one(entry)
        return entry

    async def list_entries(
        self, *, item_id: str | None, limit: int, offset: int
    ) -> tuple[int, list[dict[str, Any]]]:
        query: dict[str, Any] = {"item_id": item_id} if item_id else {}
        total = await self.collection.count_documents(query)
        cursor = (
            self.collection.find(query)
            .sort("created_at", DESCENDING)
            .skip(offset)
            .limit(limit)
        )
        return total, await cursor.to_list(length=limit)
