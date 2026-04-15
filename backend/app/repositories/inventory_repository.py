from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ASCENDING

from app.core.config import settings
from app.db.mongo import get_database


class InventoryRepository:
    """CRUD + lookup helpers for user-declared environment inventory items."""

    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> InventoryRepository:
        database = await get_database()
        collection = database[settings.mongo_environment_inventory_collection]
        await collection.create_index(
            [("vendor_slug", ASCENDING), ("product_slug", ASCENDING)]
        )
        await collection.create_index([("name", ASCENDING)])
        return cls(collection)

    async def list_all(self) -> list[dict[str, Any]]:
        cursor = self.collection.find({}).sort("name", ASCENDING)
        documents: list[dict[str, Any]] = []
        async for doc in cursor:
            documents.append(doc)
        return documents

    async def get(self, item_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"_id": item_id})

    async def insert(self, item_id: str, data: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(tz=UTC)
        payload = {
            "_id": item_id,
            **data,
            "created_at": now,
            "updated_at": now,
        }
        await self.collection.insert_one(payload)
        return payload

    async def update(self, item_id: str, updates: dict[str, Any]) -> bool:
        updates["updated_at"] = datetime.now(tz=UTC)
        result = await self.collection.update_one(
            {"_id": item_id},
            {"$set": updates},
        )
        return result.modified_count > 0

    async def delete(self, item_id: str) -> bool:
        result = await self.collection.delete_one({"_id": item_id})
        return result.deleted_count > 0

    async def distinct_vendor_product_pairs(self) -> list[tuple[str, str]]:
        """Return the set of (vendor_slug, product_slug) pairs present in inventory.

        Used by the notification watch-rule evaluator to narrow an OpenSearch
        range query to products the user actually runs.
        """
        cursor = self.collection.find(
            {},
            projection={"vendor_slug": 1, "product_slug": 1},
        )
        pairs: set[tuple[str, str]] = set()
        async for doc in cursor:
            vendor = doc.get("vendor_slug")
            product = doc.get("product_slug")
            if isinstance(vendor, str) and isinstance(product, str):
                pairs.add((vendor, product))
        return sorted(pairs)
