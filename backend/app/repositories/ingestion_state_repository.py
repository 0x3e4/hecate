from __future__ import annotations

from datetime import datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection

from app.core.config import settings
from app.db.mongo import get_database


class IngestionStateRepository:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "IngestionStateRepository":
        database = await get_database()
        collection = database[settings.mongo_ingestion_state_collection]
        # _id index exists by default; ensure TTL for optional expires_at field.
        await collection.create_index("expires_at", expireAfterSeconds=0, sparse=True)
        return cls(collection)

    async def get_timestamp(self, key: str) -> datetime | None:
        doc = await self.collection.find_one({"_id": key})
        if not doc:
            return None
        ts = doc.get("last_run")
        if isinstance(ts, datetime):
            return ts
        return None

    async def get_state(self, key: str) -> dict[str, Any] | None:
        doc = await self.collection.find_one({"_id": key})
        if not doc:
            return None
        return doc

    async def set_timestamp(self, key: str, ts: datetime) -> None:
        await self.collection.update_one(
            {"_id": key},
            {"$set": {"last_run": ts}},
            upsert=True,
        )

    async def update_state(self, key: str, updates: dict[str, Any]) -> None:
        await self.collection.update_one(
            {"_id": key},
            {"$set": updates},
            upsert=True,
        )
