from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ASCENDING

from app.core.config import settings
from app.db.mongo import get_database


class LicensePolicyRepository:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> LicensePolicyRepository:
        database = await get_database()
        collection = database[settings.mongo_license_policies_collection]
        await collection.create_index([("name", ASCENDING)], unique=True)
        await collection.create_index([("is_default", ASCENDING)])
        return cls(collection)

    async def list_all(self) -> list[dict[str, Any]]:
        cursor = self.collection.find({}).sort("name", ASCENDING)
        documents: list[dict[str, Any]] = []
        async for doc in cursor:
            documents.append(doc)
        return documents

    async def get(self, policy_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"_id": policy_id})

    async def get_default(self) -> dict[str, Any] | None:
        return await self.collection.find_one({"is_default": True})

    async def insert(self, policy_id: str, data: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(tz=UTC)
        payload = {
            "_id": policy_id,
            **data,
            "created_at": now,
            "updated_at": now,
        }
        await self.collection.insert_one(payload)
        return payload

    async def update(self, policy_id: str, updates: dict[str, Any]) -> bool:
        updates["updated_at"] = datetime.now(tz=UTC)
        result = await self.collection.update_one(
            {"_id": policy_id},
            {"$set": updates},
        )
        return result.modified_count > 0

    async def set_default(self, policy_id: str) -> bool:
        """Unset any existing default and set the given policy as default."""
        await self.collection.update_many(
            {"is_default": True},
            {"$set": {"is_default": False, "updated_at": datetime.now(tz=UTC)}},
        )
        result = await self.collection.update_one(
            {"_id": policy_id},
            {"$set": {"is_default": True, "updated_at": datetime.now(tz=UTC)}},
        )
        return result.modified_count > 0

    async def delete(self, policy_id: str) -> bool:
        result = await self.collection.delete_one({"_id": policy_id})
        return result.deleted_count > 0
