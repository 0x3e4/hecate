from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ASCENDING

from app.core.config import settings
from app.db.mongo import get_database


class VexRuleRepository:
    """Automatic VEX triage rules (``vex_rules`` collection)."""

    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> VexRuleRepository:
        database = await get_database()
        collection = database[settings.mongo_vex_rules_collection]
        await collection.create_index([("priority", ASCENDING), ("created_at", ASCENDING)])
        return cls(collection)

    async def list_all(self) -> list[dict[str, Any]]:
        cursor = self.collection.find({}).sort([("priority", ASCENDING), ("created_at", ASCENDING)])
        return [doc async for doc in cursor]

    async def list_enabled(self) -> list[dict[str, Any]]:
        cursor = self.collection.find({"enabled": True}).sort([("priority", ASCENDING), ("created_at", ASCENDING)])
        return [doc async for doc in cursor]

    async def get(self, rule_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"_id": rule_id})

    async def insert(self, data: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(tz=UTC)
        payload = {"_id": uuid.uuid4().hex[:16], **data, "created_at": now, "updated_at": now}
        await self.collection.insert_one(payload)
        return payload

    async def replace(self, rule_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        existing = await self.get(rule_id)
        if not existing:
            return None
        payload = {
            **data,
            "_id": rule_id,
            "created_at": existing.get("created_at"),
            "updated_at": datetime.now(tz=UTC),
        }
        await self.collection.replace_one({"_id": rule_id}, payload)
        return payload

    async def delete(self, rule_id: str) -> bool:
        result = await self.collection.delete_one({"_id": rule_id})
        return result.deleted_count > 0
