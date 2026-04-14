from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ASCENDING, ReturnDocument

from app.core.config import settings
from app.db.mongo import get_database


class NotificationRuleRepository:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> NotificationRuleRepository:
        database = await get_database()
        collection = database[settings.mongo_notification_rules_collection]
        await collection.create_index([("enabled", ASCENDING)])
        await collection.create_index([("rule_type", ASCENDING)])
        return cls(collection)

    async def list_all(self) -> list[dict[str, Any]]:
        cursor = self.collection.find({}).sort("name", ASCENDING)
        documents: list[dict[str, Any]] = []
        async for doc in cursor:
            documents.append(doc)
        return documents

    async def list_enabled(self) -> list[dict[str, Any]]:
        cursor = self.collection.find({"enabled": True}).sort("name", ASCENDING)
        documents: list[dict[str, Any]] = []
        async for doc in cursor:
            documents.append(doc)
        return documents

    async def list_enabled_by_type(self, rule_type: str) -> list[dict[str, Any]]:
        cursor = self.collection.find({"enabled": True, "rule_type": rule_type}).sort("name", ASCENDING)
        documents: list[dict[str, Any]] = []
        async for doc in cursor:
            documents.append(doc)
        return documents

    async def get(self, rule_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"_id": rule_id})

    async def insert(self, rule_id: str, data: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(tz=UTC)
        payload = {
            "_id": rule_id,
            **data,
            "created_at": now,
            "updated_at": now,
        }
        await self.collection.insert_one(payload)
        return payload

    async def update(self, rule_id: str, updates: dict[str, Any]) -> bool:
        updates["updated_at"] = datetime.now(tz=UTC)
        result = await self.collection.update_one(
            {"_id": rule_id},
            {"$set": updates},
        )
        return result.modified_count > 0

    async def delete(self, rule_id: str) -> bool:
        result = await self.collection.delete_one({"_id": rule_id})
        return result.deleted_count > 0

    async def claim_evaluation(
        self, rule_id: str, prev: datetime | None, now: datetime
    ) -> bool:
        """Atomically advance ``last_evaluated_at`` from ``prev`` to ``now``.

        Returns True if this caller won the claim, False if another concurrent
        evaluator already advanced the watermark. Under ``$eq`` semantics a
        filter of ``{"last_evaluated_at": None}`` matches both missing and
        explicitly-null fields, so first-ever evaluations work without seeding.
        """
        result = await self.collection.find_one_and_update(
            {"_id": rule_id, "last_evaluated_at": prev},
            {"$set": {"last_evaluated_at": now, "updated_at": now}},
            return_document=ReturnDocument.AFTER,
        )
        return result is not None
