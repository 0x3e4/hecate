from __future__ import annotations

from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ASCENDING, ReturnDocument

from app.core.config import settings
from app.db.mongo import get_database


def name_key(name: str) -> str:
    """Names are compared without case: `CERT-FR` and `cert-fr` would be two sources that read as one."""
    return name.strip().casefold()


class AdvisoryFeedRepository:
    """Advisory feeds added on the System page. The `.env` feeds are not stored here."""

    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> AdvisoryFeedRepository:
        database = await get_database()
        collection = database[settings.mongo_advisory_feeds_collection]
        await collection.create_index([("name_key", ASCENDING)], unique=True)
        return cls(collection)

    async def list_all(self) -> list[dict[str, Any]]:
        cursor = self.collection.find({}).sort("name_key", ASCENDING)
        return [document async for document in cursor]

    async def get(self, feed_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"_id": feed_id})

    async def insert(self, document: dict[str, Any]) -> None:
        await self.collection.insert_one(document)

    async def update(self, feed_id: str, fields: dict[str, Any]) -> dict[str, Any] | None:
        return await self.collection.find_one_and_update(
            {"_id": feed_id}, {"$set": fields}, return_document=ReturnDocument.AFTER
        )

    async def delete(self, feed_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one_and_delete({"_id": feed_id})
