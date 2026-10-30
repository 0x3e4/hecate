from __future__ import annotations

from datetime import datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ASCENDING, DESCENDING

from app.core.config import settings
from app.db.mongo import get_database


class ApiTokenRepository:
    """API tokens created on the System page. Holds hashes, never the tokens."""

    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> ApiTokenRepository:
        database = await get_database()
        collection = database[settings.mongo_api_tokens_collection]
        await collection.create_index([("token_hash", ASCENDING)], unique=True)
        await collection.create_index([("scopes", ASCENDING)])
        return cls(collection)

    async def list_all(self) -> list[dict[str, Any]]:
        cursor = self.collection.find({}, {"token_hash": 0}).sort("created_at", DESCENDING)
        return [doc async for doc in cursor]

    async def insert(self, document: dict[str, Any]) -> None:
        await self.collection.insert_one(document)

    async def get_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"token_hash": token_hash})

    async def any_with_scope(self, scope: str) -> bool:
        return await self.collection.find_one({"scopes": scope}, {"_id": 1}) is not None

    async def touch(self, token_id: str, used_at: datetime) -> None:
        await self.collection.update_one({"_id": token_id}, {"$set": {"last_used_at": used_at}})

    async def delete(self, token_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one_and_delete({"_id": token_id})
