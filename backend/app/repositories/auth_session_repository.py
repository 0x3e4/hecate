from __future__ import annotations

from datetime import datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ASCENDING

from app.core.config import settings
from app.db.mongo import get_database


class AuthSessionRepository:
    """Web sessions and pending logins (``kind`` = ``session`` | ``login``).

    ``_id`` is the SHA-256 of the cookie value, so the collection alone opens
    no session. A TTL index on ``expires_at`` drops both kinds once they lapse.
    """

    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> AuthSessionRepository:
        database = await get_database()
        collection = database[settings.mongo_auth_sessions_collection]
        await collection.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
        return cls(collection)

    async def insert(self, document: dict[str, Any]) -> None:
        await self.collection.insert_one(document)

    async def get(self, document_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"_id": document_id})

    async def pop(self, document_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one_and_delete({"_id": document_id})

    async def touch(self, document_id: str, seen_at: datetime) -> None:
        await self.collection.update_one({"_id": document_id}, {"$set": {"last_seen_at": seen_at}})
