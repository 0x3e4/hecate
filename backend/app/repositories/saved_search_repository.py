from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from bson import ObjectId
from bson.errors import InvalidId
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ASCENDING, ReturnDocument

from app.core.config import settings
from app.db.mongo import get_database


class SavedSearchRepository:
    """
    Persists saved vulnerability DQL searches in MongoDB.
    """

    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "SavedSearchRepository":
        database = await get_database()
        collection = database[settings.mongo_saved_searches_collection]
        await collection.create_index([("name", ASCENDING)])
        await collection.create_index([("createdAt", ASCENDING)])
        return cls(collection)

    async def list_all(self) -> list[dict[str, Any]]:
        cursor = self.collection.find({}).sort("name", ASCENDING)
        documents: list[dict[str, Any]] = []
        async for document in cursor:
            documents.append(document)
        return documents

    async def insert(self, *, name: str, query_params: str, dql_query: str | None) -> dict[str, Any]:
        now = datetime.now(tz=UTC)
        payload = {
            "name": name,
            "queryParams": query_params,
            "dqlQuery": dql_query,
            "createdAt": now,
            "updatedAt": now,
        }
        result = await self.collection.insert_one(payload)
        payload["_id"] = result.inserted_id
        return payload

    async def get(self, search_id: str) -> dict[str, Any] | None:
        try:
            object_id = ObjectId(search_id)
        except (InvalidId, TypeError):
            return None
        document = await self.collection.find_one({"_id": object_id})
        if document is None:
            return None
        return document

    async def update(self, search_id: str, fields: dict[str, Any]) -> dict[str, Any] | None:
        try:
            object_id = ObjectId(search_id)
        except (InvalidId, TypeError):
            return None
        fields["updatedAt"] = datetime.now(tz=UTC)
        result = await self.collection.find_one_and_update(
            {"_id": object_id},
            {"$set": fields},
            return_document=ReturnDocument.AFTER,
        )
        return result

    async def delete(self, search_id: str) -> bool:
        try:
            object_id = ObjectId(search_id)
        except (InvalidId, TypeError):
            return False
        result = await self.collection.delete_one({"_id": object_id})
        return result.deleted_count > 0
