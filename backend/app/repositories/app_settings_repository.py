from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ReturnDocument

from app.core.config import settings
from app.db.mongo import get_database

# Single fixed-key document holds all editable app-level settings.
_DOC_ID = "global"


class AppSettingsRepository:
    """Persists runtime-editable app settings in a single MongoDB document.

    Unlike the env-based ``Settings``, these values can be changed at runtime
    through the System page (e.g. the AI batch limit). One document keyed by
    ``_id == "global"`` keeps the store trivial to read and upsert.
    """

    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "AppSettingsRepository":
        database = await get_database()
        collection = database[settings.mongo_app_settings_collection]
        return cls(collection)

    async def get(self) -> dict[str, Any] | None:
        return await self.collection.find_one({"_id": _DOC_ID})

    async def set_value(self, key: str, value: Any) -> dict[str, Any]:
        document = await self.collection.find_one_and_update(
            {"_id": _DOC_ID},
            {"$set": {key: value, "updatedAt": datetime.now(tz=UTC)}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return document
