from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection

from app.core.config import settings
from app.db.mongo import get_database


def user_key(issuer: str, sub: str) -> str:
    """One document per account at the identity provider."""
    return f"{issuer.rstrip('/')}|{sub}"


class UserPreferencesRepository:
    """``user_preferences``: one document per signed-in account, ``_id`` = issuer|sub."""

    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "UserPreferencesRepository":
        database = await get_database()
        return cls(database[settings.mongo_user_preferences_collection])

    async def get(self, key: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"_id": key})

    async def save(self, key: str, preferences: dict[str, Any]) -> datetime:
        now = datetime.now(UTC)
        await self.collection.replace_one(
            {"_id": key}, {"_id": key, "preferences": preferences, "updated_at": now}, upsert=True
        )
        return now


_repository: UserPreferencesRepository | None = None


async def get_user_preferences_repository() -> UserPreferencesRepository:
    global _repository
    if _repository is None:
        _repository = await UserPreferencesRepository.create()
    return _repository
