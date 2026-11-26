from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ASCENDING
from pymongo.errors import DuplicateKeyError

from app.core.config import settings
from app.db.mongo import get_database


def name_key(name: str) -> str:
    """The uniqueness key of a system name: trimmed and casefolded."""
    return name.strip().casefold()


class SystemNameTaken(ValueError):
    """Another system already has this name."""


class InventorySystemRepository:
    """Systems of the inventory (``inventory_systems``), ``_id`` a UUID.

    ``name_key`` is unique, so a push for ``WEB-01`` and a list entry
    ``web-01`` are one system; ``target_id`` is unique where set, so one
    SBOM-import target belongs to at most one system.
    """

    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> InventorySystemRepository:
        database = await get_database()
        collection = database[settings.mongo_inventory_systems_collection]
        await collection.create_index([("name_key", ASCENDING)], unique=True)
        await collection.create_index(
            [("target_id", ASCENDING)], unique=True,
            partialFilterExpression={"target_id": {"$type": "string"}},
        )
        return cls(collection)

    async def list_all(self) -> list[dict[str, Any]]:
        return [doc async for doc in self.collection.find({}).sort("name_key", ASCENDING)]

    async def get(self, system_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"_id": system_id})

    async def get_by_name(self, name: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"name_key": name_key(name)})

    async def get_by_target(self, target_id: str) -> dict[str, Any] | None:
        return await self.collection.find_one({"target_id": target_id})

    async def target_links(self) -> dict[str, str]:
        """target id -> system id, for every linked system."""
        cursor = self.collection.find({"target_id": {"$type": "string"}}, projection={"target_id": 1})
        return {doc["target_id"]: str(doc["_id"]) async for doc in cursor}

    async def linked_target_ids(self) -> list[str]:
        cursor = self.collection.find({"target_id": {"$type": "string"}}, projection={"target_id": 1})
        return [doc["target_id"] async for doc in cursor]

    async def insert(self, system_id: str, data: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(tz=UTC)
        payload = {"_id": system_id, **data, "name_key": name_key(data["name"]), "created_at": now, "updated_at": now}
        try:
            await self.collection.insert_one(payload)
        except DuplicateKeyError as exc:
            raise SystemNameTaken(data["name"]) from exc
        return payload

    async def update(self, system_id: str, set_fields: dict[str, Any], unset_fields: list[str] = ()) -> bool:
        update: dict[str, Any] = {"$set": {**set_fields, "updated_at": datetime.now(tz=UTC)}}
        if "name" in set_fields:
            update["$set"]["name_key"] = name_key(set_fields["name"])
        if unset_fields:
            update["$unset"] = {field: "" for field in unset_fields}
        try:
            result = await self.collection.update_one({"_id": system_id}, update)
        except DuplicateKeyError as exc:
            raise SystemNameTaken(str(set_fields.get("name", ""))) from exc
        return result.matched_count > 0

    async def unlink_target(self, target_id: str) -> int:
        result = await self.collection.update_many(
            {"target_id": target_id},
            {"$unset": {"target_id": ""}, "$set": {"updated_at": datetime.now(tz=UTC)}},
        )
        return result.modified_count

    async def delete(self, system_id: str) -> bool:
        result = await self.collection.delete_one({"_id": system_id})
        return result.deleted_count > 0
