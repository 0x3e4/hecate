from __future__ import annotations

import re
from typing import Any

import structlog
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import PyMongoError

from app.core.config import settings
from app.db.mongo import get_database

log = structlog.get_logger()


class CPERepository:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "CPERepository":
        database = await get_database()
        collection = database[settings.mongo_cpe_collection]
        await collection.create_index([("cpeName", ASCENDING)], unique=True)
        await collection.create_index([("vendor", ASCENDING)])
        await collection.create_index([("product", ASCENDING)])
        await collection.create_index([("lastModified", DESCENDING)])
        return cls(collection)

    async def upsert(self, document: dict[str, Any]) -> bool:
        try:
            result = await self.collection.update_one(
                {"cpeName": document["cpeName"]},
                {"$set": document},
                upsert=True,
            )
        except PyMongoError as exc:
            log.warning("cpe_repository.upsert_failed", cpe=document.get("cpeName"), error=str(exc))
            raise
        return result.matched_count == 0

    async def update_many(self, documents: list[dict[str, Any]]) -> dict[str, int]:
        success = 0
        failure = 0
        for doc in documents:
            if "cpeName" not in doc:
                failure += 1
                continue
            try:
                await self.upsert(doc)
                success += 1
            except Exception:  # noqa: BLE001 - already logged inside upsert
                failure += 1
        return {"success": success, "failure": failure}

    async def distinct_vendors(self, keyword: str | None, limit: int, offset: int) -> tuple[int, list[str]]:
        match: dict[str, Any] = {"vendor": {"$nin": [None, "", "*"]}}
        if keyword:
            match["vendor"].update({"$regex": keyword, "$options": "i"})

        pipeline = [
            {"$match": match},
            {"$group": {"_id": "$vendor"}},
            {"$sort": {"_id": 1}},
            {"$skip": offset},
            {"$limit": limit},
        ]
        cursor = self.collection.aggregate(pipeline, allowDiskUse=True)
        items = await cursor.to_list(length=limit)
        vendors = [item.get("_id") for item in items if isinstance(item.get("_id"), str)]

        count_cursor = self.collection.aggregate([{"$match": match}, {"$group": {"_id": "$vendor"}}, {"$count": "total"}], allowDiskUse=True)
        count_doc = await count_cursor.to_list(length=1)
        total = count_doc[0]["total"] if count_doc else 0
        return total, vendors

    async def distinct_products(
        self,
        vendors: list[str] | None,
        keyword: str | None,
        limit: int,
        offset: int,
    ) -> tuple[int, list[str]]:
        match: dict[str, Any] = {"product": {"$nin": [None, "", "*"]}}
        if vendors:
            or_conditions = []
            for vendor in vendors:
                if not isinstance(vendor, str) or not vendor:
                    continue
                pattern = f"^{re.escape(vendor)}$"
                or_conditions.append({"vendor": {"$regex": pattern, "$options": "i"}})
            if or_conditions:
                match["$or"] = or_conditions
        if keyword:
            match["product"] = {"$regex": keyword, "$options": "i"}

        pipeline = [
            {"$match": match},
            {"$group": {"_id": "$product"}},
            {"$sort": {"_id": 1}},
            {"$skip": offset},
            {"$limit": limit},
        ]
        cursor = self.collection.aggregate(pipeline, allowDiskUse=True)
        items = await cursor.to_list(length=limit)
        products = [item.get("_id") for item in items if isinstance(item.get("_id"), str)]

        count_cursor = self.collection.aggregate([{"$match": match}, {"$group": {"_id": "$product"}}, {"$count": "total"}], allowDiskUse=True)
        count_doc = await count_cursor.to_list(length=1)
        total = count_doc[0]["total"] if count_doc else 0
        return total, products
