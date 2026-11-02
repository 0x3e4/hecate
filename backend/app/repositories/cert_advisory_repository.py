from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection

from app.core.config import settings
from app.db.mongo import get_database
from app.services.ingestion.cert_feed_client import CertAdvisoryItem


def advisory_id(feed: str, guid: str) -> str:
    return f"{feed}:{guid}"


class CertAdvisoryRepository:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "CertAdvisoryRepository":
        database = await get_database()
        collection = database[settings.mongo_cert_advisories_collection]
        await collection.create_index([("published", -1)])
        await collection.create_index("cve_ids")
        return cls(collection)

    async def existing_ids(self, ids: Iterable[str]) -> set[str]:
        cursor = self.collection.find({"_id": {"$in": list(ids)}}, {"_id": 1})
        return {document["_id"] async for document in cursor}

    async def insert(self, feed: str, item: CertAdvisoryItem, cve_ids: list[str]) -> None:
        now = datetime.now(UTC)
        await self.collection.update_one(
            {"_id": advisory_id(feed, item.guid)},
            {
                "$setOnInsert": {
                    "feed": feed,
                    "title": item.title,
                    "url": item.url,
                    "published": item.published or now,
                    "cve_ids": cve_ids,
                    "first_seen_at": now,
                }
            },
            upsert=True,
        )

    async def list_since(self, since: datetime) -> list[dict[str, Any]]:
        """Advisories that name at least one CVE, newest first."""
        cursor = self.collection.find(
            {"published": {"$gte": since}, "cve_ids": {"$ne": []}},
            {"feed": 1, "title": 1, "url": 1, "published": 1, "cve_ids": 1},
        ).sort("published", -1)
        return [document async for document in cursor]

    async def mentions_since(self, since: datetime) -> dict[str, list[dict[str, Any]]]:
        """Maps each CVE to the feeds that named it since ``since``, one entry per feed, newest first."""
        cursor = self.collection.find(
            {"published": {"$gte": since}, "cve_ids": {"$ne": []}},
            {"feed": 1, "title": 1, "url": 1, "cve_ids": 1},
        ).sort("published", -1)
        mentions: dict[str, dict[str, dict[str, Any]]] = {}
        async for document in cursor:
            for cve_id in document.get("cve_ids", []):
                entry = {"name": document["feed"], "title": document.get("title"), "url": document.get("url")}
                mentions.setdefault(cve_id, {}).setdefault(document["feed"], entry)
        return {cve_id: list(feeds.values()) for cve_id, feeds in mentions.items()}
