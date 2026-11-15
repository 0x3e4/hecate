"""Cache of registry release metadata per (ecosystem, package, version).

Backs the supply-chain signals on SBOM components (release age, latest
version, npm publisher) and the package check. Entries expire through a TTL
index on ``expires_at``, so a rescan inside the TTL costs no registry request.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ReplaceOne
from pymongo.errors import PyMongoError

from app.core.config import settings
from app.db.mongo import get_database

log = structlog.get_logger()


class PackageReleaseRepository:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "PackageReleaseRepository":
        database = await get_database()
        collection = database[settings.mongo_package_releases_collection]
        await collection.create_index("expires_at", expireAfterSeconds=0)
        return cls(collection)

    async def get_many(self, keys: list[str]) -> dict[str, dict[str, Any]]:
        """Cached documents by key; expired ones count as missing.

        The TTL monitor only runs once a minute, so the expiry is checked here too.
        """
        if not keys:
            return {}
        now = datetime.now(UTC)
        out: dict[str, dict[str, Any]] = {}
        try:
            async for doc in self.collection.find({"_id": {"$in": keys}}):
                expires = doc.get("expires_at")
                if isinstance(expires, datetime):
                    if expires.tzinfo is None:
                        expires = expires.replace(tzinfo=UTC)
                    if expires <= now:
                        continue
                out[doc["_id"]] = doc
        except PyMongoError as exc:
            log.warning("package_release_repository.get_many_failed", count=len(keys), error=str(exc))
        return out

    async def put_many(self, docs: dict[str, dict[str, Any]], ttl_hours: float) -> None:
        if not docs:
            return
        now = datetime.now(UTC)
        expires = now + timedelta(hours=ttl_hours)
        ops = [
            ReplaceOne({"_id": key}, {**doc, "_id": key, "fetched_at": now, "expires_at": expires}, upsert=True)
            for key, doc in docs.items()
        ]
        try:
            await self.collection.bulk_write(ops, ordered=False)
        except PyMongoError as exc:
            log.warning("package_release_repository.put_many_failed", count=len(ops), error=str(exc))
