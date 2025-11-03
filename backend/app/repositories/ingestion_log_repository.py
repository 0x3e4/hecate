from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorCollection

from app.core.config import settings
from app.db.mongo import get_database


class IngestionLogRepository:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "IngestionLogRepository":
        database = await get_database()
        collection = database[settings.mongo_ingestion_log_collection]
        await collection.create_index([("jobName", 1)])
        await collection.create_index([("startedAt", -1)])
        return cls(collection)

    async def start_log(self, *, job_name: str, started_at: datetime, metadata: dict[str, Any]) -> ObjectId:
        document = {
            "jobName": job_name,
            "status": "running",
            "startedAt": started_at.astimezone(UTC),
            "metadata": metadata,
        }
        result = await self.collection.insert_one(document)
        return result.inserted_id

    async def update_progress(self, log_id: ObjectId, progress: dict[str, Any]) -> None:
        await self.collection.update_one(
            {"_id": log_id},
            {"$set": {"progress": progress, "lastProgressAt": datetime.now(tz=UTC)}},
        )

    async def cancel_running(self, *, job_name: str, reason: str | None = None) -> int:
        now = datetime.now(tz=UTC)
        cursor = self.collection.find({"jobName": job_name, "status": "running"})
        cancelled = 0
        async for document in cursor:
            started_at = document.get("startedAt")
            if isinstance(started_at, datetime):
                started_at = started_at.astimezone(UTC)
            else:
                started_at = now

            duration = (now - started_at).total_seconds()
            update: dict[str, Any] = {
                "status": "cancelled",
                "finishedAt": now,
                "durationSeconds": duration,
            }
            if reason:
                update["error"] = reason

            await self.collection.update_one({"_id": document["_id"]}, {"$set": update})
            cancelled += 1

        return cancelled

    async def complete_log(
        self,
        log_id: ObjectId,
        *,
        started_at: datetime,
        finished_at: datetime,
        result: dict[str, Any],
    ) -> None:
        await self.collection.update_one(
            {"_id": log_id},
            {
                "$set": {
                    "status": "completed",
                    "finishedAt": finished_at.astimezone(UTC),
                    "durationSeconds": (finished_at - started_at).total_seconds(),
                    "result": result,
                },
                "$unset": {"progress": "", "lastProgressAt": ""},
            },
        )

    async def fail_log(
        self,
        log_id: ObjectId,
        *,
        started_at: datetime,
        finished_at: datetime,
        error: str,
    ) -> None:
        await self.collection.update_one(
            {"_id": log_id},
            {
                "$set": {
                    "status": "failed",
                    "finishedAt": finished_at.astimezone(UTC),
                    "durationSeconds": (finished_at - started_at).total_seconds(),
                    "error": error,
                },
                "$unset": {"progress": "", "lastProgressAt": ""},
            },
        )

    async def list_logs(
        self,
        *,
        job_name: str | None,
        limit: int,
        offset: int,
    ) -> tuple[int, list[dict[str, Any]]]:
        query: dict[str, Any] = {}
        if job_name:
            query["jobName"] = job_name
        cursor = self.collection.find(query).sort("startedAt", -1).skip(offset).limit(limit)
        total = await self.collection.count_documents(query)
        items = await cursor.to_list(length=limit)
        return total, items

    async def insert_event(
        self,
        *,
        job_name: str,
        status: str,
        started_at: datetime,
        finished_at: datetime | None = None,
        duration_seconds: float | None = None,
        metadata: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> ObjectId:
        document: dict[str, Any] = {
            "jobName": job_name,
            "status": status,
            "startedAt": started_at.astimezone(UTC),
        }
        if finished_at is not None:
            document["finishedAt"] = finished_at.astimezone(UTC)
        if duration_seconds is not None:
            document["durationSeconds"] = duration_seconds
        if metadata:
            document["metadata"] = metadata
        if result:
            document["result"] = result
        if error:
            document["error"] = error

        inserted = await self.collection.insert_one(document)
        return inserted.inserted_id
