from __future__ import annotations

from typing import Any

import structlog
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.errors import PyMongoError

from app.core.config import settings
from app.db.mongo import get_database
from app.models.scan import ScanSbomComponentDocument

log = structlog.get_logger()


class ScanSbomRepository:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "ScanSbomRepository":
        database = await get_database()
        collection = database[settings.mongo_scan_sbom_collection]
        await collection.create_index("scan_id")
        await collection.create_index("target_id")
        await collection.create_index("purl")
        return cls(collection)

    async def bulk_insert(self, components: list[ScanSbomComponentDocument]) -> int:
        """Insert multiple SBOM components. Returns count of inserted documents."""
        if not components:
            return 0
        payloads = [c.model_dump(mode="python") for c in components]
        try:
            result = await self.collection.insert_many(payloads, ordered=False)
            return len(result.inserted_ids)
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.bulk_insert_failed", count=len(components), error=str(exc))
            return 0

    async def list_by_scan(
        self,
        scan_id: str,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        query: dict[str, Any] = {"scan_id": scan_id}
        if search:
            query["name"] = {"$regex": search, "$options": "i"}

        try:
            total = await self.collection.count_documents(query)
            cursor = (
                self.collection.find(query)
                .sort([("name", 1), ("version", 1)])
                .skip(offset)
                .limit(limit)
            )
            items = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                items.append(doc)
            return total, items
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.list_by_scan_failed", scan_id=scan_id, error=str(exc))
            return 0, []

    async def list_all_by_scan(self, scan_id: str) -> list[dict[str, Any]]:
        """Fetch all SBOM components for a scan (no pagination, for export)."""
        try:
            cursor = self.collection.find({"scan_id": scan_id}).sort([("name", 1), ("version", 1)])
            items = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                items.append(doc)
            return items
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.list_all_failed", scan_id=scan_id, error=str(exc))
            return []

    async def list_across_scans_consolidated(
        self,
        scan_ids: list[str],
        search: str | None = None,
        type_filter: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        """List SBOM components across scans, consolidated by name+version."""
        if not scan_ids:
            return 0, []
        match_stage: dict[str, Any] = {"scan_id": {"$in": scan_ids}}
        if search:
            regex = {"$regex": search, "$options": "i"}
            match_stage["$or"] = [
                {"name": regex},
                {"type": regex},
                {"purl": regex},
                {"licenses": regex},
            ]
        if type_filter:
            match_stage["type"] = type_filter

        pipeline: list[dict[str, Any]] = [
            {"$match": match_stage},
            {"$group": {
                "_id": {"name": "$name", "version": "$version"},
                "type": {"$first": "$type"},
                "purl": {"$first": "$purl"},
                "licenses": {"$first": "$licenses"},
                "provenance_verified": {"$first": "$provenance_verified"},
                "targets": {"$addToSet": {"target_id": "$target_id", "scan_id": "$scan_id"}},
            }},
            {"$sort": {"_id.name": 1, "_id.version": 1}},
            {"$facet": {
                "total": [{"$count": "count"}],
                "items": [{"$skip": offset}, {"$limit": limit}],
            }},
        ]
        try:
            result = await self.collection.aggregate(pipeline).to_list(1)
            if not result:
                return 0, []
            doc = result[0]
            total = doc["total"][0]["count"] if doc["total"] else 0
            items: list[dict[str, Any]] = []
            for item in doc["items"]:
                items.append({
                    "name": item["_id"]["name"],
                    "version": item["_id"]["version"],
                    "type": item.get("type", ""),
                    "purl": item.get("purl"),
                    "licenses": item.get("licenses", []),
                    "provenance_verified": item.get("provenance_verified"),
                    "targets": item.get("targets", []),
                })
            return total, items
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.list_across_scans_consolidated_failed", error=str(exc))
            return 0, []

    async def count_consolidated(self, scan_ids: list[str]) -> int:
        """Count consolidated SBOM components (grouped by name+version) across scans."""
        if not scan_ids:
            return 0
        pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": scan_ids}}},
            {"$group": {"_id": {"name": "$name", "version": "$version"}}},
            {"$count": "total"},
        ]
        try:
            result = await self.collection.aggregate(pipeline).to_list(1)
            return result[0]["total"] if result else 0
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.count_consolidated_failed", error=str(exc))
            return 0

    async def count_distinct_licenses(self, scan_ids: list[str]) -> int:
        """Count distinct license identifiers across scans."""
        if not scan_ids:
            return 0
        pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": scan_ids}}},
            {"$unwind": "$licenses"},
            {"$group": {"_id": "$licenses"}},
            {"$count": "total"},
        ]
        try:
            result = await self.collection.aggregate(pipeline).to_list(1)
            return result[0]["total"] if result else 0
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.count_distinct_licenses_failed", error=str(exc))
            return 0

    async def delete_by_scan(self, scan_id: str) -> int:
        try:
            result = await self.collection.delete_many({"scan_id": scan_id})
            return result.deleted_count
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.delete_by_scan_failed", scan_id=scan_id, error=str(exc))
            return 0

    async def delete_by_target(self, target_id: str) -> int:
        try:
            result = await self.collection.delete_many({"target_id": target_id})
            return result.deleted_count
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.delete_by_target_failed", target_id=target_id, error=str(exc))
            return 0
