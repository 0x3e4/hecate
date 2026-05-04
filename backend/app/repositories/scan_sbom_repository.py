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
        """List SBOM components for a single scan, consolidated by (name, version).

        Raw rows are deduplicated across scanners so the returned `total` matches
        what the user sees after any client-side dedup. The aggregation mirrors
        `list_across_scans_consolidated` but constrained to one scan_id.
        """
        match_stage: dict[str, Any] = {"scan_id": scan_id}
        if search:
            regex = {"$regex": search, "$options": "i"}
            match_stage["$or"] = [
                {"name": regex},
                {"type": regex},
                {"purl": regex},
                {"licenses": regex},
            ]

        pipeline: list[dict[str, Any]] = [
            {"$match": match_stage},
            {"$group": {
                "_id": {"name": "$name", "version": "$version"},
                "type": {"$first": "$type"},
                "purl": {"$first": "$purl"},
                "cpe": {"$first": "$cpe"},
                "supplier": {"$first": "$supplier"},
                "licenses": {"$addToSet": "$licenses"},
                "provenance_verified": {"$max": "$provenance_verified"},
                "file_paths": {"$addToSet": "$file_path"},
                "scan_id": {"$first": "$scan_id"},
                "target_id": {"$first": "$target_id"},
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
                # $addToSet on array fields produces [[...], [...]] — flatten
                raw_licenses = item.get("licenses", []) or []
                flat: list[str] = []
                for entry in raw_licenses:
                    if isinstance(entry, list):
                        flat.extend(e for e in entry if isinstance(e, str) and e)
                    elif isinstance(entry, str) and entry:
                        flat.append(entry)
                seen: set[str] = set()
                unique_licenses = [lic for lic in flat if not (lic in seen or seen.add(lic))]
                file_paths = sorted({p for p in item.get("file_paths", []) if p})
                items.append({
                    "name": item["_id"]["name"],
                    "version": item["_id"]["version"],
                    "type": item.get("type", ""),
                    "purl": item.get("purl"),
                    "cpe": item.get("cpe"),
                    "supplier": item.get("supplier"),
                    "licenses": unique_licenses,
                    "provenance_verified": item.get("provenance_verified"),
                    "file_paths": file_paths,
                    "scan_id": item.get("scan_id"),
                    "target_id": item.get("target_id"),
                })
            return total, items
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.list_by_scan_failed", scan_id=scan_id, error=str(exc))
            return 0, []

    async def count_by_scan_consolidated(self, scan_id: str) -> int:
        """Count distinct (name, version) SBOM components for a single scan."""
        pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": scan_id}},
            {"$group": {"_id": {"name": "$name", "version": "$version"}}},
            {"$count": "total"},
        ]
        try:
            result = await self.collection.aggregate(pipeline).to_list(1)
            return result[0]["total"] if result else 0
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.count_by_scan_consolidated_failed", scan_id=scan_id, error=str(exc))
            return 0

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

    async def get_consolidated_facets(
        self, scan_ids: list[str]
    ) -> dict[str, list[tuple[str, int]]]:
        """Return ecosystem/license/type counts over consolidated (name+version) components."""
        if not scan_ids:
            return {"ecosystems": [], "licenses": [], "types": []}
        pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": scan_ids}}},
            {"$group": {
                "_id": {"name": "$name", "version": "$version"},
                "type": {"$first": "$type"},
                "purl": {"$first": "$purl"},
                "licenses": {"$first": "$licenses"},
            }},
            {"$facet": {
                "ecosystems": [
                    {"$project": {
                        "eco": {
                            "$cond": [
                                {"$and": [
                                    {"$ne": ["$purl", None]},
                                    {"$regexMatch": {"input": "$purl", "regex": r"^pkg:[^/]+/"}},
                                ]},
                                {"$arrayElemAt": [
                                    {"$split": [{"$substrCP": ["$purl", 4, 1000]}, "/"]},
                                    0,
                                ]},
                                "unknown",
                            ],
                        },
                    }},
                    {"$group": {"_id": "$eco", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                ],
                "licenses": [
                    {"$unwind": {"path": "$licenses", "preserveNullAndEmptyArrays": False}},
                    {"$group": {"_id": "$licenses", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}},
                ],
                "types": [
                    {"$group": {
                        "_id": {"$ifNull": ["$type", "unknown"]},
                        "count": {"$sum": 1},
                    }},
                    {"$sort": {"count": -1}},
                ],
            }},
        ]
        try:
            result = await self.collection.aggregate(pipeline).to_list(1)
            if not result:
                return {"ecosystems": [], "licenses": [], "types": []}
            doc = result[0]
            def _unpack(bucket: list[dict[str, Any]]) -> list[tuple[str, int]]:
                return [(str(b["_id"] or "unknown"), int(b["count"])) for b in bucket]
            return {
                "ecosystems": _unpack(doc.get("ecosystems", [])),
                "licenses": _unpack(doc.get("licenses", [])),
                "types": _unpack(doc.get("types", [])),
            }
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.get_consolidated_facets_failed", error=str(exc))
            return {"ecosystems": [], "licenses": [], "types": []}

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

    async def list_distinct_raw_licenses(self, scan_ids: list[str]) -> list[str]:
        """Return distinct raw license strings across scans.

        SPDX expressions like ``"MIT OR Apache-2.0"`` are returned as a single
        string — splitting into atoms is the caller's responsibility (see
        ``split_spdx_expression`` in ``license_compliance_service``). The
        Licenses-tab badge needs the post-split atom count to match the
        overview page; counting raw strings here would over-report whenever
        a component declared a compound expression.
        """
        if not scan_ids:
            return []
        pipeline: list[dict[str, Any]] = [
            {"$match": {"scan_id": {"$in": scan_ids}}},
            {"$unwind": "$licenses"},
            {"$group": {"_id": "$licenses"}},
        ]
        try:
            cursor = self.collection.aggregate(pipeline)
            out: list[str] = []
            async for doc in cursor:
                value = doc.get("_id")
                if isinstance(value, str) and value.strip():
                    out.append(value)
            return out
        except PyMongoError as exc:
            log.warning("scan_sbom_repository.list_distinct_raw_licenses_failed", error=str(exc))
            return []

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
