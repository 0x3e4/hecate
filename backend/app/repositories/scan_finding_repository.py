from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo.errors import PyMongoError

from app.core.config import settings
from app.db.mongo import get_database
from app.models.scan import ScanFindingDocument

log = structlog.get_logger()


class ScanFindingRepository:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self.collection = collection

    @classmethod
    async def create(cls) -> "ScanFindingRepository":
        database = await get_database()
        collection = database[settings.mongo_scan_findings_collection]
        await collection.create_index("scan_id")
        await collection.create_index("target_id")
        await collection.create_index("vulnerability_id")
        await collection.create_index("severity")
        await collection.create_index("vex_status", sparse=True)
        return cls(collection)

    async def bulk_insert(self, findings: list[ScanFindingDocument]) -> int:
        """Insert multiple findings. Returns count of inserted documents."""
        if not findings:
            return 0
        payloads = [f.model_dump(mode="python") for f in findings]
        try:
            result = await self.collection.insert_many(payloads, ordered=False)
            return len(result.inserted_ids)
        except PyMongoError as exc:
            log.warning("scan_finding_repository.bulk_insert_failed", count=len(findings), error=str(exc))
            return 0

    async def list_by_scan(
        self,
        scan_id: str,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        query: dict[str, Any] = {"scan_id": scan_id}
        if severity:
            query["severity"] = severity

        try:
            total = await self.collection.count_documents(query)
            cursor = (
                self.collection.find(query)
                .sort([("severity", 1), ("package_name", 1)])
                .skip(offset)
                .limit(limit)
            )
            items = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                items.append(doc)
            return total, items
        except PyMongoError as exc:
            log.warning("scan_finding_repository.list_by_scan_failed", scan_id=scan_id, error=str(exc))
            return 0, []

    async def count_by_severity(self, scan_id: str) -> dict[str, int]:
        """Return severity counts for a scan."""
        try:
            pipeline = [
                {"$match": {"scan_id": scan_id}},
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            ]
            counts: dict[str, int] = {}
            async for doc in self.collection.aggregate(pipeline):
                sev = doc.get("_id", "unknown")
                counts[sev.lower() if isinstance(sev, str) else "unknown"] = doc.get("count", 0)
            return counts
        except PyMongoError as exc:
            log.warning("scan_finding_repository.count_by_severity_failed", scan_id=scan_id, error=str(exc))
            return {}

    async def find_by_cve(
        self, vulnerability_id: str, limit: int = 50, offset: int = 0
    ) -> tuple[int, list[dict[str, Any]]]:
        """Find scan findings that match a specific CVE ID."""
        query = {"vulnerability_id": vulnerability_id}
        try:
            total = await self.collection.count_documents(query)
            cursor = (
                self.collection.find(query)
                .sort("created_at", -1)
                .skip(offset)
                .limit(limit)
            )
            items = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                items.append(doc)
            return total, items
        except PyMongoError as exc:
            log.warning("scan_finding_repository.find_by_cve_failed", cve=vulnerability_id, error=str(exc))
            return 0, []

    async def update_vulnerability_id(
        self,
        scan_id: str,
        package_name: str,
        package_version: str,
        vulnerability_id: str,
        matched_from: str = "auto",
    ) -> int:
        """Update vulnerability_id for findings matching scan+package."""
        try:
            result = await self.collection.update_many(
                {
                    "scan_id": scan_id,
                    "package_name": package_name,
                    "package_version": package_version,
                    "vulnerability_id": None,
                },
                {"$set": {"vulnerability_id": vulnerability_id, "matched_from": matched_from}},
            )
            return result.modified_count
        except PyMongoError as exc:
            log.warning("scan_finding_repository.update_vuln_id_failed", scan_id=scan_id, error=str(exc))
            return 0

    async def update_fix_version(
        self, scan_id: str, package_name: str, package_version: str, fix_version: str | None
    ) -> int:
        """Update fix_version for all findings matching scan+package+version."""
        try:
            result = await self.collection.update_many(
                {"scan_id": scan_id, "package_name": package_name, "package_version": package_version},
                {"$set": {"fix_version": fix_version}},
            )
            return result.modified_count
        except PyMongoError as exc:
            log.warning("scan_finding_repository.update_fix_version_failed", scan_id=scan_id, error=str(exc))
            return 0

    async def list_across_scans_consolidated(
        self,
        scan_ids: list[str],
        search: str | None = None,
        severity: str | None = None,
        sort_by: str = "cvss_score",
        sort_order: str = "desc",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        """List findings across scans, consolidated by vulnerability+package+version."""
        if not scan_ids:
            return 0, []
        match_stage: dict[str, Any] = {
            "scan_id": {"$in": scan_ids},
            "package_type": {"$nin": ["malicious-indicator", "compliance-check", "sast-finding", "secret-finding"]},
        }
        if search:
            regex = {"$regex": search, "$options": "i"}
            match_stage["$or"] = [
                {"vulnerability_id": regex},
                {"package_name": regex},
                {"title": regex},
            ]
        if severity:
            match_stage["severity"] = severity

        # Build sort specification
        allowed_sort_fields: dict[str, str] = {
            "cvss_score": "cvss_score",
            "severity": "severity",
            "package_name": "_id.package_name",
            "package_version": "_id.package_version",
            "vulnerability_id": "_id.vulnerability_id",
            "fix_version": "fix_version",
            "targets": "target_count",
        }
        sort_field = allowed_sort_fields.get(sort_by, "cvss_score")
        direction = -1 if sort_order == "desc" else 1

        pipeline: list[dict[str, Any]] = [
            {"$match": match_stage},
            {"$group": {
                "_id": {
                    "vulnerability_id": "$vulnerability_id",
                    "package_name": "$package_name",
                    "package_version": "$package_version",
                },
                "severity": {"$first": "$severity"},
                "fix_version": {"$first": "$fix_version"},
                "fix_state": {"$first": "$fix_state"},
                "title": {"$first": "$title"},
                "scanners": {"$addToSet": "$scanner"},
                "targets": {"$addToSet": {"target_id": "$target_id", "scan_id": "$scan_id"}},
                "cvss_score": {"$max": "$cvss_score"},
                "urls": {"$first": "$urls"},
            }},
            {"$addFields": {"target_count": {"$size": "$targets"}}},
            {"$sort": {sort_field: direction, "_id.package_name": 1}},
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
                    "vulnerability_id": item["_id"]["vulnerability_id"],
                    "package_name": item["_id"]["package_name"],
                    "package_version": item["_id"]["package_version"],
                    "severity": item["severity"],
                    "fix_version": item.get("fix_version"),
                    "fix_state": item.get("fix_state", "unknown"),
                    "title": item.get("title"),
                    "scanners": sorted(item.get("scanners", [])),
                    "targets": item.get("targets", []),
                    "cvss_score": item.get("cvss_score"),
                    "urls": item.get("urls", []),
                })
            return total, items
        except PyMongoError as exc:
            log.warning("scan_finding_repository.list_across_scans_consolidated_failed", error=str(exc))
            return 0, []

    async def delete_by_scan(self, scan_id: str) -> int:
        try:
            result = await self.collection.delete_many({"scan_id": scan_id})
            return result.deleted_count
        except PyMongoError as exc:
            log.warning("scan_finding_repository.delete_by_scan_failed", scan_id=scan_id, error=str(exc))
            return 0

    async def delete_by_target(self, target_id: str) -> int:
        try:
            result = await self.collection.delete_many({"target_id": target_id})
            return result.deleted_count
        except PyMongoError as exc:
            log.warning("scan_finding_repository.delete_by_target_failed", target_id=target_id, error=str(exc))
            return 0

    # --- VEX methods ---

    async def update_vex_status(
        self,
        finding_id: str,
        vex_status: str,
        vex_justification: str | None = None,
        vex_detail: str | None = None,
        vex_response: list[str] | None = None,
        vex_updated_by: str = "user",
    ) -> bool:
        """Update VEX status on a single finding."""
        try:
            update: dict[str, Any] = {
                "vex_status": vex_status,
                "vex_justification": vex_justification,
                "vex_detail": vex_detail,
                "vex_response": vex_response,
                "vex_updated_at": datetime.now(tz=UTC),
                "vex_updated_by": vex_updated_by,
            }
            result = await self.collection.update_one(
                {"_id": ObjectId(finding_id)},
                {"$set": update},
            )
            return result.modified_count > 0
        except PyMongoError as exc:
            log.warning("scan_finding_repository.update_vex_failed", finding_id=finding_id, error=str(exc))
            return False

    async def bulk_update_vex_by_vulnerability(
        self,
        target_id: str,
        vulnerability_id: str,
        vex_status: str,
        vex_justification: str | None = None,
        vex_updated_by: str = "user",
    ) -> int:
        """Apply VEX status to all findings matching vulnerability+target across scans."""
        try:
            update: dict[str, Any] = {
                "vex_status": vex_status,
                "vex_justification": vex_justification,
                "vex_updated_at": datetime.now(tz=UTC),
                "vex_updated_by": vex_updated_by,
            }
            result = await self.collection.update_many(
                {"target_id": target_id, "vulnerability_id": vulnerability_id},
                {"$set": update},
            )
            return result.modified_count
        except PyMongoError as exc:
            log.warning("scan_finding_repository.bulk_update_vex_failed", error=str(exc))
            return 0

    async def get_vex_findings_by_scan(self, scan_id: str) -> list[dict[str, Any]]:
        """Get all findings with VEX annotations for a scan."""
        try:
            cursor = self.collection.find(
                {"scan_id": scan_id, "vex_status": {"$ne": None}},
            ).sort("vulnerability_id", 1)
            items: list[dict[str, Any]] = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                items.append(doc)
            return items
        except PyMongoError as exc:
            log.warning("scan_finding_repository.get_vex_findings_failed", scan_id=scan_id, error=str(exc))
            return []

    async def carry_forward_vex(self, old_scan_id: str, new_scan_id: str) -> int:
        """Copy VEX annotations from old scan findings to matching new scan findings."""
        try:
            old_vex = await self.get_vex_findings_by_scan(old_scan_id)
            if not old_vex:
                return 0

            carried = 0
            for old_finding in old_vex:
                vuln_id = old_finding.get("vulnerability_id")
                pkg_name = old_finding.get("package_name")
                if not vuln_id or not pkg_name:
                    continue

                result = await self.collection.update_many(
                    {
                        "scan_id": new_scan_id,
                        "vulnerability_id": vuln_id,
                        "package_name": pkg_name,
                        "vex_status": None,
                    },
                    {"$set": {
                        "vex_status": old_finding.get("vex_status"),
                        "vex_justification": old_finding.get("vex_justification"),
                        "vex_detail": old_finding.get("vex_detail"),
                        "vex_response": old_finding.get("vex_response"),
                        "vex_updated_at": old_finding.get("vex_updated_at"),
                        "vex_updated_by": "carry-forward",
                    }},
                )
                carried += result.modified_count
            return carried
        except PyMongoError as exc:
            log.warning("scan_finding_repository.carry_forward_vex_failed", error=str(exc))
            return 0
