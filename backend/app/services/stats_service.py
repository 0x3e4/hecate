from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from dateutil.relativedelta import relativedelta

from app.repositories.asset_repository import AssetRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository


class StatsService:
    async def get_overview(self) -> dict[str, Any]:
        vulnerability_stats = await self._fetch_vulnerability_stats()
        asset_stats = await self._fetch_asset_stats()
        return {"vulnerabilities": vulnerability_stats, "assets": asset_stats}

    async def _fetch_vulnerability_stats(self) -> dict[str, Any]:
        repository = await VulnerabilityRepository.create()
        collection = repository.collection

        total = await collection.count_documents({})

        sources_pipeline = [
            {
                "$group": {
                    "_id": {"$ifNull": ["$source", "unbekannt"]},
                    "count": {"$sum": 1},
                }
            },
            {"$sort": {"count": -1, "_id": 1}},
            {"$limit": 10},
        ]
        sources_raw = await collection.aggregate(sources_pipeline).to_list(length=10)
        sources = self._map_group_results(sources_raw)

        vendors_pipeline = [
            {"$unwind": "$vendors"},
            {"$match": {"vendors": {"$nin": [None, "", "*"]}}},
            {"$group": {"_id": "$vendors", "count": {"$sum": 1}}},
            {"$sort": {"count": -1, "_id": 1}},
            {"$limit": 10},
        ]
        vendor_raw = await collection.aggregate(vendors_pipeline).to_list(length=10)
        top_vendors = self._map_group_results(vendor_raw)

        products_pipeline = [
            {"$unwind": "$products"},
            {"$match": {"products": {"$nin": [None, "", "*"]}}},
            {"$group": {"_id": "$products", "count": {"$sum": 1}}},
            {"$sort": {"count": -1, "_id": 1}},
            {"$limit": 10},
        ]
        product_raw = await collection.aggregate(products_pipeline).to_list(length=10)
        top_products = self._map_group_results(product_raw)

        severity_pipeline = [
            {
                "$project": {
                    "severity": {
                        "$toUpper": {"$ifNull": ["$cvss.severity", "UNKNOWN"]},
                    }
                }
            },
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            {"$sort": {"count": -1, "_id": 1}},
        ]
        severity_raw = await collection.aggregate(severity_pipeline).to_list(length=10)
        severities = self._map_group_results(severity_raw)

        now = datetime.now(tz=UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        start = (now - relativedelta(months=11))
        timeline_pipeline = [
            {
                "$addFields": {
                    "publishedDate": {
                        "$cond": [
                            {"$in": [{"$type": "$published"}, ["date", "timestamp"]]},
                            "$published",
                            {
                                "$convert": {
                                    "input": "$published",
                                    "to": "date",
                                    "onError": None,
                                    "onNull": None,
                                }
                            },
                        ]
                    }
                }
            },
            {"$match": {"publishedDate": {"$ne": None, "$gte": start}}},
            {
                "$project": {
                    "month": {
                        "$dateToString": {
                            "format": "%Y-%m",
                            "date": "$publishedDate",
                            "timezone": "UTC",
                        }
                    }
                }
            },
            {"$group": {"_id": "$month", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}},
        ]
        timeline_raw = await collection.aggregate(timeline_pipeline).to_list(length=200)

        month_cursor = start
        timeline_map: dict[str, int] = {row.get("_id"): int(row.get("count", 0)) for row in timeline_raw if isinstance(row, dict)}
        timeline: list[dict[str, Any]] = []
        for _ in range(12):
            month_key = month_cursor.strftime("%Y-%m")
            timeline.append({"key": month_key, "count": timeline_map.get(month_key, 0)})
            month_cursor = month_cursor + relativedelta(months=1)

        return {
            "total": total,
            "sources": sources,
            "severities": severities,
            "topVendors": top_vendors,
            "topProducts": top_products,
            "timeline": timeline,
        }

    async def _fetch_asset_stats(self) -> dict[str, Any]:
        repository = await AssetRepository.create()
        vendor_total = await repository.vendors.count_documents({})
        product_total = await repository.products.count_documents({})
        version_total = await repository.versions.count_documents({})

        vendor_samples = await repository.sample_vendors(limit=6)
        product_samples = await repository.sample_products(limit=6)

        def _simplify_sample(item: dict[str, Any]) -> dict[str, Any]:
            name = (
                item.get("name")
                or item.get("displayName")
                or item.get("_id")
                or "—"
            )
            return {
                "slug": item.get("slug") or item.get("_id"),
                "name": name,
                "aliases": item.get("aliases", [])[:3],
            }

        return {
            "vendorTotal": vendor_total,
            "productTotal": product_total,
            "versionTotal": version_total,
            "sampleVendors": [_simplify_sample(item) for item in vendor_samples],
            "sampleProducts": [_simplify_sample(item) for item in product_samples],
        }

    @staticmethod
    def _map_group_results(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for doc in documents:
            key = doc.get("_id")
            if key is None:
                continue
            if isinstance(key, str) and key.strip().lower() in {"n/a", "na"}:
                continue
            results.append({
                "key": key,
                "doc_count": int(doc.get("count", 0)),
            })
        return results


def get_stats_service() -> StatsService:
    return StatsService()
