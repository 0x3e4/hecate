from __future__ import annotations

from typing import Any

from app.core.config import settings
from app.db.opensearch import async_search
from app.repositories.cpe_repository import CPERepository


class StatsService:
    async def get_overview(self) -> dict[str, Any]:
        vulnerability_stats = await self._fetch_vulnerability_stats()
        cpe_stats = await self._fetch_cpe_stats()
        return {"vulnerabilities": vulnerability_stats, "cpe": cpe_stats}

    async def _fetch_vulnerability_stats(self) -> dict[str, Any]:
        query = {
            "size": 0,
            "track_total_hits": True,
            "aggs": {
                "by_source": {
                    "terms": {
                        "field": "source",
                        "missing": "unbekannt",
                        "size": 10,
                    }
                },
                "by_vendor": {
                    "terms": {
                        "field": "vendors",
                        "size": 10,
                    }
                },
                "by_product": {
                    "terms": {
                        "field": "products",
                        "size": 10,
                    }
                },
            },
        }
        response = await async_search(settings.opensearch_index, query)
        total = response.get("hits", {}).get("total", {}).get("value", 0)
        aggs = response.get("aggregations", {})
        return {
            "total": total,
            "by_source": aggs.get("by_source", {}).get("buckets", []),
            "top_vendors": aggs.get("by_vendor", {}).get("buckets", []),
            "top_products": aggs.get("by_product", {}).get("buckets", []),
        }

    async def _fetch_cpe_stats(self) -> dict[str, Any]:
        repo = await CPERepository.create()
        total = await repo.collection.count_documents({})
        vendor_count = await repo.collection.aggregate(
            [
                {"$match": {"vendor": {"$nin": [None, "", "*"]}}},
                {"$group": {"_id": "$vendor"}},
                {"$count": "total"},
            ]
        ).to_list(length=1)
        product_count = await repo.collection.aggregate(
            [
                {"$match": {"product": {"$nin": [None, "", "*"]}}},
                {"$group": {"_id": "$product"}},
                {"$count": "total"},
            ]
        ).to_list(length=1)
        return {
            "total": total,
            "vendors": vendor_count[0]["total"] if vendor_count else 0,
            "products": product_count[0]["total"] if product_count else 0,
        }


def get_stats_service() -> StatsService:
    return StatsService()
