from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Callable, Iterable

from dateutil.relativedelta import relativedelta
import structlog
from opensearchpy.exceptions import (
    OpenSearchException,
    RequestError,
    ConnectionError as OSConnectionError,
)

from app.core.config import settings
from app.db.opensearch import async_search
from app.repositories.asset_repository import AssetRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository


log = structlog.get_logger()


class StatsService:
    async def get_overview(self) -> dict[str, Any]:
        vulnerability_stats = await self._fetch_vulnerability_stats()
        asset_stats = await self._fetch_asset_stats()
        return {"vulnerabilities": vulnerability_stats, "assets": asset_stats}

    async def _fetch_vulnerability_stats(self) -> dict[str, Any]:
        now = datetime.now(tz=UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        start = now - relativedelta(months=11)

        try:
            response = await self._run_vulnerability_search(start, now, use_keyword_suffix=False)
        except RequestError as exc:
            if self._is_fielddata_error(exc):
                log.info("stats.retry_keyword_fields")
                try:
                    response = await self._run_vulnerability_search(start, now, use_keyword_suffix=True)
                except (RequestError, OSConnectionError, OpenSearchException) as retry_exc:
                    log.warning("stats.keyword_retry_failed", error=str(retry_exc))
                    return await self._fetch_vulnerability_stats_from_mongo(start, now)
            else:
                log.warning("stats.opensearch_request_error", error=str(exc))
                return await self._fetch_vulnerability_stats_from_mongo(start, now)
        except (OSConnectionError, OpenSearchException) as exc:
            log.warning("stats.opensearch_unavailable", error=str(exc))
            return await self._fetch_vulnerability_stats_from_mongo(start, now)

        aggregations = response.get("aggregations", {}) if isinstance(response, dict) else {}

        total = self._resolve_total(aggregations)
        sources = self._map_terms_aggregation(aggregations.get("sources"))
        top_vendors = self._map_terms_aggregation(aggregations.get("vendors"), limit=10)
        top_products = self._map_terms_aggregation(aggregations.get("products"), limit=10)
        severities = self._map_terms_aggregation(
            aggregations.get("severity"),
            value_transform=lambda value: str(value).upper(),
        )

        timeline_buckets: dict[str, int] = {}
        timeline_agg = aggregations.get("timeline")
        if isinstance(timeline_agg, dict):
            timeline_buckets = self._map_histogram(timeline_agg.get("months"))
        timeline = self._build_timeline_sequence(start, timeline_buckets)

        return {
            "total": total,
            "sources": sources,
            "severities": severities,
            "topVendors": top_vendors,
            "topProducts": top_products,
            "timeline": timeline,
        }

    async def _run_vulnerability_search(
        self,
        start: datetime,
        now: datetime,
        *,
        use_keyword_suffix: bool,
    ) -> dict[str, Any]:
        body = self._build_vulnerability_query(start, now, use_keyword_suffix=use_keyword_suffix)
        return await async_search(
            settings.opensearch_index,
            body,
            suppress_exceptions=False,
        )

    def _build_vulnerability_query(
        self,
        start: datetime,
        now: datetime,
        *,
        use_keyword_suffix: bool,
    ) -> dict[str, Any]:
        def field(name: str) -> str:
            if not use_keyword_suffix or name.endswith(".keyword"):
                return name
            return f"{name}.keyword"

        body = {
            "size": 0,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "must": [{"match_all": {}}],                }
            },
            "aggs": {
                "total_cves": {
                    "filter": {
                        "wildcard": {
                            "vuln_id.keyword": "CVE-*",
                        }
                    },
                    "aggs": {
                        "unique": {
                            "cardinality": {
                                "field": "vuln_id.keyword",
                                "precision_threshold": 40000,
                            }
                        },
                    },
                },
                "total_euvd_non_cve": {
                    "filter": {
                        "bool": {
                            "must": [{"term": {field("source"): "EUVD"}}],
                            "must_not": [{"wildcard": {"vuln_id.keyword": "CVE-*"}}],
                        }
                    },
                    "aggs": {
                        "unique": {
                            "cardinality": {
                                "field": "vuln_id.keyword",
                                "precision_threshold": 40000,
                            }
                        },
                    },
                },
                "sources": {
                    "terms": {
                        "field": field("source"),
                        "size": 10,
                        "missing": "unbekannt",
                    }
                },
                "vendors": {
                    "terms": {
                        "field": field("vendors"),
                        "size": 20,
                    }
                },
                "products": {
                    "terms": {
                        "field": field("products"),
                        "size": 20,
                    }
                },
                "severity": {
                    "terms": {
                        "field": field("cvss.severity"),
                        "size": 10,
                        "missing": "unknown",
                    }
                },
                "timeline": {
                    "filter": {
                        "range": {
                            "published": {
                                "gte": start.isoformat(),
                            }
                        }
                    },
                    "aggs": {
                        "months": {
                            "date_histogram": {
                                "field": "published",
                                "calendar_interval": "month",
                                "min_doc_count": 0,
                                "extended_bounds": {},
                                "format": "yyyy-MM",
                            }
                        }
                    },
                },
            },
        }
        if use_keyword_suffix:
            body["aggs"]["timeline"]["aggs"]["months"]["date_histogram"]["extended_bounds"] = {
                "min": start.strftime("%Y-%m-%dT%H:%M:%S"),
                "max": now.strftime("%Y-%m-%dT%H:%M:%S"),
            }
        else:
            body["aggs"]["timeline"]["aggs"]["months"]["date_histogram"]["extended_bounds"] = {
                "min": start.isoformat(),
                "max": now.isoformat(),
            }

        return body

    @staticmethod
    def _resolve_total(aggregations: dict[str, Any]) -> int:
        total = 0

        cve_bucket = aggregations.get("total_cves")
        if isinstance(cve_bucket, dict):
            unique = cve_bucket.get("unique")
            if isinstance(unique, dict):
                value = unique.get("value")
                if isinstance(value, (int, float)):
                    total += int(value)

        euvd_bucket = aggregations.get("total_euvd_non_cve")
        if isinstance(euvd_bucket, dict):
            unique = euvd_bucket.get("unique")
            if isinstance(unique, dict):
                value = unique.get("value")
                if isinstance(value, (int, float)):
                    total += int(value)

        return total

    @staticmethod
    def _is_fielddata_error(error: RequestError) -> bool:
        message = str(error).lower()
        if "fielddata" in message and "text" in message:
            return True
        info = getattr(error, "info", None)
        if isinstance(info, dict):
            reason = StatsService._extract_reason(info)
            if isinstance(reason, str) and "fielddata" in reason.lower():
                return True
        return False

    @staticmethod
    def _extract_reason(info: dict[str, Any]) -> str | None:
        error = info.get("error")
        if isinstance(error, dict):
            reason = error.get("reason")
            if isinstance(reason, str):
                return reason
            caused_by = error.get("caused_by")
            if isinstance(caused_by, dict):
                cb_reason = caused_by.get("reason")
                if isinstance(cb_reason, str):
                    return cb_reason
        return None

    async def _fetch_vulnerability_stats_from_mongo(self, start: datetime, now: datetime) -> dict[str, Any]:
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

        timeline_map: dict[str, int] = {
            row.get("_id"): int(row.get("count", 0))
            for row in timeline_raw
            if isinstance(row, dict)
        }

        timeline: list[dict[str, Any]] = []
        month_cursor = start
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
    def _map_terms_aggregation(
        aggregation: dict[str, Any] | None,
        *,
        limit: int | None = None,
        value_transform: Callable[[Any], Any] | None = None,
    ) -> list[dict[str, Any]]:
        if not isinstance(aggregation, dict):
            return []

        buckets = aggregation.get("buckets")
        if not isinstance(buckets, Iterable):
            return []

        results: list[dict[str, Any]] = []
        for bucket in buckets:
            if not isinstance(bucket, dict):
                continue

            raw_key = bucket.get("key_as_string", bucket.get("key"))
            if raw_key is None:
                continue

            key = raw_key
            if isinstance(key, str):
                key = key.strip()
                if not key or key.lower() in {"n/a", "na"}:
                    continue

            if value_transform is not None:
                key = value_transform(key)

            count = bucket.get("doc_count", 0)
            if not isinstance(count, (int, float)):
                continue

            results.append({"key": key, "doc_count": int(count)})

            if limit is not None and len(results) >= limit:
                break

        return results

    @staticmethod
    def _map_histogram(aggregation: dict[str, Any] | None) -> dict[str, int]:
        if not isinstance(aggregation, dict):
            return {}
        buckets = aggregation.get("buckets")
        if not isinstance(buckets, Iterable):
            return {}

        values: dict[str, int] = {}
        for bucket in buckets:
            if not isinstance(bucket, dict):
                continue

            key = bucket.get("key_as_string")
            if isinstance(key, str) and key:
                month_key = key[:7]
            else:
                raw_key = bucket.get("key")
                if isinstance(raw_key, (int, float)):
                    month_key = datetime.fromtimestamp(raw_key / 1000, tz=UTC).strftime("%Y-%m")
                else:
                    continue

            count = bucket.get("doc_count", 0)
            if not isinstance(count, (int, float)):
                continue

            values[month_key] = int(count)

        return values

    @staticmethod
    def _build_timeline_sequence(start: datetime, bucket_map: dict[str, int]) -> list[dict[str, Any]]:
        timeline: list[dict[str, Any]] = []
        month_cursor = start
        for _ in range(12):
            month_key = month_cursor.strftime("%Y-%m")
            timeline.append({"key": month_key, "count": bucket_map.get(month_key, 0)})
            month_cursor = month_cursor + relativedelta(months=1)
        return timeline

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
