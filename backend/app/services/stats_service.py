from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
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


class StatsCache:
    """Simple in-memory cache for stats data."""

    def __init__(self, ttl_seconds: int = 300):  # 5 minutes default
        self._cache: dict[str, tuple[datetime, Any]] = {}
        self._ttl = timedelta(seconds=ttl_seconds)

    def get(self, key: str) -> Any | None:
        if key not in self._cache:
            return None

        timestamp, value = self._cache[key]
        if datetime.now(tz=UTC) - timestamp > self._ttl:
            del self._cache[key]
            return None

        return value

    def set(self, key: str, value: Any) -> None:
        self._cache[key] = (datetime.now(tz=UTC), value)

    def clear(self) -> None:
        self._cache.clear()


# Global cache instance with longer TTL (15 minutes instead of 5)
# Stats data doesn't change frequently, so longer cache is acceptable
_stats_cache = StatsCache(ttl_seconds=900)


class StatsService:
    async def get_overview(self) -> dict[str, Any]:
        # Check cache first
        cached = _stats_cache.get("overview")

        if cached is not None:
            log.info("stats.cache_hit")
            # Refresh asset samples even when cached to show random vendors/products
            cached_copy = cached.copy()
            try:
                fresh_asset_samples = await self._fetch_fresh_asset_samples()
                cached_copy["assets"]["sampleVendors"] = fresh_asset_samples["sampleVendors"]
                cached_copy["assets"]["sampleProducts"] = fresh_asset_samples["sampleProducts"]
            except Exception as e:
                log.warning("stats.fresh_samples_failed", error=str(e))
                # Return cached version if fresh samples fail
            return cached_copy

        # Add timeout protection to prevent hanging requests
        try:
            # Run both queries in parallel with 30 second timeout
            vulnerability_stats, asset_stats = await asyncio.wait_for(
                asyncio.gather(
                    self._fetch_vulnerability_stats(),
                    self._fetch_asset_stats(),
                ),
                timeout=30.0,
            )
        except asyncio.TimeoutError:
            log.error("stats.timeout", timeout_seconds=30)
            # Return minimal fallback data on timeout
            return {
                "vulnerabilities": {
                    "total": 0,
                    "sources": [],
                    "severities": [],
                    "topVendors": [],
                    "topProducts": [],
                    "timeline": [],
                },
                "assets": {
                    "vendorTotal": 0,
                    "productTotal": 0,
                    "versionTotal": 0,
                    "sampleVendors": [],
                    "sampleProducts": [],
                },
            }

        result = {"vulnerabilities": vulnerability_stats, "assets": asset_stats}

        # Cache the result
        _stats_cache.set("overview", result)
        log.info("stats.cache_set")

        return result

    async def _fetch_fresh_asset_samples(self) -> dict[str, Any]:
        """Fetch fresh random asset samples quickly without hitting cache."""
        repository = await AssetRepository.create()
        vendor_samples, product_samples = await asyncio.gather(
            repository.sample_vendors(limit=6),
            repository.sample_products(limit=6),
        )

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
            "sampleVendors": [_simplify_sample(item) for item in vendor_samples],
            "sampleProducts": [_simplify_sample(item) for item in product_samples],
        }

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
        except (OSConnectionError, OpenSearchException, asyncio.TimeoutError) as exc:
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
                                "precision_threshold": 10000,  # Reduced from 40000 for better performance
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
                                "precision_threshold": 10000,  # Reduced from 40000 for better performance
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
                        "size": 10,  # Reduced from 20 to 10 for better performance
                    }
                },
                "products": {
                    "terms": {
                        "field": field("products"),
                        "size": 10,  # Reduced from 20 to 10 for better performance
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
                                "gte": int(start.timestamp() * 1000),
                            }
                        }
                    },
                    "aggs": {
                        "months": {
                            "date_histogram": {
                                "field": "published",
                                "calendar_interval": "month",
                                "min_doc_count": 0,
                                "format": "yyyy-MM",
                            }
                        }
                    },
                },
            },
        }
        # Use timestamp in milliseconds for extended_bounds to avoid date format issues
        body["aggs"]["timeline"]["aggs"]["months"]["date_histogram"]["extended_bounds"] = {
            "min": int(start.timestamp() * 1000),
            "max": int(now.timestamp() * 1000),
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
        """
        Fast MongoDB fallback with minimal aggregations.
        When OpenSearch fails/times out, we prioritize speed over completeness.
        """
        repository = await VulnerabilityRepository.create()
        collection = repository.collection

        # Only run the fastest queries - skip expensive aggregations
        sources_pipeline = [
            {
                "$group": {
                    "_id": {"$ifNull": ["$source", "unbekannt"]},
                    "count": {"$sum": 1},
                }
            },
            {"$sort": {"count": -1, "_id": 1}},
            {"$limit": 5},  # Reduced to 5 for speed
        ]

        severity_pipeline = [
            {
                "$group": {
                    "_id": {"$ifNull": ["$cvss.severity", "UNKNOWN"]},
                    "count": {"$sum": 1},
                }
            },
            {"$sort": {"count": -1, "_id": 1}},
            {"$limit": 5},
        ]

        # Run only essential aggregations in parallel with timeout
        try:
            total, sources_raw, severity_raw = await asyncio.wait_for(
                asyncio.gather(
                    collection.estimated_document_count(),
                    collection.aggregate(sources_pipeline).to_list(length=5),
                    collection.aggregate(severity_pipeline).to_list(length=5),
                ),
                timeout=5.0,  # 5 second timeout for fallback
            )

            sources = self._map_group_results(sources_raw)
            severities = [
                {"key": doc.get("_id", "UNKNOWN").upper(), "doc_count": int(doc.get("count", 0))}
                for doc in severity_raw
                if doc.get("_id")
            ]

        except asyncio.TimeoutError:
            log.warning("stats.mongo_fallback_timeout")
            total = 0
            sources = []
            severities = []

        # Return minimal data - skip expensive vendors/products/timeline
        return {
            "total": total,
            "sources": sources,
            "severities": severities,
            "topVendors": [],  # Skip expensive aggregation
            "topProducts": [],  # Skip expensive aggregation
            "timeline": [],  # Skip expensive aggregation
        }

    async def _fetch_asset_stats(self) -> dict[str, Any]:
        repository = await AssetRepository.create()

        # Run all queries in parallel for better performance
        # Note: counts are cached but samples are always fresh (random)
        (
            vendor_total,
            product_total,
            version_total,
        ) = await asyncio.gather(
            repository.vendors.count_documents({}),
            repository.products.count_documents({}),
            repository.versions.count_documents({}),
        )

        # Fetch samples separately to get fresh random samples each time
        # (not affected by cache since they change on every request)
        vendor_samples, product_samples = await asyncio.gather(
            repository.sample_vendors(limit=6),
            repository.sample_products(limit=6),
        )

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
