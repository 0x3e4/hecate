from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, Callable, Iterable
from urllib.parse import urlparse

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
                    "topCwes": [],
                    "epssRanges": [],
                    "timeline": [],
                    "timelineSummary": [],
                    "topAssigners": [],
                    "exploitedCount": 0,
                    "referenceDomains": [],
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

        return result

    async def _fetch_vulnerability_stats(self) -> dict[str, Any]:
        now = datetime.now(tz=UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        start_30_days = now - relativedelta(days=30)

        try:
            response = await self._run_vulnerability_search(
                start_30_days=start_30_days,
                use_keyword_suffix=False,
            )
        except RequestError as exc:
            if self._is_fielddata_error(exc):
                log.info("stats.retry_keyword_fields")
                try:
                    response = await self._run_vulnerability_search(
                        start_30_days=start_30_days,
                        use_keyword_suffix=True,
                    )
                except (RequestError, OSConnectionError, OpenSearchException) as retry_exc:
                    log.warning("stats.keyword_retry_failed", error=str(retry_exc))
                    return await self._fetch_vulnerability_stats_from_mongo()
            elif self._is_nested_path_error(exc):
                log.warning("stats.nested_path_error", error=str(exc))
                return await self._fetch_vulnerability_stats_from_mongo()
            else:
                log.warning("stats.opensearch_request_error", error=str(exc))
                return await self._fetch_vulnerability_stats_from_mongo()
        except (OSConnectionError, OpenSearchException, asyncio.TimeoutError) as exc:
            log.warning("stats.opensearch_unavailable", error=str(exc))
            return await self._fetch_vulnerability_stats_from_mongo()

        aggregations = response.get("aggregations", {}) if isinstance(response, dict) else {}

        total = self._resolve_total(response)
        # Sources is a nested aggregation, need to unwrap it
        sources_agg = aggregations.get("sources")
        if isinstance(sources_agg, dict):
            sources = self._map_terms_aggregation(sources_agg.get("source_names"))
        else:
            sources = []
        top_vendors = self._map_terms_aggregation(aggregations.get("vendors"), limit=10)
        top_products = self._map_terms_aggregation(aggregations.get("products"), limit=10)
        severities = self._map_terms_aggregation(
            aggregations.get("severity"),
            value_transform=lambda value: str(value).upper(),
        )
        top_cwes = self._map_terms_aggregation(aggregations.get("cwes"), limit=5)

        # EPSS ranges are wrapped in a filter aggregation
        epss_agg = aggregations.get("epss_ranges")
        if isinstance(epss_agg, dict):
            epss_ranges = self._map_range_aggregation(epss_agg.get("ranges"))
        else:
            epss_ranges = []

        # 30-day detailed timeline (nested under filter)
        timeline: list[dict[str, Any]] = []
        timeline_agg = aggregations.get("timeline")
        if isinstance(timeline_agg, dict):
            days_agg = timeline_agg.get("days")
            if isinstance(days_agg, dict):
                timeline = self._map_daily_histogram(days_agg)

        # All-time monthly summary
        timeline_summary: list[dict[str, Any]] = []
        summary_agg = aggregations.get("timeline_summary")
        if isinstance(summary_agg, dict):
            timeline_summary = self._map_monthly_histogram(summary_agg)

        # Top assigners
        top_assigners = self._map_terms_aggregation(aggregations.get("assigners"), limit=10)

        # Exploited count
        exploited_agg = aggregations.get("exploited")
        exploited_count = 0
        if isinstance(exploited_agg, dict):
            exploited_count = exploited_agg.get("doc_count", 0)

        # Reference domains - extract domains from full URLs
        raw_refs = self._map_terms_aggregation(aggregations.get("reference_domains"), limit=100)
        reference_domains = self._extract_domain_counts(raw_refs)

        return {
            "total": total,
            "sources": sources,
            "severities": severities,
            "topVendors": top_vendors,
            "topProducts": top_products,
            "topCwes": top_cwes,
            "epssRanges": epss_ranges,
            "timeline": timeline,
            "timelineSummary": timeline_summary,
            "topAssigners": top_assigners,
            "exploitedCount": exploited_count,
            "referenceDomains": reference_domains,
        }

    async def _run_vulnerability_search(
        self,
        *,
        start_30_days: datetime,
        use_keyword_suffix: bool,
    ) -> dict[str, Any]:
        body = self._build_vulnerability_query(
            start_30_days=start_30_days,
            use_keyword_suffix=use_keyword_suffix,
        )
        return await async_search(
            settings.opensearch_index,
            body,
            suppress_exceptions=False,
        )

    def _build_vulnerability_query(
        self,
        *,
        start_30_days: datetime,
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
                    "must": [{"match_all": {}}],
                }
            },
            "aggs": {
                "sources": {
                    "nested": {
                        "path": "sources"
                    },
                    "aggs": {
                        "source_names": {
                            "terms": {
                                "field": "sources.source",
                                "size": 10,
                            }
                        }
                    }
                },
                "vendors": {
                    "terms": {
                        "field": field("vendors"),
                        "size": 10,
                    }
                },
                "products": {
                    "terms": {
                        "field": field("products"),
                        "size": 10,
                    }
                },
                "severity": {
                    "terms": {
                        "field": field("cvss.severity"),
                        "size": 10,
                        "missing": "unknown",
                    }
                },
                "cwes": {
                    "terms": {
                        "field": field("cwes"),
                        "size": 5,
                        "exclude": ["NVD-CWE-noinfo", "NVD-CWE-Other"],
                    }
                },
                "epss_ranges": {
                    "filter": {
                        "exists": {
                            "field": "epssScore"
                        }
                    },
                    "aggs": {
                        "ranges": {
                            "range": {
                                "field": "epssScore",
                                "ranges": [
                                    {"key": "0.0-0.1", "from": 0.0, "to": 0.1},
                                    {"key": "0.1-0.3", "from": 0.1, "to": 0.3},
                                    {"key": "0.3-0.5", "from": 0.3, "to": 0.5},
                                    {"key": "0.5-0.7", "from": 0.5, "to": 0.7},
                                    {"key": "0.7-1.0", "from": 0.7, "to": 1.0},
                                ],
                                "keyed": True,
                            }
                        }
                    }
                },
                # Last 30 days - daily granularity
                "timeline": {
                    "filter": {
                        "range": {
                            "published": {
                                "gte": int(start_30_days.timestamp() * 1000),
                            }
                        }
                    },
                    "aggs": {
                        "days": {
                            "date_histogram": {
                                "field": "published",
                                "calendar_interval": "day",
                                "min_doc_count": 0,
                                "format": "yyyy-MM-dd",
                            }
                        }
                    }
                },
                # All-time monthly summary
                "timeline_summary": {
                    "date_histogram": {
                        "field": "published",
                        "calendar_interval": "month",
                        "min_doc_count": 0,
                        "format": "yyyy-MM",
                    }
                },
                # Top assigners
                "assigners": {
                    "terms": {
                        "field": field("assigner"),
                        "size": 10,
                    }
                },
                # Exploited vulnerabilities count
                "exploited": {
                    "filter": {
                        "term": {
                            "exploited": True
                        }
                    }
                },
                # Reference domains (extract domain from URLs)
                "reference_domains": {
                    "terms": {
                        "field": field("references"),
                        "size": 100,
                    }
                },
            },
        }

        return body

    @staticmethod
    def _resolve_total(response: dict[str, Any]) -> int:
        """Get total document count from OpenSearch response.

        Uses track_total_hits for accurate count instead of cardinality aggregations
        which can undercount due to approximation algorithms.
        """
        hits = response.get("hits")
        if isinstance(hits, dict):
            total = hits.get("total")
            if isinstance(total, dict):
                value = total.get("value")
                if isinstance(value, (int, float)):
                    return int(value)
            elif isinstance(total, (int, float)):
                return int(total)

        return 0

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
    def _is_nested_path_error(error: RequestError) -> bool:
        """Check if error is due to nested path mapping mismatch."""
        message = str(error).lower()
        if "nested" in message and "is not nested" in message:
            return True
        info = getattr(error, "info", None)
        if isinstance(info, dict):
            reason = StatsService._extract_reason(info)
            if isinstance(reason, str) and "is not nested" in reason.lower():
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

    async def _fetch_vulnerability_stats_from_mongo(self) -> dict[str, Any]:
        """
        Fast MongoDB fallback with minimal aggregations.
        When OpenSearch fails/times out, we prioritize speed over completeness.
        """
        repository = await VulnerabilityRepository.create()
        collection = repository.collection

        # Only run the fastest queries - skip expensive aggregations
        # Use sources array if available, fall back to source field
        sources_pipeline = [
            {"$unwind": {"path": "$sources", "preserveNullAndEmptyArrays": True}},
            {
                "$group": {
                    "_id": {"$ifNull": ["$sources.source", "$source"]},
                    "count": {"$sum": 1},
                }
            },
            {"$match": {"_id": {"$ne": None}}},  # Filter out null
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

        cwes_pipeline = [
            {"$unwind": {"path": "$cwes", "preserveNullAndEmptyArrays": False}},
            {"$match": {"cwes": {"$nin": ["NVD-CWE-noinfo", "NVD-CWE-Other"]}}},
            {
                "$group": {
                    "_id": "$cwes",
                    "count": {"$sum": 1},
                }
            },
            {"$sort": {"count": -1, "_id": 1}},
            {"$limit": 5},
        ]

        epss_pipeline = [
            # Filter out documents without EPSS scores
            {"$match": {"epss_score": {"$exists": True, "$ne": None}}},
            {
                "$bucket": {
                    "groupBy": "$epss_score",
                    "boundaries": [0.0, 0.1, 0.3, 0.5, 0.7, 1.0],
                    "default": "other",
                    "output": {
                        "count": {"$sum": 1}
                    }
                }
            }
        ]

        # Run only essential aggregations in parallel with timeout
        try:
            total, sources_raw, severity_raw, cwes_raw, epss_raw = await asyncio.wait_for(
                asyncio.gather(
                    collection.estimated_document_count(),
                    collection.aggregate(sources_pipeline).to_list(length=5),
                    collection.aggregate(severity_pipeline).to_list(length=5),
                    collection.aggregate(cwes_pipeline).to_list(length=5),
                    collection.aggregate(epss_pipeline).to_list(length=5),
                ),
                timeout=5.0,  # 5 second timeout for fallback
            )

            sources = self._map_group_results(sources_raw)
            severities = [
                {"key": doc.get("_id", "UNKNOWN").upper(), "doc_count": int(doc.get("count", 0))}
                for doc in severity_raw
                if doc.get("_id")
            ]
            cwes = self._map_group_results(cwes_raw)

            # Map EPSS bucket results to range format
            epss_ranges = []
            range_labels = ["0.0-0.1", "0.1-0.3", "0.3-0.5", "0.5-0.7", "0.7-1.0"]
            for idx, doc in enumerate(epss_raw):
                if idx < len(range_labels):
                    epss_ranges.append({
                        "key": range_labels[idx],
                        "doc_count": int(doc.get("count", 0))
                    })

        except asyncio.TimeoutError:
            log.warning("stats.mongo_fallback_timeout")
            total = 0
            sources = []
            severities = []
            cwes = []
            epss_ranges = []

        # Return minimal data - skip expensive vendors/products/timeline
        return {
            "total": total,
            "sources": sources,
            "severities": severities,
            "topCwes": cwes,
            "epssRanges": epss_ranges,
            "topVendors": [],  # Skip expensive aggregation
            "topProducts": [],  # Skip expensive aggregation
            "timeline": [],  # Skip expensive aggregation
            "timelineSummary": [],
            "topAssigners": [],
            "exploitedCount": 0,
            "referenceDomains": [],
        }

    async def _fetch_asset_stats(self) -> dict[str, Any]:
        repository = await AssetRepository.create()

        # Run all queries in parallel for better performance
        (
            vendor_total,
            product_total,
            version_total,
            vendor_samples,
            product_samples,
        ) = await asyncio.gather(
            repository.vendors.count_documents({}),
            repository.products.count_documents({}),
            repository.versions.count_documents({}),
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

        merged: dict[Any, int] = {}
        order: list[Any] = []
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

            if key in merged:
                merged[key] += int(count)
            else:
                merged[key] = int(count)
                order.append(key)

        results: list[dict[str, Any]] = []
        for key in order:
            results.append({"key": key, "doc_count": merged[key]})
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
    def _map_daily_histogram(aggregation: dict[str, Any] | None) -> list[dict[str, Any]]:
        """Map daily date histogram to timeline points with timestamps."""
        if not isinstance(aggregation, dict):
            return []
        buckets = aggregation.get("buckets")
        if not isinstance(buckets, Iterable):
            return []

        results: list[dict[str, Any]] = []
        for bucket in buckets:
            if not isinstance(bucket, dict):
                continue

            # Get timestamp in milliseconds
            raw_key = bucket.get("key")
            if not isinstance(raw_key, (int, float)):
                continue

            timestamp = int(raw_key)
            key_str = bucket.get("key_as_string", "")

            count = bucket.get("doc_count", 0)
            if not isinstance(count, (int, float)):
                continue

            results.append({
                "key": key_str,
                "count": int(count),
                "timestamp": timestamp,
            })

        return results

    @staticmethod
    def _map_monthly_histogram(aggregation: dict[str, Any] | None) -> list[dict[str, Any]]:
        """Map monthly date histogram to timeline summary points."""
        if not isinstance(aggregation, dict):
            return []
        buckets = aggregation.get("buckets")
        if not isinstance(buckets, Iterable):
            return []

        results: list[dict[str, Any]] = []
        for bucket in buckets:
            if not isinstance(bucket, dict):
                continue

            raw_key = bucket.get("key")
            if not isinstance(raw_key, (int, float)):
                continue

            timestamp = int(raw_key)
            key_str = bucket.get("key_as_string", "")

            count = bucket.get("doc_count", 0)
            if not isinstance(count, (int, float)):
                continue

            results.append({
                "key": key_str,
                "count": int(count),
                "timestamp": timestamp,
            })

        return results

    @staticmethod
    def _map_range_aggregation(aggregation: dict[str, Any] | None) -> list[dict[str, Any]]:
        """Map OpenSearch range aggregation to TermsBucket format."""
        if not isinstance(aggregation, dict):
            return []

        buckets = aggregation.get("buckets")
        if not isinstance(buckets, dict):
            return []

        # Define the order of range keys
        range_order = ["0.0-0.1", "0.1-0.3", "0.3-0.5", "0.5-0.7", "0.7-1.0"]

        results: list[dict[str, Any]] = []
        for range_key in range_order:
            bucket = buckets.get(range_key)
            if not isinstance(bucket, dict):
                continue

            count = bucket.get("doc_count", 0)
            if not isinstance(count, (int, float)):
                continue

            results.append({"key": range_key, "doc_count": int(count)})

        return results

    @staticmethod
    def _extract_domain_counts(raw_refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Extract and aggregate domain counts from full URL references."""
        domain_counts: dict[str, int] = {}

        for ref in raw_refs:
            url = ref.get("key", "")
            count = ref.get("doc_count", 0)
            if not isinstance(url, str) or not url:
                continue

            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                # Remove www. prefix for cleaner grouping
                if domain.startswith("www."):
                    domain = domain[4:]
                if domain:
                    domain_counts[domain] = domain_counts.get(domain, 0) + count
            except Exception:
                continue

        # Sort by count descending and take top 10
        sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        return [{"key": domain, "doc_count": count} for domain, count in sorted_domains]

    @staticmethod
    def _build_timeline_sequence(start: datetime, bucket_map: dict[str, int]) -> list[dict[str, Any]]:
        timeline: list[dict[str, Any]] = []
        month_cursor = start
        for _ in range(12):
            month_key = month_cursor.strftime("%Y-%m")
            timeline.append({"key": month_key, "count": bucket_map.get(month_key, 0)})
            month_cursor = month_cursor + relativedelta(months=1)
        return timeline

    async def get_today_summary(self) -> dict[str, Any]:
        """Return today's vulnerability stats: vendors with products, severity breakdown, CVE list."""
        today_str = datetime.now(UTC).strftime("%Y-%m-%d")

        body: dict[str, Any] = {
            "size": 200,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"published": {"gte": "now/d"}}},
                    ]
                }
            },
            "_source": ["vuln_id", "title", "cvss.severity", "aliases"],
            "sort": [{"published": {"order": "desc"}}],
            "aggs": {
                "vendors": {
                    "terms": {"field": "vendorSlugs.keyword", "size": 500},
                    "aggs": {
                        "display_name": {"terms": {"field": "vendors", "size": 1}},
                        "products": {
                            "terms": {"field": "productSlugs.keyword", "size": 500},
                        },
                    },
                },
                "severity_breakdown": {
                    "terms": {"field": "cvss.severity", "size": 10, "missing": "unknown"},
                },
            },
        }

        response = await async_search(
            settings.opensearch_index,
            body,
            suppress_exceptions=True,
        )

        aggregations = response.get("aggregations", {}) if isinstance(response, dict) else {}

        # Collect all vendor/product slugs so we can look up correct display names from MongoDB
        vendors_agg = aggregations.get("vendors", {})
        all_vendor_slugs: set[str] = set()
        all_product_slugs: set[str] = set()
        for vb in (vendors_agg.get("buckets") or []):
            vslug = vb.get("key")
            if vslug and isinstance(vslug, str):
                all_vendor_slugs.add(vslug)
            for pb in (vb.get("products", {}).get("buckets") or []):
                pslug = pb.get("key")
                if pslug and isinstance(pslug, str):
                    all_product_slugs.add(pslug)

        # Look up correct display names from asset catalog
        asset_repo = await AssetRepository.create()
        vendor_name_map: dict[str, str] = {}
        product_name_map: dict[str, str] = {}
        if all_vendor_slugs:
            vendor_docs = await asset_repo.find_vendors_by_slugs(all_vendor_slugs)
            for doc in vendor_docs:
                vendor_name_map[doc["_id"]] = doc.get("displayName") or doc["_id"]
        if all_product_slugs:
            product_docs = await asset_repo.find_products_by_slugs(all_product_slugs)
            for doc in product_docs:
                product_name_map[doc["_id"]] = doc.get("displayName") or doc["_id"]

        vendors: list[dict[str, Any]] = []
        products: list[dict[str, Any]] = []
        for vb in (vendors_agg.get("buckets") or []):
            if not isinstance(vb, dict):
                continue
            vslug = vb.get("key")
            if not vslug or not isinstance(vslug, str):
                continue
            vname = vendor_name_map.get(vslug, vslug.replace("-", " ").title())
            vendors.append({"slug": vslug, "name": vname, "doc_count": int(vb.get("doc_count", 0))})

            for pb in (vb.get("products", {}).get("buckets") or []):
                if not isinstance(pb, dict):
                    continue
                pslug = pb.get("key")
                if not pslug or not isinstance(pslug, str):
                    continue
                pname = product_name_map.get(pslug, pslug.replace("-", " ").title())
                products.append({
                    "slug": pslug,
                    "name": pname,
                    "doc_count": int(pb.get("doc_count", 0)),
                    "vendorSlug": vslug,
                    "vendorName": vname,
                })

        severities = self._map_terms_aggregation(
            aggregations.get("severity_breakdown"),
            value_transform=lambda v: str(v).lower(),
        )

        hits = response.get("hits", {}).get("hits", [])
        cves: list[dict[str, Any]] = []
        for hit in hits:
            source = hit.get("_source", {})
            if not isinstance(source, dict):
                continue
            vuln_id = source.get("vuln_id")
            if not vuln_id:
                continue
            severity = "unknown"
            cvss = source.get("cvss")
            if isinstance(cvss, dict):
                severity = (cvss.get("severity") or "unknown").lower()
            raw_aliases = source.get("aliases")
            aliases = raw_aliases if isinstance(raw_aliases, list) else []
            cves.append({
                "vulnId": vuln_id,
                "title": source.get("title", ""),
                "severity": severity,
                "aliases": aliases,
            })

        total = self._resolve_total(response)

        return {
            "total": total,
            "todayDate": today_str,
            "vendors": vendors,
            "products": products,
            "severities": severities,
            "cves": cves,
        }

    @staticmethod
    def _map_slug_with_name(
        aggregation: dict[str, Any] | None,
        *,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Map a terms aggregation on a slug field with a nested display_name sub-agg."""
        if not isinstance(aggregation, dict):
            return []
        buckets = aggregation.get("buckets")
        if not isinstance(buckets, list):
            return []

        results: list[dict[str, Any]] = []
        for bucket in buckets:
            if not isinstance(bucket, dict):
                continue
            slug = bucket.get("key")
            if not slug or not isinstance(slug, str):
                continue
            count = bucket.get("doc_count", 0)
            if not isinstance(count, (int, float)):
                continue

            display_name_agg = bucket.get("display_name", {})
            display_buckets = display_name_agg.get("buckets", [])
            if display_buckets and isinstance(display_buckets, list) and display_buckets[0]:
                name = display_buckets[0].get("key", slug)
            else:
                name = slug.replace("-", " ").title()

            results.append({"slug": slug, "name": name, "doc_count": int(count)})
            if len(results) >= limit:
                break

        return results

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
