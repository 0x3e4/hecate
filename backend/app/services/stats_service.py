from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Iterable
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dateutil.relativedelta import relativedelta
import structlog
from pymongo.errors import PyMongoError
from opensearchpy.exceptions import (
    OpenSearchException,
    RequestError,
    ConnectionError as OSConnectionError,
)

from app.core.config import settings
from app.db.opensearch import async_search
from app.repositories.asset_repository import AssetRepository
from app.repositories.cert_advisory_repository import CertAdvisoryRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.cert_topics import group_advisories
from app.services.inventory_matcher import items_for_vuln
from app.services.inventory_service import get_inventory_service


log = structlog.get_logger()

# A busy day publishes several hundred CVEs. The summary matches each one against the
# inventory and the scans, so a low cap silently hides the matches past it.
TODAY_MAX_CVES = 2000
ATTENTION_MAX_KEV = 50
OVERVIEW_CACHE_SECONDS = 60
_OVERVIEW_CACHE: dict[str, Any] = {}
# Last vulnerability stats OpenSearch answered. Served while OpenSearch is
# down, because MongoDB cannot compute them without reading the whole
# collection (tens of GB, minutes of disk IO for every other service).
_LAST_GOOD_VULN_STATS: dict[str, Any] = {}
# One retry for the start-up race (OpenSearch answers 503 for a few seconds).
OPENSEARCH_RETRY_DELAY_SECONDS = 3.0
# Server-side bound for every MongoDB fallback query. asyncio.wait_for only
# stops the Python task; without maxTimeMS MongoDB keeps working.
MONGO_FALLBACK_MAX_TIME_MS = 3000
# Feeds name hundreds of CVEs in a week. Most mentions stand alone, so the cut falls on those.
ATTENTION_MAX_CERT_MENTIONS = 300
CERT_OVERVIEW_MAX_CVES = 1000

# What a CVE row needs, including the fields the inventory matcher reads.
_VULN_ROW_SOURCE = [
    "vuln_id",
    "title",
    "aliases",
    "exploited",
    "cvss.severity",
    "cvss.base_score",
    "epssScore",
    "exploitation.dateAdded",
    "exploitation.dueDate",
    "exploitation.knownRansomwareCampaignUse",
    "vendorSlugs",
    "productSlugs",
    "vendors",
    "products",
    "impactedProducts",
    "cpeConfigurations",
    "cpes",
]


def _string_list(source: dict[str, Any], key: str) -> list[str]:
    raw = source.get(key)
    return [value for value in raw if isinstance(value, str)] if isinstance(raw, list) else []


def _hit_sources(response: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        hit["_source"]
        for hit in response.get("hits", {}).get("hits", [])
        if isinstance(hit.get("_source"), dict) and hit["_source"].get("vuln_id")
    ]


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "unknown")


def _severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else len(_SEVERITY_ORDER)


def _unknown_row(cve_id: str) -> dict[str, Any]:
    """A CVE a CERT named before Hecate has a record of it."""
    return {
        "vulnId": cve_id,
        "title": "",
        "known": False,
        "severity": "unknown",
        "cvssScore": None,
        "epssScore": None,
        "exploited": False,
        "kevListed": False,
        "dateAdded": None,
        "dueDate": None,
        "ransomware": False,
        "aliases": [],
        "vendorSlugs": [],
        "productSlugs": [],
        "vendors": [],
        "products": [],
        "inventoryMatchIds": [],
    }


def _severity_of(source: dict[str, Any]) -> str:
    cvss = source.get("cvss")
    if isinstance(cvss, dict):
        return (cvss.get("severity") or "unknown").lower()
    return "unknown"


class StatsService:
    async def get_overview(self) -> dict[str, Any]:
        # Public and up to 30 s of aggregations per call: one result serves everyone for a minute.
        cached = _OVERVIEW_CACHE.get("value")
        if cached is not None and time.monotonic() - _OVERVIEW_CACHE["at"] < OVERVIEW_CACHE_SECONDS:
            return cached
        result = await self._compute_overview()
        _OVERVIEW_CACHE.update(value=result, at=time.monotonic())
        return result

    async def _compute_overview(self) -> dict[str, Any]:
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
            await asyncio.sleep(OPENSEARCH_RETRY_DELAY_SECONDS)
            try:
                response = await self._run_vulnerability_search(
                    start_30_days=start_30_days,
                    use_keyword_suffix=False,
                )
            except (OSConnectionError, OpenSearchException, asyncio.TimeoutError) as retry_exc:
                log.warning("stats.opensearch_retry_failed", error=str(retry_exc))
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

        stats = {
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
        _LAST_GOOD_VULN_STATS.update(value=stats, at=time.monotonic())
        return stats

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
        """Stats while OpenSearch is unavailable.

        Serves the last OpenSearch result when there is one. Otherwise only
        index-backed counts run on MongoDB (total, primary source, severity),
        each bounded server-side by ``maxTimeMS``. The ``$unwind`` / ``$group``
        / ``$bucket`` aggregations this used to run read the whole collection
        and kept the disk busy for minutes after the Python timeout had given
        up on them.
        """
        last = _LAST_GOOD_VULN_STATS.get("value")
        if last is not None:
            log.info(
                "stats.serving_last_opensearch_result",
                age_seconds=round(time.monotonic() - _LAST_GOOD_VULN_STATS["at"]),
            )
            return last

        repository = await VulnerabilityRepository.create()
        collection = repository.collection
        max_time = MONGO_FALLBACK_MAX_TIME_MS

        async def _counts_by(field: str) -> list[dict[str, Any]]:
            # distinct + count on an indexed field are index-only (DISTINCT_SCAN,
            # COUNT_SCAN); a $group over the same field is a COLLSCAN.
            values = await collection.distinct(field, maxTimeMS=max_time)
            buckets: list[dict[str, Any]] = []
            for value in values:
                if not value:
                    continue
                count = await collection.count_documents({field: value}, maxTimeMS=max_time)
                buckets.append({"key": str(value), "doc_count": int(count)})
            buckets.sort(key=lambda item: (-item["doc_count"], item["key"]))
            return buckets

        total = 0
        sources: list[dict[str, Any]] = []
        severities: list[dict[str, Any]] = []
        try:
            total = await collection.estimated_document_count(maxTimeMS=max_time)
            sources = (await _counts_by("source"))[:5]
            severities = [
                {"key": item["key"].upper(), "doc_count": item["doc_count"]}
                for item in await _counts_by("cvss.severity")
            ]
        except PyMongoError as exc:
            log.warning("stats.mongo_fallback_failed", error=str(exc))

        # CWEs, EPSS, vendors, timeline: no index serves them, so they stay
        # empty until OpenSearch is back rather than scanning the collection.
        return {
            "total": total,
            "sources": sources,
            "severities": severities,
            "topCwes": [],
            "epssRanges": [],
            "topVendors": [],
            "topProducts": [],
            "timeline": [],
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

    async def get_today_summary(
        self,
        *,
        date: str | None = None,
        tz: str | None = None,
    ) -> dict[str, Any]:
        """Return vulnerability stats for a given date (default: today).

        Args:
            date: Optional date string in YYYY-MM-DD format. Defaults to today.
            tz: Optional IANA timezone (e.g. "Europe/Vienna"). When provided,
                "today" and the day boundaries are computed in that zone.
        """
        zone: ZoneInfo | None = None
        if tz:
            try:
                zone = ZoneInfo(tz)
            except (ZoneInfoNotFoundError, ValueError):
                zone = None

        def _now_date() -> str:
            return datetime.now(zone or UTC).strftime("%Y-%m-%d")

        if date and len(date) == 10:
            # Validate format
            try:
                datetime.strptime(date, "%Y-%m-%d")
                target_date = date
            except ValueError:
                target_date = _now_date()
        else:
            target_date = _now_date()

        next_day = (datetime.strptime(target_date, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")

        published_range: dict[str, Any] = {"gte": target_date, "lt": next_day}
        if zone is not None:
            published_range["time_zone"] = tz

        def _build_body(use_keyword_suffix: bool) -> dict[str, Any]:
            suffix = ".keyword" if use_keyword_suffix else ""
            return {
                "size": TODAY_MAX_CVES,
                "track_total_hits": True,
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"published": published_range}},
                        ]
                    }
                },
                "_source": [
                    "vuln_id",
                    "title",
                    "cvss.severity",
                    "aliases",
                    "vendorSlugs",
                    "productSlugs",
                    "vendors",
                    "products",
                    "impactedProducts",
                    "cpeConfigurations",
                    "cpes",
                ],
                "sort": [{"published": {"order": "desc"}}],
                "aggs": {
                    "vendors": {
                        "terms": {"field": f"vendorSlugs{suffix}", "size": 500},
                        "aggs": {
                            "display_name": {"terms": {"field": "vendors", "size": 1}},
                            "products": {
                                "terms": {"field": f"productSlugs{suffix}", "size": 500},
                            },
                        },
                    },
                    "severity_breakdown": {
                        "terms": {"field": "cvss.severity", "size": 10, "missing": "unknown"},
                    },
                },
            }

        try:
            response = await async_search(
                settings.opensearch_index,
                _build_body(use_keyword_suffix=False),
                suppress_exceptions=False,
            )
        except RequestError as exc:
            if self._is_fielddata_error(exc):
                log.info("stats.today_retry_keyword_fields")
                response = await async_search(
                    settings.opensearch_index,
                    _build_body(use_keyword_suffix=True),
                    suppress_exceptions=True,
                )
            else:
                log.warning("stats.today_opensearch_request_error", error=str(exc))
                response = {"hits": {"hits": [], "total": {"value": 0}}}
        except (OSConnectionError, OpenSearchException) as exc:
            log.warning("stats.today_opensearch_unavailable", error=str(exc))
            response = {"hits": {"hits": [], "total": {"value": 0}}}

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

        vendor_name_map, product_name_map = await self._catalog_names(all_vendor_slugs, all_product_slugs)

        severities = self._map_terms_aggregation(
            aggregations.get("severity_breakdown"),
            value_transform=lambda v: str(v).lower(),
        )

        # Cross-reference each of today's CVEs against the environment inventory
        # with the same precise, version-aware matcher used on the Inventory page
        # and the vulnerability detail page (`items_for_vuln`) -- NOT a soft
        # vendor/product slug membership check. This keeps the "in inventory"
        # highlight from firing on a CVE whose version range doesn't actually
        # cover the pinned inventory version (e.g. n8n 2.26.6 vs. a CVE affecting
        # only < 2.26.2).
        inventory_service = await get_inventory_service()
        raw_inventory_items = await inventory_service.list_all_cached()

        hits = response.get("hits", {}).get("hits", [])
        cves: list[dict[str, Any]] = []
        matched_vendor_slugs: set[str] = set()
        matched_pairs: set[str] = set()
        for hit in hits:
            source = hit.get("_source", {})
            if not isinstance(source, dict):
                continue
            vuln_id = source.get("vuln_id")
            if not vuln_id:
                continue
            raw_aliases = source.get("aliases")
            aliases = raw_aliases if isinstance(raw_aliases, list) else []
            vendor_slugs = _string_list(source, "vendorSlugs")
            product_slugs = _string_list(source, "productSlugs")

            inventory_match_ids = self._inventory_match_ids(source, vuln_id, raw_inventory_items)
            if inventory_match_ids:
                for v in vendor_slugs:
                    matched_vendor_slugs.add(v)
                    for p in product_slugs:
                        matched_pairs.add(f"{v}|{p}")

            cves.append({
                "vulnId": vuln_id,
                "title": source.get("title", ""),
                "severity": _severity_of(source),
                "aliases": aliases,
                "vendorSlugs": vendor_slugs,
                "productSlugs": product_slugs,
                "inventoryMatchIds": inventory_match_ids,
            })

        vendors: list[dict[str, Any]] = []
        products: list[dict[str, Any]] = []
        for vb in (vendors_agg.get("buckets") or []):
            if not isinstance(vb, dict):
                continue
            vslug = vb.get("key")
            if not vslug or not isinstance(vslug, str):
                continue
            vname = vendor_name_map.get(vslug, vslug.replace("-", " ").title())
            vendors.append({
                "slug": vslug,
                "name": vname,
                "doc_count": int(vb.get("doc_count", 0)),
                "inventoryMatch": vslug in matched_vendor_slugs,
            })

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
                    "inventoryMatch": f"{vslug}|{pslug}" in matched_pairs,
                })

        total = self._resolve_total(response)

        return {
            "total": total,
            "todayDate": target_date,
            "vendors": vendors,
            "products": products,
            "severities": severities,
            "cves": cves,
        }

    async def get_attention(self, *, days: int = 7, tz: str | None = None) -> dict[str, Any]:
        """Return what is being exploited or warned about in the last ``days`` days.

        Combines CVEs added to the CISA KEV catalogue with those the CERT feeds
        named. Neither is keyed on ``published``: most of them are older CVEs.
        """
        since_at = self._window_start(days, tz)
        since = since_at.strftime("%Y-%m-%d")

        mentions = await self._cert_mentions(since_at)
        kev_clause = {"range": {"exploitation.dateAdded": {"gte": since}}}
        clauses: list[dict[str, Any]] = [kev_clause]
        if mentions:
            mentioned = sorted(mentions, key=lambda cve_id: -len(mentions[cve_id]))[:ATTENTION_MAX_CERT_MENTIONS]
            clauses += [{"terms": {"vuln_id": mentioned}}, {"terms": {"aliases": mentioned}}]

        body = {
            "size": ATTENTION_MAX_KEV + ATTENTION_MAX_CERT_MENTIONS,
            "track_total_hits": True,
            "query": {"bool": {"should": clauses, "minimum_should_match": 1}},
            "_source": _VULN_ROW_SOURCE,
            "sort": [{"exploitation.dateAdded": {"order": "desc", "missing": "_last", "unmapped_type": "date"}}],
        }
        try:
            response = await async_search(settings.opensearch_index, body, suppress_exceptions=False)
        except (RequestError, OSConnectionError, OpenSearchException) as exc:
            log.warning("stats.attention_opensearch_error", error=str(exc))
            return {"since": since, "days": days, "total": 0, "items": []}

        rows = await self._vulnerability_rows(_hit_sources(response), since)
        items: list[dict[str, Any]] = []
        for source, row in rows:
            certs: dict[str, dict[str, Any]] = {}
            for identifier in [row["vulnId"], *_string_list(source, "aliases")]:
                for mention in mentions.get(identifier.upper(), []):
                    certs.setdefault(mention["name"], mention)
            items.append({**row, "certs": list(certs.values())})

        return {"since": since, "days": days, "total": self._resolve_total(response), "items": items}

    async def get_cert_overview(self, *, days: int = 30, tz: str | None = None) -> dict[str, Any]:
        """Return the CERT advisories of the window, merged into topics through shared CVEs.

        Round-ups stay apart and are not looked up: they name hundreds of CVEs, and
        the page only needs their IDs to count what is in the user's scans.
        """
        since_at = self._window_start(days, tz)
        since = since_at.strftime("%Y-%m-%d")
        empty = {"since": since, "days": days, "topics": [], "roundups": []}
        try:
            repository = await CertAdvisoryRepository.create()
            advisories = await repository.list_since(since_at)
        except PyMongoError as exc:
            log.warning("stats.cert_overview_unavailable", error=str(exc))
            return empty

        topics, roundups = group_advisories(advisories)
        known = await self._rows_by_id(
            [cve_id for topic in topics for cve_id in topic["cve_ids"]][:CERT_OVERVIEW_MAX_CVES],
            since,
        )

        def advisory_row(advisory: dict[str, Any]) -> dict[str, Any]:
            return {
                "feed": advisory["feed"],
                "title": advisory.get("title"),
                "url": advisory.get("url"),
                "published": advisory["published"].isoformat(),
            }

        def topic_row(topic: dict[str, Any]) -> dict[str, Any]:
            rows: dict[str, dict[str, Any]] = {}
            for cve_id in topic["cve_ids"]:
                row = known.get(cve_id) or _unknown_row(cve_id)
                rows.setdefault(row["vulnId"], row)
            published = [advisory["published"] for advisory in topic["advisories"]]
            severities = [row["severity"] for row in rows.values()]
            return {
                "id": topic["id"],
                "certs": list(dict.fromkeys(advisory["feed"] for advisory in topic["advisories"])),
                "firstSeen": min(published).isoformat(),
                "lastSeen": max(published).isoformat(),
                "worstSeverity": min(severities, key=_severity_rank),
                "cves": sorted(rows.values(), key=lambda row: _severity_rank(row["severity"])),
                "advisories": [advisory_row(advisory) for advisory in topic["advisories"]],
            }

        return {
            **empty,
            "topics": [topic_row(topic) for topic in topics],
            "roundups": [
                {"id": str(advisory["_id"]), **advisory_row(advisory), "cveIds": advisory["cve_ids"]}
                for advisory in roundups
            ],
        }

    async def _rows_by_id(self, cve_ids: list[str], since: str) -> dict[str, dict[str, Any]]:
        """CVE rows keyed by every identifier they answer to, so an alias finds its record."""
        if not cve_ids:
            return {}
        body = {
            "size": len(cve_ids),
            "query": {
                "bool": {
                    "should": [{"terms": {"vuln_id": cve_ids}}, {"terms": {"aliases": cve_ids}}],
                    "minimum_should_match": 1,
                }
            },
            "_source": _VULN_ROW_SOURCE,
        }
        try:
            response = await async_search(settings.opensearch_index, body, suppress_exceptions=False)
        except (RequestError, OSConnectionError, OpenSearchException) as exc:
            log.warning("stats.cert_overview_opensearch_error", error=str(exc))
            return {}

        by_id: dict[str, dict[str, Any]] = {}
        for source, row in await self._vulnerability_rows(_hit_sources(response), since):
            for identifier in [row["vulnId"], *_string_list(source, "aliases")]:
                by_id.setdefault(identifier.upper(), row)
        return by_id

    async def _vulnerability_rows(
        self,
        sources: list[dict[str, Any]],
        since: str,
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        """Pairs each document with the row the dashboard and the CERT page show for it."""
        vendor_names, product_names = await self._catalog_names(
            {slug for source in sources for slug in _string_list(source, "vendorSlugs")},
            {slug for source in sources for slug in _string_list(source, "productSlugs")},
        )
        inventory_service = await get_inventory_service()
        raw_inventory_items = await inventory_service.list_all_cached()

        rows: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for source in sources:
            vuln_id = source["vuln_id"]
            cvss = source.get("cvss") if isinstance(source.get("cvss"), dict) else {}
            exploitation = source.get("exploitation") if isinstance(source.get("exploitation"), dict) else {}
            vendor_slugs = _string_list(source, "vendorSlugs")
            product_slugs = _string_list(source, "productSlugs")
            date_added = exploitation.get("dateAdded")
            rows.append((source, {
                "vulnId": vuln_id,
                "title": source.get("title", ""),
                "known": True,
                "severity": _severity_of(source),
                "cvssScore": cvss.get("base_score"),
                "epssScore": source.get("epssScore"),
                "exploited": bool(source.get("exploited")),
                "kevListed": bool(date_added) and str(date_added)[:10] >= since,
                "dateAdded": date_added,
                "dueDate": exploitation.get("dueDate"),
                "ransomware": str(exploitation.get("knownRansomwareCampaignUse") or "").lower() == "known",
                "aliases": [],
                "vendorSlugs": vendor_slugs,
                "productSlugs": product_slugs,
                "vendors": [{"slug": s, "name": vendor_names.get(s, s)} for s in vendor_slugs],
                "products": [{"slug": s, "name": product_names.get(s, s)} for s in product_slugs],
                "inventoryMatchIds": self._inventory_match_ids(source, vuln_id, raw_inventory_items),
            }))
        return rows

    @staticmethod
    def _window_start(days: int, tz: str | None) -> datetime:
        """Local midnight ``days - 1`` days back, so the window includes today. An invalid zone falls back to UTC."""
        zone: ZoneInfo | None = None
        if tz:
            try:
                zone = ZoneInfo(tz)
            except (ZoneInfoNotFoundError, ValueError):
                zone = None
        start = datetime.now(zone or UTC) - timedelta(days=days - 1)
        return start.replace(hour=0, minute=0, second=0, microsecond=0)

    @staticmethod
    async def _cert_mentions(since: datetime) -> dict[str, list[dict[str, Any]]]:
        """CVE → the feeds naming it. The panel still works from KEV when this store is unavailable."""
        try:
            repository = await CertAdvisoryRepository.create()
            return await repository.mentions_since(since)
        except PyMongoError as exc:
            log.warning("stats.cert_mentions_unavailable", error=str(exc))
            return {}

    @staticmethod
    async def _catalog_names(
        vendor_slugs: set[str],
        product_slugs: set[str],
    ) -> tuple[dict[str, str], dict[str, str]]:
        """Display names from the asset catalog, keyed by slug."""
        asset_repo = await AssetRepository.create()
        vendor_names: dict[str, str] = {}
        product_names: dict[str, str] = {}
        if vendor_slugs:
            for doc in await asset_repo.find_vendors_by_slugs(vendor_slugs):
                vendor_names[doc["_id"]] = doc.get("displayName") or doc["_id"]
        if product_slugs:
            for doc in await asset_repo.find_products_by_slugs(product_slugs):
                product_names[doc["_id"]] = doc.get("displayName") or doc["_id"]
        return vendor_names, product_names

    @staticmethod
    def _inventory_match_ids(
        source: dict[str, Any],
        vuln_id: str,
        raw_inventory_items: list[dict[str, Any]],
    ) -> list[str]:
        if not raw_inventory_items:
            return []
        try:
            matches = items_for_vuln(source, raw_inventory_items)
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("stats.inventory_match_error", vuln_id=vuln_id, error=str(exc))
            return []
        return [str(m["_id"]) for m in matches if m.get("_id")]

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
