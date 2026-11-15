"""As-you-type suggestions for the dashboard search.

The dashboard ranks them (needs attention, then your inventory or scans, then
severity, KEV and EPSS); this module finds the candidates and says for each
whether it touches the inventory (the version-aware matcher) or a scanned SBOM
at an affected version. Read-only and fail-soft: an error means no suggestions.
"""
from __future__ import annotations

import re
from typing import Any

import structlog

from app.core.config import settings
from app.db.opensearch import async_search
from app.services.inventory_matcher import items_for_vuln

log = structlog.get_logger()

MIN_QUERY = 2
MAX_QUERY = 100
CANDIDATES = 30
INFO_LENGTH = 160
_ID_PREFIX = re.compile(r"^(CVE|GHSA|EUVD|MAL|PYSEC|OSV|GO|RUSTSEC)-", re.IGNORECASE)
_SOURCE_FIELDS = [
    "vuln_id", "title", "summary", "aliases", "cvss", "epssScore", "exploited", "exploitation",
    "published", "vendorSlugs", "productSlugs", "vendors", "products",
    "impactedProducts", "cpeConfigurations", "cpes",
]


def _wildcard_literal(text: str) -> str:
    """User text inside a wildcard pattern: its own * ? and \\ match literally."""
    return re.sub(r"([*?\\])", r"\\\1", text)


def build_suggestion_query(raw: str) -> dict[str, Any] | None:
    """The OpenSearch body for a query, or None when it is too short to suggest anything."""
    query = " ".join(raw.split())[:MAX_QUERY]
    if len(query) < MIN_QUERY:
        return None
    upper = query.upper()
    id_clauses: list[dict[str, Any]] = [
        {"term": {"vuln_id": {"value": upper, "boost": 20}}},
        {"prefix": {"vuln_id": {"value": upper, "boost": 8}}},
        {"prefix": {"aliases": {"value": upper, "boost": 6}}},
    ]
    if _ID_PREFIX.match(query):
        should = id_clauses
    else:
        pattern = f"*{_wildcard_literal(query)}*"
        should = [
            *id_clauses,
            {"multi_match": {"query": query, "fields": ["title^2", "summary"], "operator": "and"}},
            {"wildcard": {"products": {"value": pattern, "case_insensitive": True, "boost": 4}}},
            {"wildcard": {"vendors": {"value": pattern, "case_insensitive": True, "boost": 2}}},
        ]
    return {
        "size": CANDIDATES,
        "track_total_hits": False,
        "query": {"bool": {"should": should, "minimum_should_match": 1}},
        "_source": _SOURCE_FIELDS,
    }


def _info(source: dict[str, Any]) -> str:
    """One line on what the vulnerability is: the summary's start, else the title."""
    text = " ".join(str(source.get("summary") or source.get("title") or "").split())
    return text if len(text) <= INFO_LENGTH else text[: INFO_LENGTH - 1].rstrip() + "…"


def _strings(source: dict[str, Any], key: str) -> list[str]:
    value = source.get(key)
    return [v for v in value if isinstance(v, str) and v] if isinstance(value, list) else []


async def suggest(raw: str) -> list[dict[str, Any]]:
    body = build_suggestion_query(raw)
    if body is None:
        return []
    try:
        response = await async_search(settings.opensearch_index, body, suppress_exceptions=True)
    except Exception as exc:  # noqa: BLE001 - suggestions are optional
        log.warning("search_suggestions.search_failed", error=str(exc))
        return []
    hits = ((response or {}).get("hits") or {}).get("hits") or []
    sources = [hit["_source"] for hit in hits if isinstance(hit.get("_source"), dict) and hit["_source"].get("vuln_id")]
    if not sources:
        return []

    try:
        from app.services.inventory_service import get_inventory_service

        inventory = await (await get_inventory_service()).list_all_cached()
    except Exception as exc:  # noqa: BLE001
        log.warning("search_suggestions.inventory_failed", error=str(exc))
        inventory = []

    items: list[dict[str, Any]] = []
    for source in sources:
        try:
            matches = items_for_vuln(source, inventory) if inventory else []
        except Exception:  # noqa: BLE001 - one odd document costs only its match
            matches = []
        cvss = source.get("cvss") if isinstance(source.get("cvss"), dict) else {}
        exploitation = source.get("exploitation") if isinstance(source.get("exploitation"), dict) else {}
        items.append({
            "vulnId": source["vuln_id"],
            "title": source.get("title") or "",
            "info": _info(source),
            "severity": str(cvss.get("severity") or "unknown").lower(),
            "cvssScore": cvss.get("base_score"),
            "epssScore": source.get("epssScore"),
            "exploited": bool(source.get("exploited")),
            "kevListed": bool(exploitation.get("dateAdded")),
            "published": source.get("published"),
            "aliases": _strings(source, "aliases")[:5],
            "products": _strings(source, "products")[:3],
            "vendors": _strings(source, "vendors")[:3],
            "inventoryMatchIds": [str(m["_id"]) for m in matches if m.get("_id")],
            "sbomScanId": None,
        })

    # After the inventory match: building the SBOM check's products cleans their versions in place.
    from app.services.stats_service import StatsService

    sbom_hits = await StatsService._sbom_scan_ids(sources)
    for item in items:
        item["sbomScanId"] = sbom_hits.get(item["vulnId"])
    return items
