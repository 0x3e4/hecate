"""Dashboard signals: the KEV attention list and the cap on the day summary."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from opensearchpy.exceptions import ConnectionError as OSConnectionError

from app.services import stats_service
from app.services.stats_service import StatsService


class _Inventory:
    def __init__(self, items):
        self.items = items

    async def list_all_cached(self):
        return self.items


class _Assets:
    async def find_vendors_by_slugs(self, slugs):
        return [{"_id": slug, "displayName": slug.title()} for slug in slugs]

    async def find_products_by_slugs(self, slugs):
        return [{"_id": slug, "displayName": slug.upper()} for slug in slugs]


def _wire(monkeypatch, *, hits=(), total=None, inventory=(), error=None, certs=None):
    certs = certs or {}
    bodies: list[dict] = []

    async def search(_index, body, **_kwargs):
        bodies.append(body)
        if error:
            raise error
        return {
            "hits": {
                "hits": [{"_source": h} for h in hits],
                "total": {"value": len(hits) if total is None else total},
            }
        }

    async def get_inventory():
        return _Inventory(list(inventory))

    async def create_assets():
        return _Assets()

    async def mentions(_since):
        return dict(certs)

    monkeypatch.setattr(StatsService, "_cert_mentions", staticmethod(mentions))
    monkeypatch.setattr(stats_service, "async_search", search)
    monkeypatch.setattr(stats_service, "get_inventory_service", get_inventory)
    monkeypatch.setattr(stats_service.AssetRepository, "create", staticmethod(create_assets))
    return bodies


KEV_DOC = {
    "vuln_id": "CVE-2026-1000",
    "title": "Example RCE",
    "cvss": {"severity": "CRITICAL", "base_score": 9.8},
    "epssScore": 0.42,
    "exploitation": {
        "dateAdded": "2026-10-30",
        "dueDate": "2026-11-20",
        "knownRansomwareCampaignUse": "Known",
    },
    "vendorSlugs": ["acme"],
    "productSlugs": ["widget"],
}


async def test_attention_filters_on_the_kev_date_and_not_on_published(monkeypatch):
    bodies = _wire(monkeypatch)

    await StatsService().get_attention(days=7)

    query = bodies[0]["query"]["bool"]
    assert list(query["should"][0]["range"]) == ["exploitation.dateAdded"]
    assert query["minimum_should_match"] == 1
    assert list(bodies[0]["sort"][0]) == ["exploitation.dateAdded"]


async def test_attention_window_includes_today(monkeypatch):
    bodies = _wire(monkeypatch)

    result = await StatsService().get_attention(days=7, tz="UTC")

    expected = (datetime.now(UTC) - timedelta(days=6)).strftime("%Y-%m-%d")
    assert result["since"] == expected
    assert bodies[0]["query"]["bool"]["should"][0]["range"]["exploitation.dateAdded"]["gte"] == expected


async def test_attention_maps_the_reasons_a_row_shows(monkeypatch):
    _wire(monkeypatch, hits=[KEV_DOC])

    result = await StatsService().get_attention()

    assert result["total"] == 1
    item = result["items"][0]
    assert item["vulnId"] == "CVE-2026-1000"
    assert item["severity"] == "critical"
    assert item["cvssScore"] == 9.8
    assert item["dateAdded"] == "2026-10-30"
    assert item["dueDate"] == "2026-11-20"
    assert item["ransomware"] is True
    assert item["vendors"] == [{"slug": "acme", "name": "Acme"}]
    assert item["products"] == [{"slug": "widget", "name": "WIDGET"}]


@pytest.mark.parametrize("value", ["Unknown", None, ""])
async def test_attention_only_marks_confirmed_ransomware_use(monkeypatch, value):
    doc = {**KEV_DOC, "exploitation": {**KEV_DOC["exploitation"], "knownRansomwareCampaignUse": value}}
    _wire(monkeypatch, hits=[doc])

    result = await StatsService().get_attention()

    assert result["items"][0]["ransomware"] is False


async def test_attention_asks_for_the_cves_the_certs_named(monkeypatch):
    certs = {"CVE-2026-1": [{"name": "CISA", "url": None, "title": "x"}]}
    bodies = _wire(monkeypatch, certs=certs)

    await StatsService().get_attention()

    clauses = bodies[0]["query"]["bool"]["should"]
    assert {"terms": {"vuln_id": ["CVE-2026-1"]}} in clauses
    assert {"terms": {"aliases": ["CVE-2026-1"]}} in clauses


async def test_attention_cuts_lone_mentions_first(monkeypatch):
    lone = {f"CVE-2026-{n}": [{"name": "A", "url": None, "title": None}] for n in range(1000, 1400)}
    shared = {"CVE-2026-9999": [{"name": "A"}, {"name": "B"}]}
    bodies = _wire(monkeypatch, certs={**lone, **shared})

    await StatsService().get_attention()

    asked = bodies[0]["query"]["bool"]["should"][1]["terms"]["vuln_id"]
    assert len(asked) == stats_service.ATTENTION_MAX_CERT_MENTIONS
    assert asked[0] == "CVE-2026-9999"


async def test_attention_attaches_cert_mentions_also_through_an_alias(monkeypatch):
    doc = {**KEV_DOC, "vuln_id": "MAL-2026-1", "aliases": ["cve-2026-1000"], "exploitation": None}
    certs = {
        "CVE-2026-1000": [
            {"name": "CISA", "url": "https://cisa.example/a", "title": "a"},
            {"name": "CERT-FR", "url": "https://fr.example/b", "title": "b"},
        ]
    }
    _wire(monkeypatch, hits=[doc], certs=certs)

    result = await StatsService().get_attention()

    item = result["items"][0]
    assert [cert["name"] for cert in item["certs"]] == ["CISA", "CERT-FR"]
    assert item["kevListed"] is False


async def test_attention_only_counts_a_kev_listing_inside_the_window(monkeypatch):
    old = {**KEV_DOC, "exploitation": {**KEV_DOC["exploitation"], "dateAdded": "2024-01-01"}}
    recent = {
        **KEV_DOC,
        "vuln_id": "CVE-2026-2000",
        "exploitation": {"dateAdded": datetime.now(UTC).strftime("%Y-%m-%d")},
    }
    _wire(monkeypatch, hits=[old, recent])

    result = await StatsService().get_attention()

    assert [item["kevListed"] for item in result["items"]] == [False, True]


async def test_attention_uses_the_version_aware_inventory_matcher(monkeypatch):
    item = {"_id": "inv-1", "vendor_slug": "acme", "product_slug": "widget", "version": "2.0.0"}
    _wire(monkeypatch, hits=[KEV_DOC], inventory=[item])
    seen = []

    def matcher(source, inventory):
        seen.append(source["vuln_id"])
        return inventory

    monkeypatch.setattr(stats_service, "items_for_vuln", matcher)

    result = await StatsService().get_attention()

    assert seen == ["CVE-2026-1000"]
    assert result["items"][0]["inventoryMatchIds"] == ["inv-1"]


async def test_attention_is_empty_when_opensearch_fails(monkeypatch):
    _wire(monkeypatch, error=OSConnectionError("N/A", "down", Exception("down")))

    result = await StatsService().get_attention()

    assert result["total"] == 0
    assert result["items"] == []


async def test_attention_ignores_an_invalid_timezone(monkeypatch):
    _wire(monkeypatch)

    result = await StatsService().get_attention(tz="Not/AZone")

    assert result["items"] == []


async def test_day_summary_is_not_capped_at_two_hundred(monkeypatch):
    bodies = _wire(monkeypatch)

    await StatsService().get_today_summary(date="2026-10-29")

    assert bodies[0]["size"] >= 2000
