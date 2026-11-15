"""Statistics asset cards: the catalogue entries most vulnerabilities name, by slug,
dressed with catalogue names, aliases and breadth from indexed lookups only."""
from __future__ import annotations

from opensearchpy.exceptions import ConnectionError as OSConnectionError

from app.services import stats_service
from app.services.stats_service import StatsService, _primary_vendor_slug


class _Count:
    def __init__(self, value: int) -> None:
        self.value = value
        self.filters: list[dict] = []

    async def count_documents(self, query, **_kwargs):
        self.filters.append(query)
        return self.value


class _Repo:
    def __init__(self) -> None:
        self.vendors = _Count(40)
        self.products = _Count(400)
        self.versions = _Count(4000)
        self.calls: dict[str, list] = {}

    async def find_vendors_by_slugs(self, slugs):
        self.calls.setdefault("vendors", []).append(list(slugs))
        known = {
            "microsoft": {"_id": "microsoft", "displayName": "Microsoft", "aliases": ["microsoft", "Microsoft Corp.", "MSFT"]},
            "wordpress": {"_id": "wordpress", "displayName": "WordPress", "aliases": []},
        }
        return [known[slug] for slug in slugs if slug in known]

    async def find_products_by_slugs(self, slugs):
        known = {
            "windows-10": {"_id": "windows-10", "displayName": "Windows 10", "aliases": ["Windows 10", "win10"],
                           "vendorSlugs": ["microsoft"]},
            "wordpress": {"_id": "wordpress", "displayName": "WordPress", "aliases": [],
                          "vendorSlugs": ["automattic", "npm", "wordpress", "zz-plugins"]},
        }
        return [known[slug] for slug in slugs if slug in known]

    async def count_products_by_vendor(self, slugs, *, max_time_ms):
        assert max_time_ms > 0
        return {slug: 7 for slug in slugs}

    async def count_versions_by_product(self, slugs, *, max_time_ms):
        assert max_time_ms > 0
        return {slug: 12 for slug in slugs}


def _wire(monkeypatch, *, error=None):
    repo = _Repo()
    bodies: list[dict] = []

    async def create():
        return repo

    async def search(_index, body, **_kwargs):
        bodies.append(body)
        if error:
            raise error
        return {
            "aggregations": {
                "vendors": {"buckets": [
                    {"key": "microsoft", "doc_count": 900},
                    {"key": "orphan-vendor", "doc_count": 5},
                ]},
                "products": {"buckets": [
                    {"key": "windows-10", "doc_count": 800},
                    {"key": "wordpress", "doc_count": 300},
                ]},
            }
        }

    monkeypatch.setattr(stats_service.AssetRepository, "create", staticmethod(create))
    monkeypatch.setattr(stats_service, "async_search", search)
    return repo, bodies


async def test_asset_cards_rank_catalogue_slugs_by_vulnerabilities(monkeypatch):
    repo, bodies = _wire(monkeypatch)
    result = await StatsService()._fetch_asset_stats()

    assert result["vendorTotal"] == 40
    assert result["productTotal"] == 400
    assert result["versionTotal"] == 4000

    microsoft, orphan = result["topVendors"]
    assert microsoft == {
        "slug": "microsoft",
        "name": "Microsoft",
        "aliases": ["Microsoft Corp.", "MSFT"],  # the case variant of the name is dropped
        "vulnerabilityCount": 900,
        "productCount": 7,
        "inCatalog": True,
    }
    assert orphan["name"] == "orphan-vendor" and orphan["inCatalog"] is False

    windows, wordpress = result["topProducts"]
    assert windows["vendor"] == {"slug": "microsoft", "name": "Microsoft"}
    assert windows["versionCount"] == 12
    assert windows["aliases"] == ["win10"]
    # The vendor sharing the product's name wins over plugin vendors and registries.
    assert wordpress["vendor"] == {"slug": "wordpress", "name": "WordPress"}

    aggs = bodies[0]["aggs"]
    assert aggs["vendors"]["terms"]["size"] == stats_service.ASSET_RANKING_SIZE
    assert "npm" in aggs["vendors"]["terms"]["exclude"]
    assert "n-a" in aggs["products"]["terms"]["exclude"]
    assert "npm" not in aggs["products"]["terms"]["exclude"]


async def test_asset_ranking_is_fail_soft_without_opensearch(monkeypatch):
    _wire(monkeypatch, error=OSConnectionError("N/A", "down", None))
    result = await StatsService()._fetch_asset_stats()
    assert result["topVendors"] == [] and result["topProducts"] == []
    assert result["vendorTotal"] == 40


def test_primary_vendor_follows_the_catalog_rule():
    assert _primary_vendor_slug("wordpress", ["automattic", "wordpress"]) == "wordpress"
    assert _primary_vendor_slug("apache-tomcat", ["a-plugin", "apache"]) == "apache"
    assert _primary_vendor_slug("left-pad", ["npm", "someone"]) == "someone"
    assert _primary_vendor_slug("left-pad", ["npm"]) == "npm"
    assert _primary_vendor_slug("orphan", []) is None
