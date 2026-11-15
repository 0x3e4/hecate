"""Name-only "possibly affected" matches for advisories without version data."""
from __future__ import annotations

from typing import Any

from app.services.possibly_affected import (
    has_version_evidence,
    inventory_name_matches,
    named_products,
    possibly_affected_for_vuln,
    sbom_component_fits,
)

NO_VERSIONS = {
    "vendors": ["Citrix"],
    "products": ["NetScaler Console"],
    "impactedProducts": [
        {"vendor": {"name": "Citrix", "slug": "citrix"},
         "product": {"name": "Console", "slug": "console"}, "versions": []},
    ],
    "cpes": ["cpe:2.3:a:citrix:console:*:*:*:*:*:*:*:*"],
}

WITH_VERSIONS = {
    **NO_VERSIONS,
    "impactedProducts": [
        {"vendor": {"name": "Citrix", "slug": "citrix"},
         "product": {"name": "Console", "slug": "console"}, "versions": ["< 14.1-74.34"]},
    ],
}

INVENTORY = [
    {"_id": "i1", "name": "NetScaler Console", "vendor_slug": "citrix", "product_slug": "console", "version": "14.1"},
    {"_id": "i2", "name": "Some console", "vendor_slug": "acme", "product_slug": "console", "version": "1.0"},
    {"_id": "i3", "name": "Other", "vendor_slug": "citrix", "product_slug": "adc", "version": "13"},
]


def test_version_evidence_is_decided_like_the_matcher() -> None:
    assert has_version_evidence(NO_VERSIONS) is False  # [] and a wildcard CPE are no evidence
    assert has_version_evidence(WITH_VERSIONS) is True
    assert has_version_evidence({**NO_VERSIONS, "cpes": ["cpe:2.3:a:citrix:console:14.1:*:*:*:*:*:*:*"]}) is True


def test_named_products_pair_vendors() -> None:
    products, raw = named_products(NO_VERSIONS)
    assert products["console"] >= {"citrix"}
    assert "netscaler-console" in products
    assert "Console" in raw and "console" in raw


def test_inventory_matches_by_product_and_vendor() -> None:
    products, _ = named_products(NO_VERSIONS)
    rows = inventory_name_matches(products, INVENTORY)
    assert [r["itemId"] for r in rows] == ["i1"]
    assert rows[0]["kind"] == "inventory"


def test_registry_packages_need_a_fitting_vendor() -> None:
    products, _ = named_products(NO_VERSIONS)
    # npm "console" is not Citrix Console.
    assert sbom_component_fits(products, "console", "pkg:npm/console@0.15.11") is False
    # A distro / binary package keeps the plain name match.
    assert sbom_component_fits(products, "console", "pkg:deb/debian/console@1") is True
    assert sbom_component_fits(products, "console", None) is True
    # A registry package whose namespace is the vendor fits.
    npm_vuln = {"impactedProducts": [{"vendor": {"name": "npm", "slug": "npm"},
                                      "product": {"name": "left-pad", "slug": "left-pad"}, "versions": []}]}
    npm_products, _ = named_products(npm_vuln)
    assert sbom_component_fits(npm_products, "left-pad", "pkg:npm/left-pad@1.3.0") is True
    # Without any vendor a registry package is not matched on its name alone.
    bare, _ = named_products({"products": ["left-pad"]})
    assert sbom_component_fits(bare, "left-pad", "pkg:npm/left-pad@1.3.0") is False


class FakeCursor:
    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self.docs = docs

    def limit(self, _n: int) -> FakeCursor:
        return self

    def max_time_ms(self, ms: int) -> FakeCursor:
        assert ms > 0
        return self

    def __aiter__(self) -> Any:
        async def gen() -> Any:
            for d in self.docs:
                yield d
        return gen()


class FakeSbomCollection:
    def __init__(self) -> None:
        self.queries: list[dict[str, Any]] = []

    def find(self, query: dict[str, Any], _projection: Any) -> FakeCursor:
        self.queries.append(query)
        docs = [
            {"scan_id": "s1", "target_id": "t1", "name": "console", "version": "0.15.11", "purl": "pkg:npm/console@0.15.11"},
            {"scan_id": "s1", "target_id": "t1", "name": "console", "version": "14.1", "purl": None},
        ]
        return FakeCursor([d for d in docs if d["name"] in query["name"]["$in"]])


class FakeScanService:
    def __init__(self) -> None:
        self.sbom_repo = type("R", (), {"collection": FakeSbomCollection()})()

        class ScanRepo:
            async def get_latest_completed_scan_ids(self) -> list[str]:
                return ["s1"]

            async def get(self, _sid: str) -> dict[str, Any]:
                return {"target_name": "netscaler-appliance"}

        self.scan_repo = ScanRepo()


async def test_possibly_affected_lists_inventory_and_sbom_only_without_versions() -> None:
    service = FakeScanService()
    rows = await possibly_affected_for_vuln(NO_VERSIONS, inventory=INVENTORY, scan_service=service)
    assert [r["kind"] for r in rows] == ["inventory", "sbom"]
    sbom = rows[1]
    assert sbom["packageVersion"] == "14.1" and sbom["targetName"] == "netscaler-appliance"
    query = service.sbom_repo.collection.queries[0]
    assert query["scan_id"] == {"$in": ["s1"]} and "$in" in query["name"]

    assert await possibly_affected_for_vuln(WITH_VERSIONS, inventory=INVENTORY, scan_service=service) == []
