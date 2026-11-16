"""Local DB matching for packages without a scanner CVE (SBOM import, fallback).

The former wildcard search on product names gave any package whose name a
product contained the newest CVE of that product, with no vendor and no version
check: a ``console`` package in the vLLM image got Citrix NetScaler Console
CVEs, which then showed up under "Needs attention".
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.models.scan import ScanFindingDocument, ScanSbomComponentDocument
from app.services.scan_service import ScanService

NETSCALER = {
    "_id": "CVE-2026-120869",
    "product_slugs": ["console", "netscaler-console"],
    "published": datetime(2026, 11, 1, tzinfo=UTC),
    "impactedProducts": [
        {"vendor": {"slug": "citrix", "name": "Citrix"}, "product": {"slug": "console", "name": "Console"},
         "versions": ["< 14.1-74.34"]},
    ],
}
LODASH_OLD = {
    "_id": "CVE-2020-8203",
    "product_slugs": ["lodash"],
    "published": datetime(2020, 7, 15, tzinfo=UTC),
    "impactedProducts": [
        {"vendor": {"slug": "npm", "name": "npm"}, "product": {"slug": "lodash", "name": "lodash"},
         "versions": ["< 4.17.19"]},
    ],
}
LODASH_NEW = {
    "_id": "CVE-2021-23337",
    "product_slugs": ["lodash"],
    "published": datetime(2021, 2, 15, tzinfo=UTC),
    "impactedProducts": [
        {"vendor": {"slug": "lodash", "name": "lodash"}, "product": {"slug": "lodash", "name": "lodash"},
         "versions": ["< 4.17.21"]},
    ],
}


class _Cursor:
    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self._docs = docs

    def limit(self, _n: int) -> _Cursor:
        return self

    def max_time_ms(self, _ms: int) -> _Cursor:
        return self

    def __aiter__(self):
        async def gen():
            for doc in self._docs:
                yield doc
        return gen()


class _Vulns:
    """Array-aware ``$in`` on ``product_slugs``, like MongoDB's multikey match."""

    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self.docs = docs
        self.queries: list[dict[str, Any]] = []

    def find(self, query: dict[str, Any], _projection: Any = None) -> _Cursor:
        self.queries.append(query)
        wanted = set(query["product_slugs"]["$in"])
        return _Cursor([d for d in self.docs if wanted & set(d.get("product_slugs", []))])


def _service() -> ScanService:
    return ScanService(
        target_repo=None, scan_repo=None, finding_repo=None, sbom_repo=None, layer_repo=None, audit_service=None
    )


async def test_a_shared_name_from_another_vendor_is_no_match() -> None:
    vulns = _Vulns([NETSCALER])
    matches = await _service()._local_vulnerability_matches(
        [("console", "0.15.11", "pkg:pypi/console@0.15.11"), ("console", "0.15.11", "pkg:npm/console@0.15.11")],
        vulns,
    )
    assert matches == {}


async def test_version_and_vendor_decide_and_newest_comes_first() -> None:
    vulns = _Vulns([LODASH_OLD, LODASH_NEW, NETSCALER])
    key_old = ("lodash", "4.17.15", "pkg:npm/lodash@4.17.15")
    key_mid = ("lodash", "4.17.20", "pkg:npm/lodash@4.17.20")
    key_fixed = ("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")
    matches = await _service()._local_vulnerability_matches([key_old, key_mid, key_fixed], vulns)
    assert matches[key_old] == ["CVE-2021-23337", "CVE-2020-8203"]
    assert matches[key_mid] == ["CVE-2021-23337"]
    assert key_fixed not in matches
    # One indexed query for all slugs, no per-package search.
    assert len(vulns.queries) == 1


async def test_the_fallback_leaves_a_name_only_finding_without_a_cve(monkeypatch) -> None:
    service = _service()
    vulns = _Vulns([NETSCALER, LODASH_NEW])
    written: list[tuple[str, str]] = []

    class _Findings:
        async def update_vulnerability_id(self, _scan, name, _version, cve, matched_from):
            written.append((name, cve))

    service.finding_repo = _Findings()  # type: ignore[assignment]
    original = service._local_vulnerability_matches

    async def with_fake_db(components, vuln_collection=None):
        return await original(components, vulns)

    monkeypatch.setattr(service, "_local_vulnerability_matches", with_fake_db)
    console = ScanFindingDocument(scan_id="s", target_id="t", scanner="x", package_name="console",
                                  package_version="0.15.11", package_type="python")
    lodash = ScanFindingDocument(scan_id="s", target_id="t", scanner="x", package_name="lodash",
                                 package_version="4.17.20", package_type="npm")
    components = [ScanSbomComponentDocument(scan_id="s", target_id="t", name="console", version="0.15.11",
                                            purl="pkg:pypi/console@0.15.11")]
    await service._match_cve_for_unmatched_findings("s", [console, lodash], components)

    assert console.vulnerability_id is None
    assert lodash.vulnerability_id == "CVE-2021-23337"
    assert written == [("lodash", "CVE-2021-23337")]
