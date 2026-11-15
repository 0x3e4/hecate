"""Version-checked SBOM coverage for the dashboard and the advisories page.

``ScanService.sbom_version_hits`` puts a scan on a CVE row only when a package of
the latest completed scan per target sits at a version the CVE affects. A
matching name alone (the old ``productScan`` map) is no hit.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from bson import ObjectId

from app.services import scan_service as scan_service_module
from app.services.scan_service import ScanService
from app.services.sbom_ecosystem import affected_entries_by_slug, component_in_affected_range

SCAN_OLD = str(ObjectId())
SCAN_NEW = str(ObjectId())


def _matches(doc: dict, query: dict) -> bool:
    for key, cond in query.items():
        value = doc.get(key)
        if isinstance(cond, dict):
            if "$in" in cond and value not in cond["$in"]:
                return False
            if "$ne" in cond and value == cond["$ne"]:
                return False
        elif value != cond:
            return False
    return True


class _Cursor:
    def __init__(self, docs):
        self._docs = iter(docs)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._docs)
        except StopIteration:
            raise StopAsyncIteration from None


class _Collection:
    def __init__(self, docs):
        self.docs = docs
        self.queries = 0

    def find(self, query, _projection=None):
        self.queries += 1
        return _Cursor([d for d in self.docs if _matches(d, query)])


class _Repo:
    def __init__(self, docs, latest_ids=None):
        self.collection = _Collection(docs)
        self._latest_ids = latest_ids or []

    async def get_latest_completed_scan_ids(self, target_id=None):
        return list(self._latest_ids)


@pytest.fixture(autouse=True)
def _fresh_coverage_cache(monkeypatch):
    monkeypatch.setattr(scan_service_module, "_coverage_state", None)
    monkeypatch.setattr(scan_service_module, "_coverage_state_at", 0.0)


def _service(components, findings=()):
    scans = [
        {"_id": ObjectId(SCAN_OLD), "created_at": datetime(2026, 11, 1, tzinfo=UTC), "target_name": "old"},
        {"_id": ObjectId(SCAN_NEW), "created_at": datetime(2026, 11, 10, tzinfo=UTC), "target_name": "new"},
    ]
    scan_repo = _Repo(scans, latest_ids=[SCAN_OLD, SCAN_NEW])
    sbom_repo = _Repo(list(components))
    finding_repo = _Repo(list(findings))
    svc = ScanService(
        target_repo=None,
        scan_repo=scan_repo,
        finding_repo=finding_repo,
        sbom_repo=sbom_repo,
        layer_repo=None,
        audit_service=None,
    )
    return svc, sbom_repo


def _component(name, version, scan_id=SCAN_NEW, purl=None):
    return {"name": name, "version": version, "scan_id": scan_id, "purl": purl}


NODE_CVE = {
    "vuln_id": "CVE-2026-48933",
    "impactedProducts": [
        {"vendor": {"slug": "nodejs", "name": "Node.js"}, "product": {"slug": "node", "name": "Node"},
         "versions": [">= 22.0.0, < 22.22.4"]},
    ],
}


async def test_version_inside_the_range_is_a_hit():
    svc, _ = _service([_component("node", "22.22.3")])

    assert await svc.sbom_version_hits([NODE_CVE]) == {"CVE-2026-48933": SCAN_NEW}


async def test_version_outside_the_range_is_no_hit():
    svc, _ = _service([_component("node", "22.22.4"), _component("node", "20.0.0")])

    assert await svc.sbom_version_hits([NODE_CVE]) == {}


async def test_the_most_recent_covering_scan_wins():
    svc, _ = _service([_component("node", "22.1.0", SCAN_OLD), _component("node", "22.2.0", SCAN_NEW)])

    assert await svc.sbom_version_hits([NODE_CVE]) == {"CVE-2026-48933": SCAN_NEW}


async def test_a_registry_package_of_another_vendor_is_no_hit():
    citrix = {
        "vuln_id": "CVE-2026-120869",
        "impactedProducts": [
            {"vendor": {"slug": "citrix-netscaler", "name": "Citrix NetScaler"},
             "product": {"slug": "console", "name": "Console"}, "versions": ["< 14.1-74.34"]},
        ],
    }
    lodash = {
        "vuln_id": "GHSA-lodash",
        "impactedProducts": [
            {"vendor": {"slug": "npm"}, "product": {"slug": "lodash"}, "versions": ["< 4.17.21"]},
        ],
    }
    svc, _ = _service([
        _component("console", "0.15.11", purl="pkg:npm/console@0.15.11"),
        _component("lodash", "4.17.20", SCAN_OLD, purl="pkg:npm/lodash@4.17.20"),
    ])

    assert await svc.sbom_version_hits([citrix, lodash]) == {"GHSA-lodash": SCAN_OLD}


async def test_a_finding_only_cve_gets_no_sbom_hit_and_stays_in_cve_scan():
    finding = {"vulnerability_id": "CVE-2026-1", "scan_id": SCAN_OLD}
    svc, _ = _service([_component("node", "22.22.3")], findings=[finding])
    unrelated = {
        "vuln_id": "CVE-2026-1",
        "impactedProducts": [{"product": {"slug": "openssl"}, "versions": ["< 3.0.15"]}],
    }

    assert await svc.sbom_version_hits([unrelated]) == {}
    coverage = await svc.get_dashboard_coverage()
    assert coverage["cveScan"] == {"CVE-2026-1": SCAN_OLD}
    assert coverage["scanTargets"] == {SCAN_OLD: "old", SCAN_NEW: "new"}
    assert "productScan" not in coverage


async def test_snake_case_products_and_entries_without_versions():
    doc = {
        "vuln_id": "CVE-2",
        "impacted_products": [
            {"product": {"slug": "node"}, "versions": []},
            {"product": {"slug": "node"}, "versions": ["22.22.3"]},
        ],
    }
    svc, _ = _service([_component("node", "22.22.3")])

    assert await svc.sbom_version_hits([doc, {"vuln_id": "CVE-3"}]) == {"CVE-2": SCAN_NEW}


async def test_the_sbom_index_is_read_once_for_many_cves():
    svc, sbom_repo = _service([_component("node", "22.22.3")])
    docs = [{**NODE_CVE, "vuln_id": f"CVE-2026-{n}"} for n in range(2000)]

    hits = await svc.sbom_version_hits(docs)
    await svc.sbom_version_hits(docs)
    await svc.get_dashboard_coverage()

    assert len(hits) == 2000
    assert sbom_repo.collection.queries == 1


async def test_versions_per_package_and_scan_are_capped_in_the_index():
    # An imported SBOM with thousands of versions of one package made every
    # suggest / dashboard request walk all of them on the event loop.
    limit = scan_service_module.COVERAGE_MAX_VERSIONS_PER_SLUG_SCAN
    flood = [_component("node", f"999.{i}.0") for i in range(limit * 10)]
    svc, _ = _service([*flood, _component("node", "22.22.3", SCAN_OLD)])

    state = await svc._load_coverage_state()

    new_versions = {c.version for c in state.sbom_by_slug["node"] if c.scan_id == SCAN_NEW}
    assert len(new_versions) == limit
    # Another scan's versions are counted separately and still hit.
    assert await svc.sbom_version_hits([NODE_CVE]) == {"CVE-2026-48933": SCAN_OLD}


async def test_hits_stop_at_the_time_budget(monkeypatch):
    svc, _ = _service([_component("node", "22.22.3")])
    monkeypatch.setattr(scan_service_module, "SBOM_HITS_BUDGET_SECONDS", -1.0)

    assert await svc.sbom_version_hits([NODE_CVE]) == {}


async def test_fail_soft_on_a_broken_index(monkeypatch):
    svc, _ = _service([_component("node", "22.22.3")])

    async def broken():
        raise RuntimeError("mongo down")

    monkeypatch.setattr(svc, "_load_coverage_state", broken)

    assert await svc.sbom_version_hits([NODE_CVE]) == {}


def test_component_match_takes_the_whole_range_list_and_the_vendor_rule():
    entries, names = affected_entries_by_slug([
        {"vendor": {"slug": "npm"}, "product": {"slug": "lodash", "name": "Lodash"}, "versions": ["< 4.17.21"]},
        {"vendor": {"slug": "acme"}, "product": {"slug": "lodash"}, "versions": ["< 99"]},
        {"product": {"slug": "node"}, "versions": ["1.0"], "vulnerable": False},
    ])
    assert {"lodash", "Lodash"} <= names
    assert "node" not in entries
    npm = "pkg:npm/lodash@4.17.20"
    assert component_in_affected_range(entries, name="lodash", version="4.17.20", purl=npm)
    assert not component_in_affected_range(entries, name="lodash", version="4.17.21", purl="pkg:npm/lodash@4.17.21")
    # An OS package takes every entry's ranges, the acme one included.
    assert component_in_affected_range(entries, name="lodash", version="50", purl="pkg:deb/debian/lodash@50")
    assert not component_in_affected_range(entries, name="lodash", version="", purl=npm)
