"""Unit tests for the three target/finding/CVE-detail features:

1. ``advisory_fixed_versions`` — advisory unaffected/patched versions surfaced
   as a fix hint in the Findings tab.
2. ``ScanService.get_target_sbom_diff`` — SBOM delta between a target's two
   most-recent completed scans (target detail "SBOM changes" card).
3. ``ScanService.affected_scan_targets_for_vuln`` — reverse lookup that powers
   the "Affected in your scans" block on the CVE detail page.

The service methods only touch the repos, so they're exercised with light
fakes (no MongoDB).
"""
from __future__ import annotations

import pytest

from app.services.scan_service import ScanService, advisory_fixed_versions


# --------------------------------------------------------------------------
# advisory_fixed_versions (pure function)
# --------------------------------------------------------------------------


def test_advisory_fixed_versions_matches_package_and_merges():
    entries = [
        {
            "product": {"slug": "lodash", "name": "lodash"},
            "unaffectedVersions": ["4.17.21"],
            "patchedVersions": ["4.18.0"],
        },
        {
            "product": {"slug": "axios", "name": "axios"},
            "unaffectedVersions": ["1.7.0"],
        },
    ]
    # Only the matched product's versions, unaffected before patched.
    assert advisory_fixed_versions(entries, "lodash") == ["4.17.21", "4.18.0"]


def test_advisory_fixed_versions_dedup_and_snake_case():
    entries = [
        {
            "product": {"name": "Foo"},
            "unaffected_versions": ["1.0", "1.0"],
            "patched_versions": ["1.0", "2.0"],
        },
    ]
    assert advisory_fixed_versions(entries, "foo") == ["1.0", "2.0"]


def test_advisory_fixed_versions_fallback_when_no_name_match():
    entries = [{"product": {"slug": "libfoo", "name": "libfoo"}, "patchedVersions": ["9.9"]}]
    # No product matches the package name → union across all entries.
    assert advisory_fixed_versions(entries, "something-else") == ["9.9"]


def test_advisory_fixed_versions_only_matched_product_when_match_exists():
    entries = [
        {"product": {"name": "lodash"}, "patchedVersions": ["4.17.21"]},
        {"product": {"name": "axios"}, "patchedVersions": ["1.7.0"]},
    ]
    assert advisory_fixed_versions(entries, "lodash") == ["4.17.21"]


def test_advisory_fixed_versions_empty_inputs():
    assert advisory_fixed_versions([], "lodash") == []
    assert advisory_fixed_versions([{"product": {"name": "x"}}], "x") == []


def test_advisory_fixed_versions_cap():
    entries = [{"product": {"name": "x"}, "unaffectedVersions": [str(i) for i in range(20)]}]
    assert len(advisory_fixed_versions(entries, "x", cap=5)) == 5


# --------------------------------------------------------------------------
# Fakes + service factory
# --------------------------------------------------------------------------


class _FakeScanRepo:
    def __init__(self, recent=None, scans=None, latest_ids=None):
        self._recent = recent or []
        self._scans = scans or {}
        self._latest_ids = latest_ids or []

    async def get_recent_completed(self, target_id, n=2):
        return self._recent[:n]

    async def get(self, scan_id):
        return self._scans.get(scan_id)

    async def get_latest_completed_scan_ids(self, target_id=None):
        return list(self._latest_ids)


class _FakeSbomRepo:
    def __init__(self, rows_by_scan=None, components=None):
        self._rows = rows_by_scan or {}
        self._components = components or []

    async def list_all_by_scan(self, scan_id):
        return self._rows.get(scan_id, [])

    async def find_components_in_scans(self, scan_ids, names):
        name_set = set(names)
        scan_set = set(scan_ids)
        return [
            c for c in self._components
            if c.get("scan_id") in scan_set and c.get("name") in name_set
        ]


class _FakeFindingRepo:
    def __init__(self, findings):
        self._findings = findings

    async def find_by_vulnerability_ids(self, ids, limit=100, offset=0):
        hits = [
            f for f in self._findings
            if f.get("vulnerability_id") in set(ids) and not f.get("dismissed")
        ]
        return len(hits), hits[offset : offset + limit]


class _FakeTargetRepo:
    def __init__(self, targets):
        self._targets = targets

    async def get(self, target_id):
        return self._targets.get(target_id)


def _make_service(*, scan_repo=None, sbom_repo=None, finding_repo=None, target_repo=None):
    return ScanService(
        target_repo=target_repo,
        scan_repo=scan_repo,
        finding_repo=finding_repo,
        sbom_repo=sbom_repo,
        layer_repo=None,
        audit_service=None,
    )


# --------------------------------------------------------------------------
# get_target_sbom_diff
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sbom_diff_two_scans_classifies_added_updated_removed():
    recent = [
        {"_id": "s2", "started_at": "2026-06-26T10:00:00Z", "commit_sha": "abc1234def"},
        {"_id": "s1", "started_at": "2026-06-25T10:00:00Z", "commit_sha": "old9999"},
    ]
    rows = {
        "s2": [
            {"name": "lodash", "version": "4.17.21"},  # updated (was 4.17.20)
            {"name": "newpkg", "version": "1.0.0"},     # added
            {"name": "stable", "version": "2.0.0"},     # unchanged
        ],
        "s1": [
            {"name": "lodash", "version": "4.17.20"},
            {"name": "oldpkg", "version": "3.0.0"},     # removed
            {"name": "stable", "version": "2.0.0"},
        ],
    }
    svc = _make_service(scan_repo=_FakeScanRepo(recent=recent), sbom_repo=_FakeSbomRepo(rows))
    diff = await svc.get_target_sbom_diff("t1")

    assert diff["latest_scan_id"] == "s2"
    assert diff["previous_scan_id"] == "s1"
    assert diff["latest_commit_sha"] == "abc1234def"
    assert diff["component_total"] == 3

    assert [e["name"] for e in diff["added"]] == ["newpkg"]
    assert diff["added_count"] == 1

    assert diff["updated_count"] == 1
    upd = diff["updated"][0]
    assert upd["name"] == "lodash"
    assert upd["previous_version"] == "4.17.20"
    assert upd["version"] == "4.17.21"

    assert [e["name"] for e in diff["removed"]] == ["oldpkg"]
    assert diff["removed_count"] == 1


@pytest.mark.asyncio
async def test_sbom_diff_baseline_single_scan():
    recent = [{"_id": "s1", "started_at": None, "commit_sha": None}]
    rows = {"s1": [{"name": "a", "version": "1"}, {"name": "b", "version": "2"}]}
    svc = _make_service(scan_repo=_FakeScanRepo(recent=recent), sbom_repo=_FakeSbomRepo(rows))
    diff = await svc.get_target_sbom_diff("t1")

    assert diff["latest_scan_id"] == "s1"
    assert diff["previous_scan_id"] is None
    assert diff["component_total"] == 2
    assert diff["added"] == [] and diff["updated"] == [] and diff["removed"] == []


@pytest.mark.asyncio
async def test_sbom_diff_no_scans():
    svc = _make_service(scan_repo=_FakeScanRepo(), sbom_repo=_FakeSbomRepo({}))
    diff = await svc.get_target_sbom_diff("t1")
    assert diff["latest_scan_id"] is None
    assert diff["component_total"] == 0


# --------------------------------------------------------------------------
# affected_scan_targets_for_vuln
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_affected_scan_targets_dedup_resolve_and_alias():
    findings = [
        {
            "vulnerability_id": "CVE-2024-1", "target_id": "tA", "scan_id": "sA",
            "package_name": "lodash", "package_version": "4.17.20", "severity": "high",
            "scanner": "trivy", "fix_version": "4.17.21", "cvss_score": 7.5,
        },
        # Same (target, package, version) from another scanner → deduped away.
        {
            "vulnerability_id": "CVE-2024-1", "target_id": "tA", "scan_id": "sA",
            "package_name": "lodash", "package_version": "4.17.20", "severity": "high",
            "scanner": "grype",
        },
        # Alias match, different target; scan doc has no target_name → fallback.
        {
            "vulnerability_id": "GHSA-xxxx", "target_id": "tB", "scan_id": "sB",
            "package_name": "axios", "package_version": "1.6.0", "severity": "medium",
            "scanner": "osv-scanner",
        },
        # Dismissed → excluded by the repo fake.
        {
            "vulnerability_id": "CVE-2024-1", "target_id": "tC", "scan_id": "sC",
            "package_name": "express", "package_version": "4.0.0", "severity": "low",
            "scanner": "trivy", "dismissed": True,
        },
    ]
    scans = {"sA": {"target_name": "Target A"}, "sB": {}}
    targets = {"tB": {"name": "Target B"}}
    svc = _make_service(
        scan_repo=_FakeScanRepo(scans=scans),
        finding_repo=_FakeFindingRepo(findings),
        target_repo=_FakeTargetRepo(targets),
    )
    res = await svc.affected_scan_targets_for_vuln(["CVE-2024-1", "GHSA-xxxx"], limit=25)

    assert len(res) == 2
    by_target = {r["targetId"]: r for r in res}
    assert by_target["tA"]["targetName"] == "Target A"
    assert by_target["tA"]["fixVersion"] == "4.17.21"
    assert by_target["tA"]["scanId"] == "sA"
    assert by_target["tB"]["targetName"] == "Target B"
    assert "tC" not in by_target  # dismissed excluded


@pytest.mark.asyncio
async def test_affected_scan_targets_empty_ids():
    svc = _make_service(finding_repo=_FakeFindingRepo([]))
    assert await svc.affected_scan_targets_for_vuln([]) == []


@pytest.mark.asyncio
async def test_affected_scan_targets_sbom_version_checked():
    # No findings; the package only sits in the SBOM (stale scan).
    impacted = [{"product": {"slug": "node", "name": "Node"}, "versions": [">=22.22.3, <=22.22.3"]}]
    components = [
        {"name": "node", "version": "22.22.3", "scan_id": "sX", "target_id": "tX"},  # affected
        {"name": "node", "version": "20.0.0", "scan_id": "sX", "target_id": "tX"},   # not in range
        {"name": "pytest", "version": "9.0.2", "scan_id": "sX", "target_id": "tX"},  # not a candidate name
    ]
    svc = _make_service(
        scan_repo=_FakeScanRepo(scans={"sX": {"target_name": "Prod API"}}, latest_ids=["sX"]),
        finding_repo=_FakeFindingRepo([]),
        sbom_repo=_FakeSbomRepo(components=components),
        target_repo=_FakeTargetRepo({}),
    )
    res = await svc.affected_scan_targets_for_vuln(
        ["CVE-2026-48933"], impacted_products=impacted, limit=25
    )
    assert len(res) == 1
    row = res[0]
    assert row["matchType"] == "sbom"
    assert row["packageName"] == "node" and row["packageVersion"] == "22.22.3"
    assert row["targetName"] == "Prod API"
    assert row["scanner"] == "" and row["fixVersion"] is None


@pytest.mark.asyncio
async def test_affected_scan_targets_sbom_skipped_when_finding_covers():
    # A finding already covers node on tX → the SBOM hit must not duplicate it.
    findings = [{
        "vulnerability_id": "CVE-2026-48933", "target_id": "tX", "scan_id": "sX",
        "package_name": "node", "package_version": "22.22.3", "severity": "high",
        "scanner": "osv-scanner",
    }]
    impacted = [{"product": {"slug": "node", "name": "Node"}, "versions": [">=22.22.3, <=22.22.3"]}]
    components = [{"name": "node", "version": "22.22.3", "scan_id": "sX", "target_id": "tX"}]
    svc = _make_service(
        scan_repo=_FakeScanRepo(scans={"sX": {"target_name": "Prod API"}}, latest_ids=["sX"]),
        finding_repo=_FakeFindingRepo(findings),
        sbom_repo=_FakeSbomRepo(components=components),
        target_repo=_FakeTargetRepo({}),
    )
    res = await svc.affected_scan_targets_for_vuln(
        ["CVE-2026-48933"], impacted_products=impacted, limit=25
    )
    assert len(res) == 1
    assert res[0]["matchType"] == "finding"
