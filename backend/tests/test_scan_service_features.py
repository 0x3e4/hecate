"""Unit tests for the three target/finding/CVE-detail features:

1. ``advisory_fixed_versions`` — advisory unaffected/patched versions surfaced
   as a fix hint in the Findings tab.
2. ``ScanService.get_target_sbom_diff`` — SBOM delta for a target, walking
   back through scan history to the last pair that actually changed (target
   detail "SBOM changes" card).
3. ``ScanService.affected_scan_targets_for_vuln`` — reverse lookup that powers
   the "Affected in your scans" block on the CVE detail page.
4. ``ScanService.delete_target`` / ``delete_scan`` — cascade cleanup of scan
   data, including the background-task deletion path.

The service methods only touch the repos, so they're exercised with light
fakes (no MongoDB).
"""
from __future__ import annotations

import pytest

from app.services import scan_service as scan_service_module
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
        self.deleted_by_target = []
        self.deleted_scan_ids = []

    async def get_recent_completed(self, target_id, n=2):
        return self._recent[:n]

    async def get(self, scan_id):
        return self._scans.get(scan_id)

    async def get_latest_completed_scan_ids(self, target_id=None):
        return list(self._latest_ids)

    async def delete_by_target(self, target_id):
        self.deleted_by_target.append(target_id)
        return len([s for s in self._scans.values() if s.get("target_id") == target_id])

    async def delete(self, scan_id):
        self.deleted_scan_ids.append(scan_id)
        return scan_id in self._scans


class _FakeSbomRepo:
    def __init__(self, rows_by_scan=None, components=None):
        self._rows = rows_by_scan or {}
        self._components = components or []
        self.deleted_by_target = []
        self.deleted_by_scan = []

    async def list_all_by_scan(self, scan_id):
        return self._rows.get(scan_id, [])

    async def find_components_in_scans(self, scan_ids, names):
        name_set = set(names)
        scan_set = set(scan_ids)
        return [
            c for c in self._components
            if c.get("scan_id") in scan_set and c.get("name") in name_set
        ]

    async def delete_by_target(self, target_id):
        self.deleted_by_target.append(target_id)
        return 0

    async def delete_by_scan(self, scan_id):
        self.deleted_by_scan.append(scan_id)
        return 0


class _FakeFindingRepo:
    def __init__(self, findings=None):
        self._findings = findings or []
        self.deleted_by_target = []
        self.deleted_by_scan = []

    async def find_by_vulnerability_ids(self, ids, limit=100, offset=0):
        hits = [
            f for f in self._findings
            if f.get("vulnerability_id") in set(ids) and not f.get("dismissed")
        ]
        return len(hits), hits[offset : offset + limit]

    async def delete_by_target(self, target_id):
        self.deleted_by_target.append(target_id)
        return 0

    async def delete_by_scan(self, scan_id):
        self.deleted_by_scan.append(scan_id)
        return 0


class _FakeTargetRepo:
    def __init__(self, targets=None):
        self._targets = targets or {}
        self.deleted_ids = []

    async def get(self, target_id):
        return self._targets.get(target_id)

    async def delete(self, target_id):
        self.deleted_ids.append(target_id)
        return self._targets.pop(target_id, None) is not None

    async def list_ids(self):
        return list(self._targets.keys())


class _FakeLayerRepo:
    def __init__(self):
        self.deleted_by_target = []
        self.deleted_by_scan = []

    async def delete_by_target(self, target_id):
        self.deleted_by_target.append(target_id)
        return 0

    async def delete_by_scan(self, scan_id):
        self.deleted_by_scan.append(scan_id)
        return 0


def _make_service(*, scan_repo=None, sbom_repo=None, finding_repo=None, target_repo=None, layer_repo=None):
    return ScanService(
        target_repo=target_repo,
        scan_repo=scan_repo,
        finding_repo=finding_repo,
        sbom_repo=sbom_repo,
        layer_repo=layer_repo,
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
    assert diff["changed_scan_id"] == "s2"
    assert diff["changed_commit_sha"] == "abc1234def"

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
    assert diff["changed_scan_id"] == "s1"


@pytest.mark.asyncio
async def test_sbom_diff_no_scans():
    svc = _make_service(scan_repo=_FakeScanRepo(), sbom_repo=_FakeSbomRepo({}))
    diff = await svc.get_target_sbom_diff("t1")
    assert diff["latest_scan_id"] is None
    assert diff["component_total"] == 0
    assert diff["changed_scan_id"] is None


@pytest.mark.asyncio
async def test_sbom_diff_lookback_finds_older_changed_pair():
    # s4 (latest) identical to s3; s3 identical to s2; s2 differs from s1
    # (adds "newpkg"). The card should report the s2-vs-s1 diff, not the
    # unchanged s4-vs-s3 pair, while still reporting s4 as the true latest.
    recent = [
        {"_id": "s4", "started_at": "2026-06-29T10:00:00Z", "commit_sha": "c4"},
        {"_id": "s3", "started_at": "2026-06-28T10:00:00Z", "commit_sha": "c3"},
        {"_id": "s2", "started_at": "2026-06-27T10:00:00Z", "commit_sha": "c2"},
        {"_id": "s1", "started_at": "2026-06-26T10:00:00Z", "commit_sha": "c1"},
    ]
    same = [{"name": "stable", "version": "1.0.0"}]
    with_newpkg = same + [{"name": "newpkg", "version": "1.0.0"}]
    rows = {
        "s4": with_newpkg,
        "s3": with_newpkg,
        "s2": with_newpkg,  # first appeared here, vs. s1
        "s1": same,
    }
    svc = _make_service(scan_repo=_FakeScanRepo(recent=recent), sbom_repo=_FakeSbomRepo(rows))
    diff = await svc.get_target_sbom_diff("t1")

    # True latest scan info is preserved...
    assert diff["latest_scan_id"] == "s4"
    assert diff["component_total"] == 2

    # ...but the shown diff is the pair that actually changed (s2 vs s1).
    assert diff["changed_scan_id"] == "s2"
    assert diff["changed_commit_sha"] == "c2"
    assert diff["previous_scan_id"] == "s1"
    assert diff["added_count"] == 1
    assert [e["name"] for e in diff["added"]] == ["newpkg"]


@pytest.mark.asyncio
async def test_sbom_diff_lookback_all_unchanged_falls_back_to_latest():
    recent = [
        {"_id": "s3", "started_at": "2026-06-28T10:00:00Z", "commit_sha": "c3"},
        {"_id": "s2", "started_at": "2026-06-27T10:00:00Z", "commit_sha": "c2"},
        {"_id": "s1", "started_at": "2026-06-26T10:00:00Z", "commit_sha": "c1"},
    ]
    same = [{"name": "stable", "version": "1.0.0"}]
    rows = {"s3": same, "s2": same, "s1": same}
    svc = _make_service(scan_repo=_FakeScanRepo(recent=recent), sbom_repo=_FakeSbomRepo(rows))
    diff = await svc.get_target_sbom_diff("t1")

    assert diff["latest_scan_id"] == "s3"
    assert diff["changed_scan_id"] == "s3"  # falls back to the true latest scan
    assert diff["previous_scan_id"] == "s2"  # immediate predecessor, not skipped further back
    assert diff["added_count"] == 0
    assert diff["updated_count"] == 0
    assert diff["removed_count"] == 0


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


# --------------------------------------------------------------------------
# delete_target / delete_scan — cascade cleanup, incl. background task path
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_target_returns_false_and_skips_cascade_when_missing():
    target_repo = _FakeTargetRepo({})
    finding_repo = _FakeFindingRepo()
    sbom_repo = _FakeSbomRepo()
    scan_repo = _FakeScanRepo()
    layer_repo = _FakeLayerRepo()
    svc = _make_service(
        target_repo=target_repo, finding_repo=finding_repo, sbom_repo=sbom_repo,
        scan_repo=scan_repo, layer_repo=layer_repo,
    )

    assert await svc.delete_target("missing") is False
    assert finding_repo.deleted_by_target == []
    assert sbom_repo.deleted_by_target == []
    assert scan_repo.deleted_by_target == []
    assert layer_repo.deleted_by_target == []
    assert not scan_service_module._target_cleanup_tasks


@pytest.mark.asyncio
async def test_delete_target_deletes_row_immediately_and_cascades_in_background():
    target_repo = _FakeTargetRepo({"t1": {"name": "Target One"}})
    finding_repo = _FakeFindingRepo()
    sbom_repo = _FakeSbomRepo()
    scan_repo = _FakeScanRepo()
    layer_repo = _FakeLayerRepo()
    svc = _make_service(
        target_repo=target_repo, finding_repo=finding_repo, sbom_repo=sbom_repo,
        scan_repo=scan_repo, layer_repo=layer_repo,
    )

    result = await svc.delete_target("t1")

    # The target row is gone synchronously, before the cascade has run.
    assert result is True
    assert target_repo.deleted_ids == ["t1"]
    assert await target_repo.get("t1") is None

    # A background cleanup task was scheduled; wait for it to finish, then
    # verify all four child collections (incl. the previously-orphaned
    # layer_repo) were cleaned up.
    tasks = list(scan_service_module._target_cleanup_tasks)
    assert len(tasks) == 1
    await tasks[0]

    assert finding_repo.deleted_by_target == ["t1"]
    assert sbom_repo.deleted_by_target == ["t1"]
    assert scan_repo.deleted_by_target == ["t1"]
    assert layer_repo.deleted_by_target == ["t1"]
    # Task set discards itself once done (no leaked references).
    assert not scan_service_module._target_cleanup_tasks


@pytest.mark.asyncio
async def test_delete_scan_cleans_up_layer_analysis_too():
    # No target_id on the scan doc so the post-delete scan-count/summary
    # refresh branch (which needs a fuller target_repo fake) is skipped —
    # this test is only concerned with the unconditional cascade deletes.
    scan_repo = _FakeScanRepo(scans={"s1": {}})
    finding_repo = _FakeFindingRepo()
    sbom_repo = _FakeSbomRepo()
    layer_repo = _FakeLayerRepo()
    svc = _make_service(
        scan_repo=scan_repo, finding_repo=finding_repo, sbom_repo=sbom_repo,
        layer_repo=layer_repo,
    )

    assert await svc.delete_scan("s1") is True
    assert finding_repo.deleted_by_scan == ["s1"]
    assert sbom_repo.deleted_by_scan == ["s1"]
    assert layer_repo.deleted_by_scan == ["s1"]
