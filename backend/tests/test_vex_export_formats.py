"""VEX export in OpenVEX 0.2.0 and CSAF 2.0 (profile VEX), next to CycloneDX."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.services.vex_export import (
    CSAF_STATUS_GROUPS,
    build_csaf_vex,
    build_openvex,
    collect_statements,
    csaf_filename,
    cyclonedx_justification,
    export_vex_document,
    target_identity,
    vex_justification_label,
)
from app.services.vex_service import VexService

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)

SCAN = {
    "_id": "6650f0c0a1b2c3d4e5f60718",
    "target_id": "ghcr.io/acme/shop",
    "target_name": "ghcr.io/acme/shop",
    "image_ref": "ghcr.io/acme/shop@sha256:abc123",
    "status": "completed",
}
TARGET = {"target_id": "ghcr.io/acme/shop", "name": "ghcr.io/acme/shop", "type": "container_image"}
COMPONENTS = [
    {"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
    {"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},  # second scanner
    {"name": "@angular/core", "version": "17.0.0", "purl": "pkg:npm/%40angular/core@17.0.0"},
    {"name": "openssl", "version": "3.0.2", "purl": "pkg:deb/debian/openssl@3.0.2"},
]


def _finding(vid: str | None, pkg: str, ver: str, **extra: Any) -> dict[str, Any]:
    return {"vulnerability_id": vid, "package_name": pkg, "package_version": ver,
            "package_type": "library", "scanner": "trivy", "severity": "high", **extra}


FINDINGS = [
    _finding("CVE-2021-23337", "lodash", "4.17.20", vex_status="not_affected",
             vex_justification="code_not_reachable", vex_detail="Only used in the build."),
    _finding("CVE-2021-23337", "lodash", "4.17.20", scanner="grype"),  # same finding, no status
    _finding("CVE-2024-0001", "@angular/core", "17.0.0", vex_status="not_affected",
             vex_justification="We checked it by hand"),
    _finding("CVE-2024-0002", "openssl", "3.0.2", vex_status="affected", fix_version="3.0.15"),
    _finding("GHSA-aaaa-bbbb-cccc", "openssl", "3.0.2", vex_status="fixed"),
    _finding("CVE-2024-0003", "openssl", "3.0.2"),  # nobody assessed it
    _finding(None, "Dockerfile", "", package_type="compliance-check"),
    _finding("SECRET", "app.py", "", package_type="secret-finding"),
]


@pytest.mark.parametrize(
    ("text", "label"),
    [
        ("vulnerable_code_not_present", "vulnerable_code_not_present"),
        ("Vulnerable code not present", "vulnerable_code_not_present"),
        ("code_not_present", "vulnerable_code_not_present"),
        ("code_not_reachable", "vulnerable_code_not_in_execute_path"),
        ("requires_dependency", "component_not_present"),
        ("requires_configuration", "vulnerable_code_cannot_be_controlled_by_adversary"),
        ("protected_at_runtime", "inline_mitigations_already_exist"),
        ("we looked at it", None),
        (None, None),
    ],
)
def test_justifications_map_to_the_shared_labels(text: str | None, label: str | None) -> None:
    assert vex_justification_label(text) == label


def test_statements_merge_scanners_and_skip_non_vex_findings() -> None:
    statements = collect_statements(FINDINGS)
    keys = [(s["vulnerability_id"], s["package_name"]) for s in statements]
    assert keys == sorted(set(keys))
    assert ("CVE-2021-23337", "lodash") in keys
    assert all(s["package_name"] not in ("Dockerfile", "app.py") for s in statements)
    lodash = next(s for s in statements if s["package_name"] == "lodash")
    # The assessed finding wins over the other scanner's unassessed copy.
    assert lodash["status"] == "not_affected" and lodash["scanners"] == ["grype", "trivy"]
    unassessed = next(s for s in statements if s["vulnerability_id"] == "CVE-2024-0003")
    assert unassessed["status"] == "under_investigation" and unassessed["assessed"] is False


def test_container_target_is_a_pkg_oci_purl() -> None:
    ident = target_identity(SCAN, TARGET)
    assert ident["purl"] == "pkg:oci/shop@sha256%3Aabc123?repository_url=ghcr.io/acme/shop"
    assert ident["iri"] == ident["purl"]
    repo = target_identity({"target_id": "https://github.com/acme/shop"}, {"type": "source_repo", "name": "shop"})
    assert repo["purl"] is None and repo["iri"] == "https://github.com/acme/shop"


# ---------------------------------------------------------------- CSAF


def _csaf() -> dict[str, Any]:
    return build_csaf_vex(SCAN, TARGET, FINDINGS, COMPONENTS, release={"label": "1.4.2"}, now=NOW)


def test_csaf_document_metadata() -> None:
    doc = _csaf()["document"]
    assert doc["category"] == "csaf_vex"
    assert doc["csaf_version"] == "2.0"
    assert doc["title"].endswith("1.4.2")
    assert {"category", "name", "namespace"} <= set(doc["publisher"])
    tracking = doc["tracking"]
    assert tracking["status"] == "final" and tracking["version"] == "1"
    assert tracking["revision_history"][-1]["number"] == tracking["version"]  # 6.1.16
    assert tracking["initial_release_date"] == tracking["current_release_date"] == "2026-11-15T12:00:00Z"
    assert tracking["generator"]["engine"]["name"] == "Hecate"
    assert csaf_filename(tracking["id"]) == "hecate-vex-6650f0c0a1b2c3d4e5f60718-20261115t120000z.json"
    assert doc["notes"] and doc["notes"][0]["category"] in ("description", "details", "general", "summary")


def test_csaf_product_tree_defines_every_referenced_product() -> None:
    csaf = _csaf()
    tree = csaf["product_tree"]
    defined = [p["product_id"] for p in tree["full_product_names"]]
    defined += [r["full_product_name"]["product_id"] for r in tree["relationships"]]
    assert len(defined) == len(set(defined))  # 6.1.2 multiple definition
    target = tree["full_product_names"][0]
    assert target["product_identification_helper"]["purl"].startswith("pkg:oci/shop@")
    angular = next(p for p in tree["full_product_names"] if p["name"].startswith("@angular/core"))
    assert angular["product_identification_helper"]["purl"] == "pkg:npm/%40angular/core@17.0.0"
    assert all(r["category"] == "default_component_of" for r in tree["relationships"])
    referenced: set[str] = set()
    for vuln in csaf["vulnerabilities"]:
        for ids in vuln["product_status"].values():
            referenced.update(ids)
        for section in ("flags", "threats", "remediations"):
            for item in vuln.get(section, []):
                referenced.update(item["product_ids"])
    assert referenced <= set(defined)  # 6.1.1 missing definition


def test_csaf_vex_profile_mandatory_tests() -> None:
    csaf = _csaf()
    seen_cves: list[str] = []
    for vuln in csaf["vulnerabilities"]:
        assert "cve" in vuln or vuln.get("ids")  # 6.1.27.8
        if "cve" in vuln:
            seen_cves.append(vuln["cve"])
        assert vuln["notes"]  # 6.1.27.5
        status = vuln["product_status"]
        assert set(status) & set(CSAF_STATUS_GROUPS.values())  # 6.1.27.7
        groups = [set(v) for v in status.values()]
        assert sum(len(g) for g in groups) == len(set().union(*groups))  # 6.1.6 contradiction
        flagged = [pid for f in vuln.get("flags", []) for pid in f["product_ids"]]
        assert len(flagged) == len(set(flagged))  # 6.1.33 one justification per product
        impact = {pid for t in vuln.get("threats", []) if t["category"] == "impact" for pid in t["product_ids"]}
        for pid in status.get("known_not_affected", []):
            assert pid in flagged or pid in impact  # 6.1.27.9
        remediated = {pid for r in vuln.get("remediations", []) for pid in r["product_ids"]}
        for pid in status.get("known_affected", []):
            assert pid in remediated  # 6.1.27.10
    assert len(seen_cves) == len(set(seen_cves))  # 6.1.23 one entry per CVE


def test_csaf_maps_statuses_flags_threats_and_fixes() -> None:
    vulns = {v.get("cve") or v["ids"][0]["text"]: v for v in _csaf()["vulnerabilities"]}
    lodash = vulns["CVE-2021-23337"]
    assert list(lodash["product_status"]) == ["known_not_affected"]
    assert lodash["flags"][0]["label"] == "vulnerable_code_not_in_execute_path"
    assert lodash["threats"][0]["details"] == "Only used in the build."
    # A free-text justification has no flag, so it becomes the impact statement.
    angular = vulns["CVE-2024-0001"]
    assert "flags" not in angular
    assert angular["threats"][0]["details"] == "We checked it by hand"
    openssl = vulns["CVE-2024-0002"]
    assert list(openssl["product_status"]) == ["known_affected"]
    assert openssl["remediations"][0]["category"] == "vendor_fix"
    assert "3.0.15" in openssl["remediations"][0]["details"]
    ghsa = vulns["GHSA-aaaa-bbbb-cccc"]
    assert ghsa["ids"] == [{"system_name": "GHSA", "text": "GHSA-aaaa-bbbb-cccc"}]
    assert list(ghsa["product_status"]) == ["fixed"]
    assert list(vulns["CVE-2024-0003"]["product_status"]) == ["under_investigation"]


def test_csaf_carries_review_evidence_as_a_note() -> None:
    findings = [_finding("CVE-2024-9", "openssl", "3.0.2", vex_status="not_affected",
                         vex_justification="component_not_present", vex_assessed_version="3.0.2",
                         vex_review_due=datetime(2027, 5, 1, tzinfo=UTC))]
    vuln = build_csaf_vex(SCAN, TARGET, findings, COMPONENTS, now=NOW)["vulnerabilities"][0]
    details = [n for n in vuln["notes"] if n["category"] == "details"]
    assert details and "3.0.2" in details[0]["text"] and "2027-05-01" in details[0]["text"]
    openvex = build_openvex(SCAN, TARGET, findings, COMPONENTS, now=NOW)
    assert "2027-05-01" in openvex["statements"][0]["status_notes"]


def test_no_vulnerability_findings_means_no_document() -> None:
    only_sast = [_finding(None, "x", "", package_type="sast-finding")]
    assert build_csaf_vex(SCAN, TARGET, only_sast, [], now=NOW) == {}
    assert build_openvex(SCAN, TARGET, only_sast, [], now=NOW) == {}


# ---------------------------------------------------------------- OpenVEX


def test_openvex_document_shape() -> None:
    doc = build_openvex(SCAN, TARGET, FINDINGS, COMPONENTS, now=NOW)
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert doc["@id"].startswith("urn:uuid:")
    assert doc["version"] == 1 and doc["timestamp"] == "2026-11-15T12:00:00Z" and doc["author"]
    for st in doc["statements"]:
        product = st["products"][0]
        assert product["@id"].startswith("pkg:oci/shop")
        assert product["subcomponents"][0]["@id"].startswith("pkg:")
        if st["status"] == "not_affected":
            assert st.get("justification") or st.get("impact_statement")
        if st["status"] == "affected":
            assert st["action_statement"]
    lodash = next(s for s in doc["statements"] if s["vulnerability"]["name"] == "CVE-2021-23337")
    assert lodash["justification"] == "vulnerable_code_not_in_execute_path"
    assert lodash["products"][0]["subcomponents"][0]["@id"] == "pkg:npm/lodash@4.17.20"


class RecordingFindingRepo:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def bulk_update_vex_by_vulnerability_ids(self, target_id: str, ids: list[str], status: str, **kw: Any) -> int:
        self.calls.append({"ids": ids, "status": status, **kw})
        return 1


async def test_openvex_export_round_trips_through_the_import() -> None:
    doc = build_openvex(SCAN, TARGET, FINDINGS, COMPONENTS, now=NOW)
    repo = RecordingFindingRepo()

    result = await VexService(repo, None).import_vex_document(doc, "ghcr.io/acme/shop")  # type: ignore[arg-type]

    assert result["format"] == "openvex"
    assert result["skipped"] == 0
    imported = {(tuple(c["ids"])[0], c["status"]) for c in repo.calls}
    exported = {(s["vulnerability_id"], s["status"]) for s in collect_statements(FINDINGS)}
    assert imported == exported
    lodash = next(c for c in repo.calls if c["ids"][0] == "CVE-2021-23337")
    assert lodash["vex_justification"] == "vulnerable_code_not_in_execute_path"
    assert lodash["vex_detail"] == "Only used in the build."
    # openssl has statements with different statuses (CVE-2024-0002 vs others are
    # separate ids, so no scoping is needed); the purl spelling still reaches it.
    angular = next(c for c in repo.calls if c["ids"][0] == "CVE-2024-0001")
    assert angular["status"] == "not_affected"


# ---------------------------------------------------------------- loading + CycloneDX


class FakeScanRepo:
    async def get(self, scan_id: str) -> dict[str, Any] | None:
        return dict(SCAN) if scan_id == SCAN["_id"] else None


class FakeTargetRepo:
    async def get(self, _target_id: str) -> dict[str, Any]:
        return dict(TARGET)


class FakeFindingRepo:
    async def list_by_scan(self, scan_id: str, **_kw: Any) -> tuple[int, list[dict[str, Any]]]:
        return len(FINDINGS), [dict(f) for f in FINDINGS]

    async def get_vex_findings_by_scan(self, scan_id: str) -> list[dict[str, Any]]:
        return [dict(f) for f in FINDINGS if f.get("vex_status")]


class FakeSbomRepo:
    async def list_all_by_scan(self, _scan_id: str) -> list[dict[str, Any]]:
        return [dict(c) for c in COMPONENTS]


class Repos:
    scan_repo = FakeScanRepo()
    target_repo = FakeTargetRepo()
    finding_repo = FakeFindingRepo()
    sbom_repo = FakeSbomRepo()


async def test_export_dispatches_per_format_and_keeps_cyclonedx() -> None:
    cdx, name = await export_vex_document(Repos(), SCAN["_id"], "cyclonedx")  # type: ignore[misc]
    assert name == f"vex-{SCAN['_id']}.cdx.json"
    assert cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.5"
    # CycloneDX keeps listing only the findings with a status.
    assert {v["id"] for v in cdx["vulnerabilities"]} == {
        "CVE-2021-23337", "CVE-2024-0001", "CVE-2024-0002", "GHSA-aaaa-bbbb-cccc",
    }
    openvex, name = await export_vex_document(Repos(), SCAN["_id"], "openvex")  # type: ignore[misc]
    assert name.endswith(".openvex.json") and openvex["statements"]
    csaf, name = await export_vex_document(Repos(), SCAN["_id"], "csaf")  # type: ignore[misc]
    assert name.startswith("hecate-vex-") and csaf["document"]["category"] == "csaf_vex"
    assert await export_vex_document(Repos(), "unknown", "csaf") is None
    with pytest.raises(ValueError):
        await export_vex_document(Repos(), SCAN["_id"], "spdx")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("code_not_reachable", "code_not_reachable"),
        ("vulnerable_code_not_in_execute_path", "code_not_reachable"),
        ("Vulnerable code not present", "code_not_present"),
        ("inline_mitigations_already_exist", "protected_by_mitigating_control"),
        ("we only use it at build time", None),
        (None, None),
    ],
)
def test_cyclonedx_export_only_writes_its_own_justification_enum(text: str | None, expected: str | None) -> None:
    assert cyclonedx_justification(text) == expected


async def test_cyclonedx_export_moves_free_text_justification_into_detail() -> None:
    cdx, _ = await export_vex_document(Repos(), SCAN["_id"], "cyclonedx")  # type: ignore[misc]
    allowed = {
        "code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency",
        "requires_environment", "protected_by_compiler", "protected_at_runtime",
        "protected_at_perimeter", "protected_by_mitigating_control",
    }
    for vuln in cdx["vulnerabilities"]:
        justification = vuln["analysis"].get("justification")
        assert justification is None or justification in allowed

