"""CycloneDX export with vulnerabilities: the shape DefectDojo's CycloneDX parser reads."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import scans as scans_api
from app.services.sbom_export import build_cyclonedx_json, unique_components

SCAN = {"_id": "scan-1", "target_id": "ghcr.io/acme/shop", "target_name": "ghcr.io/acme/shop"}
TARGET = {"name": "ghcr.io/acme/shop", "type": "container_image"}

COMPONENTS = [
    {"name": "openssl", "version": "3.0.1", "type": "library"},
    # A second scanner's row of the same package: one component, its purl kept.
    {"name": "openssl", "version": "3.0.1", "purl": "pkg:deb/debian/openssl@3.0.1", "licenses": ["Apache-2.0"]},
    {"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
    {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
]


def _finding(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "vulnerability_id": "CVE-2024-0001",
        "scanner": "trivy",
        "package_name": "openssl",
        "package_version": "3.0.1",
        "package_type": "deb",
        "severity": "medium",
        "title": "openssl: a flaw",
        "description": "A flaw in openssl.",
        "urls": [],
    }
    base.update(overrides)
    return base


def _doc(findings: list[dict[str, Any]], cwes: dict[str, list[str]] | None = None) -> dict[str, Any]:
    return build_cyclonedx_json(SCAN, TARGET, COMPONENTS, findings=findings, cwes=cwes)


def _vuln(doc: dict[str, Any], vuln_id: str, package: str) -> dict[str, Any]:
    refs = {c["bom-ref"]: c for c in doc["components"]}
    matches = [v for v in doc["vulnerabilities"] if v["id"] == vuln_id and refs[v["affects"][0]["ref"]]["name"] == package]
    assert len(matches) == 1, matches
    return matches[0]


def test_components_are_listed_once_with_unique_refs() -> None:
    doc = build_cyclonedx_json(SCAN, TARGET, COMPONENTS)
    assert "vulnerabilities" not in doc
    names = [(c["name"], c.get("version")) for c in doc["components"]]
    assert names == [("openssl", "3.0.1"), ("lodash", "4.17.20"), ("lodash", "4.17.21")]
    refs = [c["bom-ref"] for c in doc["components"]]
    assert len(set(refs)) == len(refs)
    openssl = doc["components"][0]
    assert openssl["purl"] == "pkg:deb/debian/openssl@3.0.1"
    assert openssl["licenses"] == [{"license": {"id": "Apache-2.0"}}]


def test_unique_components_fills_empty_fields_from_later_rows() -> None:
    rows = unique_components([{"name": "a", "version": "1", "purl": ""}, {"name": "a", "version": "1", "purl": "pkg:npm/a@1"}])
    assert rows == [{"name": "a", "version": "1", "purl": "pkg:npm/a@1"}]


def test_every_affects_ref_resolves_to_a_component() -> None:
    doc = _doc([
        _finding(),
        _finding(vulnerability_id="CVE-2024-0002", package_name="lodash", package_version="4.17.20", package_type="npm"),
        # Not in the SBOM: gets a component of its own.
        _finding(vulnerability_id="GHSA-xxxx-yyyy-zzzz", package_name="left-pad", package_version="1.0.0", package_type="npm"),
    ])
    refs = {c["bom-ref"] for c in doc["components"]}
    assert len(refs) == len(doc["components"])
    for vuln in doc["vulnerabilities"]:
        assert vuln["affects"][0]["ref"] in refs
    lodash = _vuln(doc, "CVE-2024-0002", "lodash")
    assert lodash["affects"][0]["ref"] == "pkg:npm/lodash@4.17.20"
    extra = next(c for c in doc["components"] if c["name"] == "left-pad")
    assert extra["purl"] == "pkg:generic/left-pad@1.0.0"
    assert _vuln(doc, "GHSA-xxxx-yyyy-zzzz", "left-pad")["source"]["name"] == "GitHub"


def test_scanners_merge_into_one_entry_with_the_worst_rating() -> None:
    doc = _doc([
        _finding(scanner="grype", severity="medium", cvss_score=5.0),
        _finding(
            scanner="trivy", severity="high", cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            fix_version="3.0.2", urls=["https://example.org/a", "javascript:alert(1)", "https://example.org/a"],
            dependency_scope="runtime", fix_state="fixed",
        ),
    ], cwes={"CVE-2024-0001": ["CWE-79", "NVD-CWE-noinfo", "CWE-79"]})
    assert len(doc["vulnerabilities"]) == 1
    vuln = doc["vulnerabilities"][0]
    assert vuln["ratings"] == [{
        "severity": "high", "method": "CVSSv31",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 7.5,
    }]
    assert vuln["cwes"] == [79]
    assert vuln["recommendation"] == "Upgrade openssl to 3.0.2."
    assert vuln["advisories"] == [{"url": "https://example.org/a"}]
    assert vuln["source"] == {"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"}
    assert vuln["description"] == "A flaw in openssl."
    props = {p["name"]: p["value"] for p in vuln["properties"]}
    assert props == {"hecate:scanner": "grype, trivy", "hecate:dependencyScope": "runtime", "hecate:fixState": "fixed"}
    assert "analysis" not in vuln
    assert vuln["affects"] == [{"ref": "pkg:deb/debian/openssl@3.0.1", "versions": [{"version": "3.0.1", "status": "affected"}]}]


def test_negligible_is_info_and_a_rating_without_vector_has_no_method() -> None:
    vuln = _doc([_finding(severity="negligible", cvss_score=2.0)])["vulnerabilities"][0]
    assert vuln["ratings"] == [{"severity": "info"}]


def test_vex_status_becomes_the_analysis() -> None:
    doc = _doc([
        _finding(
            vex_status="not_affected", vex_justification="Vulnerable code not in execute path",
            vex_detail="Never loaded.", vex_updated_at=datetime(2026, 11, 1, tzinfo=UTC), vex_updated_by="user",
        ),
        _finding(scanner="grype"),
        _finding(vulnerability_id="CVE-2024-0003", vex_status="affected", vex_response=["update"]),
    ])
    quiet = _vuln(doc, "CVE-2024-0001", "openssl")
    assert quiet["analysis"] == {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "Never loaded.",
        "lastUpdated": "2026-11-01T00:00:00+00:00",
    }
    assert quiet["affects"][0]["versions"] == [{"version": "3.0.1", "status": "unaffected"}]
    assert {"name": "hecate:vex:updated-by", "value": "user"} in quiet["properties"]
    loud = _vuln(doc, "CVE-2024-0003", "openssl")
    assert loud["analysis"] == {"state": "exploitable", "response": ["update"]}
    assert loud["affects"][0]["versions"][0]["status"] == "affected"


def test_findings_without_an_advisory_are_left_out() -> None:
    doc = _doc([
        _finding(vulnerability_id=None, package_type="malicious-indicator", title="HEC-001 install hook"),
        _finding(vulnerability_id="CWE-89", package_type="sast-finding"),
        _finding(vulnerability_id="aws", package_type="secret-finding"),
        _finding(vulnerability_id="MAL-2026-1", package_type="npm", package_name="lodash", package_version="4.17.21"),
    ])
    assert [v["id"] for v in doc["vulnerabilities"]] == ["MAL-2026-1"]
    assert doc["vulnerabilities"][0]["source"]["name"] == "OSV"


def test_an_empty_scan_still_has_the_array() -> None:
    assert _doc([])["vulnerabilities"] == []


class ExportService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bool]] = []

    async def export_sbom(self, scan_id: str, fmt: str, *, include_vulnerabilities: bool = False) -> tuple[dict[str, Any], str]:
        self.calls.append((scan_id, fmt, include_vulnerabilities))
        return {"bomFormat": "CycloneDX"}, "x.cdx.json"


@pytest.mark.parametrize(
    ("query", "status", "call"),
    [
        ("?vulnerabilities=true", 200, ("scan-1", "cyclonedx-json", True)),
        ("", 200, ("scan-1", "cyclonedx-json", False)),
        ("?format=spdx-json&vulnerabilities=true", 400, None),
    ],
)
def test_route_passes_the_flag_and_refuses_it_for_spdx(query: str, status: int, call: tuple[str, str, bool] | None) -> None:
    service = ExportService()
    app = FastAPI()
    app.include_router(scans_api.router, prefix="/scans")
    app.dependency_overrides[scans_api.get_scan_service] = lambda: service
    response = TestClient(app).get(f"/scans/scan-1/sbom/export{query}")
    assert response.status_code == status
    assert service.calls == ([call] if call else [])


# ---------------------------------------------------------------- schema details


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (["MIT", "Expat", "apache-2.0"], [
            {"license": {"id": "MIT"}}, {"license": {"name": "Expat"}}, {"license": {"id": "Apache-2.0"}},
        ]),
        (["MIT OR Apache-2.0"], [{"expression": "MIT OR Apache-2.0"}]),
        (["(MIT)"], [{"expression": "(MIT)"}]),
        # The schema takes an expression only alone; next to others it is a name.
        (["MIT OR Apache-2.0", "BSD-3-Clause"], [
            {"license": {"name": "MIT OR Apache-2.0"}}, {"license": {"id": "BSD-3-Clause"}},
        ]),
        (["", "MIT", "MIT", None], [{"license": {"id": "MIT"}}]),
    ],
)
def test_licenses_follow_the_schema(values: list[Any], expected: list[dict[str, Any]]) -> None:
    from app.services.sbom_export import cyclonedx_licenses

    assert cyclonedx_licenses(values) == expected


@pytest.mark.parametrize(
    ("package_type", "cdx_type", "kept"),
    [("python-pkg", "library", "python-pkg"), ("deb", "library", "deb"), ("library", "library", None),
     ("os", "operating-system", "os"), ("application", "application", None), (None, "library", None)],
)
def test_scanner_package_types_become_cyclonedx_types(package_type: str | None, cdx_type: str, kept: str | None) -> None:
    doc = build_cyclonedx_json(SCAN, TARGET, [{"name": "x", "version": "1", "type": package_type}])
    comp = doc["components"][0]
    assert comp["type"] == cdx_type
    props = {p["name"]: p["value"] for p in comp.get("properties", [])}
    assert props.get("hecate:packageType") == kept


class _Cursor:
    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self.docs = docs
        self.max_time: int | None = None

    def max_time_ms(self, value: int) -> _Cursor:
        self.max_time = value
        return self

    def __aiter__(self) -> Any:
        async def gen() -> Any:
            for doc in self.docs:
                yield doc
        return gen()


async def test_cwes_come_from_the_vulnerability_records(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.db import mongo
    from app.services.scan_service import ScanService

    cursor = _Cursor([{"_id": "CVE-2024-0001", "cwes": ["CWE-79", 5]}, {"_id": "CVE-2024-0002", "cwes": []}])
    queries: list[dict[str, Any]] = []

    class Collection:
        def find(self, query: dict[str, Any], projection: dict[str, Any]) -> _Cursor:
            queries.append(query)
            return cursor

    async def fake_db() -> dict[str, Collection]:
        return {"vulnerabilities": Collection()}

    monkeypatch.setattr(mongo, "get_database", fake_db)
    monkeypatch.setattr("app.services.scan_service.settings.mongo_vulnerabilities_collection", "vulnerabilities")
    service = ScanService.__new__(ScanService)
    assert await service._cwes_for_vulnerabilities({"CVE-2024-0002", "CVE-2024-0001"}) == {"CVE-2024-0001": ["CWE-79"]}
    assert queries == [{"_id": {"$in": ["CVE-2024-0001", "CVE-2024-0002"]}}]
    assert cursor.max_time == 5000

    async def broken_db() -> None:
        raise RuntimeError("down")

    monkeypatch.setattr(mongo, "get_database", broken_db)
    assert await service._cwes_for_vulnerabilities({"CVE-2024-0001"}) == {}
