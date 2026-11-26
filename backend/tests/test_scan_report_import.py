"""Scanner reports (Trivy, Grype, OSV-Scanner JSON) through the SBOM import.

The fixtures are real reports, trimmed: ``trivy fs`` and ``osv-scanner scan
source`` (2.7.1) of an npm project with lodash 4.17.20 and minimist 1.2.5,
``grype alpine:3.16`` (0.122.0, first three matches). Trivy 0.76.2.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from bson import ObjectId

from app.core.config import settings
from app.services.scan_report_import import (
    detect_report_format,
    parse_report,
    report_package_count,
    report_target_name,
)
from app.services.scan_service import ScanService, detect_import_format, resolve_sbom_import_target

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


TRIVY = _load("report_trivy_npm.json")
GRYPE = _load("report_grype_alpine.json")
OSV = _load("report_osv_npm.json")


@pytest.mark.parametrize(
    ("data", "fmt"),
    [
        (TRIVY, "trivy-json"),
        (GRYPE, "grype-json"),
        (OSV, "osv-scanner-json"),
        ({"bomFormat": "CycloneDX", "components": []}, "cyclonedx-json"),
        ({"spdxVersion": "SPDX-2.3", "packages": []}, "spdx-json"),
        ({"hello": "world"}, None),
        ({"results": [{"unrelated": 1}]}, None),
        ({"matches": []}, None),
    ],
)
def test_formats_are_detected(data: dict[str, Any], fmt: str | None) -> None:
    assert detect_import_format(data) == fmt


def test_a_cyclonedx_document_is_never_a_report() -> None:
    assert detect_report_format({"bomFormat": "CycloneDX", "results": []}) is None
    assert detect_import_format({"bomFormat": "CycloneDX", "results": []}) == "cyclonedx-json"


def test_trivy_report_gives_findings_and_its_package_list() -> None:
    findings, components = parse_report(TRIVY, "trivy-json", "scan-1", "t")
    assert len(findings) == 5
    assert all(f.scanner == "trivy" and f.vulnerability_id for f in findings)
    assert ("CVE-2021-44906", "minimist") in {(f.vulnerability_id, f.package_name) for f in findings}
    assert {(c.name, c.version, c.purl) for c in components} == {
        ("lodash", "4.17.20", "pkg:npm/lodash@4.17.20"),
        ("minimist", "1.2.5", "pkg:npm/minimist@1.2.5"),
    }
    assert report_target_name(TRIVY, "trivy-json") == "demo-shop"


def test_grype_report_gives_its_matched_packages() -> None:
    findings, components = parse_report(GRYPE, "grype-json", "scan-1", "t")
    assert len(findings) == 3
    assert all(f.scanner == "grype" and f.vulnerability_id for f in findings)
    assert {c.name for c in components} == {f.package_name for f in findings}
    assert all(c.purl and c.purl.startswith("pkg:apk/alpine/") for c in components)
    assert report_target_name(GRYPE, "grype-json") == "alpine:3.16"


def test_osv_report_builds_purls_from_the_ecosystem() -> None:
    findings, components = parse_report(OSV, "osv-scanner-json", "scan-1", "t")
    assert {f.vulnerability_id for f in findings} == {
        "CVE-2020-28500", "CVE-2021-23337", "CVE-2025-13465", "CVE-2026-4800", "CVE-2021-44906",
    }
    assert all(f.scanner == "osv-scanner" for f in findings)
    assert {(c.name, c.purl) for c in components} == {
        ("lodash", "pkg:npm/lodash@4.17.20"), ("minimist", "pkg:npm/minimist@1.2.5"),
    }
    # OSV-Scanner names no scanned thing: the import's default name.
    assert report_target_name(OSV, "osv-scanner-json") is None
    assert resolve_sbom_import_target(OSV, None, None, None) == (
        "osv-scanner report", "sbom-import-osv-scanner-report",
    )


@pytest.mark.parametrize(
    ("ecosystem", "name", "purl"),
    [
        ("PyPI", "Django", "pkg:pypi/Django@1.0"),
        ("Maven", "org.apache.logging.log4j:log4j-core", "pkg:maven/org.apache.logging.log4j/log4j-core@1.0"),
        ("crates.io", "serde", "pkg:cargo/serde@1.0"),
        ("Debian:12", "openssl", "pkg:deb/debian/openssl@1.0"),
        ("Alpine:v3.18", "busybox", "pkg:apk/alpine/busybox@1.0"),
        ("Unknown", "x", None),
    ],
)
def test_osv_ecosystems_map_to_purls(ecosystem: str, name: str, purl: str | None) -> None:
    from app.services.scan_report_import import _osv_purl

    assert _osv_purl(ecosystem, name, "1.0") == purl


def test_the_gate_and_the_import_resolve_the_same_target() -> None:
    assert resolve_sbom_import_target(GRYPE, None, None, None) == ("alpine:3.16", "sbom-import-alpine:3.16")
    assert resolve_sbom_import_target(GRYPE, None, "web-01", None) == ("web-01", "sbom-import-web-01")
    assert report_package_count(GRYPE, "grype-json") == 3


# ---------------------------------------------------------------- the import


class _Repo(SimpleNamespace):
    pass


def _service(monkeypatch: pytest.MonkeyPatch, calls: list[str]) -> tuple[ScanService, dict[str, Any]]:
    stored: dict[str, Any] = {"findings": [], "components": [], "scans": [], "targets": {}}
    scan_id = str(ObjectId())

    async def target_get(target_id: str) -> dict[str, Any] | None:
        return stored["targets"].get(target_id)

    async def target_upsert(doc: Any) -> None:
        stored["targets"][doc.target_id] = doc.model_dump()

    async def noop(*_a: Any, **_k: Any) -> None:
        return None

    async def scan_insert(doc: Any) -> str:
        stored["scans"].append(doc)
        return scan_id

    async def sbom_insert(rows: list[Any]) -> int:
        stored["components"].extend(rows)
        return len(rows)

    async def finding_insert(rows: list[Any]) -> int:
        stored["findings"].extend(rows)
        return len(rows)

    service = ScanService.__new__(ScanService)
    service.target_repo = _Repo(get=target_get, upsert=target_upsert, update_classification=noop,
                                update_last_scan=noop, update_scan_state=noop)
    service.scan_repo = _Repo(insert=scan_insert, update_fields=noop)
    service.sbom_repo = _Repo(bulk_insert=sbom_insert)
    service.finding_repo = _Repo(bulk_insert=finding_insert)

    def record(name: str) -> Any:
        async def fn(*_a: Any, **_k: Any) -> Any:
            calls.append(name)
            return ([], []) if name in ("bundled", "sidecar") else None
        return fn

    monkeypatch.setattr(service, "_match_cve_for_unmatched_findings", record("cve_fallback"))
    monkeypatch.setattr(service, "_fix_downgrade_fix_versions", record("fix_versions"))
    monkeypatch.setattr(service, "_override_severity_from_vuln_db", record("severity"))
    monkeypatch.setattr(service, "_apply_dependency_scopes", record("scopes"))
    monkeypatch.setattr(service, "_add_bundled_libraries", record("bundled"))
    monkeypatch.setattr(service, "_scan_imported_sbom", record("sidecar"))
    monkeypatch.setattr(service, "_carry_forward_from_previous", record("carry_forward"))
    monkeypatch.setattr(service, "apply_vex_sources", record("vex_sources"))
    monkeypatch.setattr(service, "_schedule_release_info", lambda *_a: calls.append("release_info"))

    class _Collection:
        async def update_one(self, *_a: Any, **_k: Any) -> None:
            return None

    async def fake_db() -> dict[str, Any]:
        return {settings.mongo_scans_collection: _Collection()}

    from app.db import mongo
    monkeypatch.setattr(mongo, "get_database", fake_db)
    return service, stored


async def test_a_report_is_stored_as_the_scanner_reported_it(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    service, stored = _service(monkeypatch, calls)

    result = await service.import_sbom(GRYPE, kind="host", exposure="internet")

    assert result["target_id"] == "sbom-import-alpine:3.16"
    assert result["findings_count"] == 3
    scan = stored["scans"][0]
    assert scan.scanners == ["grype"] and scan.source == "sbom-import"
    target = stored["targets"]["sbom-import-alpine:3.16"]
    assert target["type"] == "sbom-import" and target["kind"] == "host" and target["exposure"] == "internet"
    # Three matches in two packages: the SBOM lists each package once.
    assert len(stored["findings"]) == 3 and len(stored["components"]) == 2
    # The scan's post-passes, no second opinion from the sidecar.
    assert "sidecar" not in calls
    for step in ("cve_fallback", "fix_versions", "severity", "scopes", "carry_forward", "vex_sources"):
        assert step in calls
    assert calls.index("carry_forward") < calls.index("vex_sources")


async def test_a_report_as_a_check_carries_nothing_forward(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    service, stored = _service(monkeypatch, calls)

    result = await service.import_sbom(TRIVY, check=True)

    assert result["check"] is True and result["target_id"].startswith("check:")
    assert stored["targets"] == {}
    assert "carry_forward" not in calls and "vex_sources" not in calls


async def test_an_sbom_import_now_carries_vex_forward_too(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    service, _ = _service(monkeypatch, calls)

    async def no_matches(*_a: Any, **_k: Any) -> list[Any]:
        return []

    monkeypatch.setattr(service, "_match_vulnerabilities_for_components", no_matches)
    await service.import_sbom({"bomFormat": "CycloneDX", "metadata": {"component": {"name": "web-01"}}, "components": []})

    assert "sidecar" in calls and "carry_forward" in calls
    assert "severity" not in calls


async def test_oversized_reports_and_unknown_formats_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    service, stored = _service(monkeypatch, calls)
    monkeypatch.setattr(settings, "sca_sbom_import_max_components", 2)
    with pytest.raises(ValueError, match="limit is 2"):
        await service.import_sbom(GRYPE)
    with pytest.raises(ValueError, match="Unknown format"):
        await service.import_sbom(GRYPE, format="nessus")
    with pytest.raises(ValueError, match="Trivy, Grype or OSV-Scanner"):
        await service.import_sbom({"hello": "world"})
    assert stored["scans"] == []


# ---------------------------------------------------------------- CycloneDX with vulnerabilities

TRIVY_CDX = _load("report_trivy_npm.cdx.json")


def test_trivy_cyclonedx_findings_point_at_their_components() -> None:
    from app.services.scan_report_import import cyclonedx_scanner, parse_cyclonedx_vulnerabilities

    assert cyclonedx_scanner(TRIVY_CDX) == "trivy"
    findings = parse_cyclonedx_vulnerabilities(TRIVY_CDX, "scan-1", "t")
    assert len(findings) == 5
    lodash = next(f for f in findings if f.vulnerability_id == "CVE-2020-28500")
    assert (lodash.package_name, lodash.package_version, lodash.package_type) == ("lodash", "4.17.20", "npm")
    assert lodash.fix_version == "4.17.21" and lodash.fix_state == "fixed"
    assert lodash.cvss_vector and lodash.cvss_vector.startswith("CVSS:3.1/")
    assert all(f.scanner == "trivy" and f.vex_status is None for f in findings)


def test_a_hecate_export_comes_back_with_its_scanners_and_statuses() -> None:
    from datetime import UTC, datetime

    from app.services.sbom_export import build_cyclonedx_json
    from app.services.scan_report_import import parse_cyclonedx_vulnerabilities

    doc = build_cyclonedx_json(
        {"_id": "s", "target_name": "web-01"}, None,
        [{"name": "openssl", "version": "3.0.1", "purl": "pkg:deb/debian/openssl@3.0.1"}],
        findings=[{
            "vulnerability_id": "CVE-2024-0001", "scanner": "grype", "package_name": "openssl",
            "package_version": "3.0.1", "severity": "high", "fix_version": "3.0.2",
            "vex_status": "not_affected", "vex_justification": "code_not_reachable",
            "vex_detail": "never loaded", "vex_updated_at": datetime(2026, 11, 1, tzinfo=UTC),
        }],
    )
    [finding] = parse_cyclonedx_vulnerabilities(doc, "scan-2", "t", now=datetime(2026, 11, 26, tzinfo=UTC))
    assert (finding.scanner, finding.severity, finding.fix_version) == ("grype", "high", "3.0.2")
    assert (finding.vex_status, finding.vex_justification, finding.vex_detail, finding.vex_updated_by) == (
        "not_affected", "vulnerable_code_not_in_execute_path", "never loaded", "vex-import",
    )


def test_ratings_take_the_worst_severity_and_a_cvss_vector() -> None:
    from app.services.scan_report_import import _rating_fields

    ratings = [
        {"source": {"name": "FIRST"}, "score": 0.08, "method": "other"},
        {"source": {"name": "ghsa"}, "score": 6.1, "severity": "medium", "method": "CVSSv31", "vector": "CVSS:3.1/A"},
        {"source": {"name": "nvd"}, "score": 9.8, "severity": "critical", "method": "CVSSv31", "vector": "CVSS:3.1/N"},
        {"source": {"name": "nvd"}, "score": 7.5, "severity": "high", "method": "CVSSv2", "vector": "AV:N"},
    ]
    assert _rating_fields(ratings) == ("critical", 9.8, "CVSS:3.1/N")
    assert _rating_fields([{"score": 7.2, "method": "CVSSv4", "vector": "CVSS:4.0/X"}]) == ("high", 7.2, "CVSS:4.0/X")
    assert _rating_fields([]) == ("unknown", None, None)


def test_a_vex_document_is_not_a_report() -> None:
    from app.services.scan_report_import import parse_cyclonedx_vulnerabilities

    vex = {"bomFormat": "CycloneDX", "vulnerabilities": [
        {"id": "CVE-2024-0001", "analysis": {"state": "not_affected"}, "affects": [{"ref": "openssl"}]},
    ]}
    with pytest.raises(ValueError, match="VEX import"):
        parse_cyclonedx_vulnerabilities(vex, "s", "t")


async def test_cyclonedx_with_vulnerabilities_is_imported_as_a_report(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    service, stored = _service(monkeypatch, calls)

    result = await service.import_sbom(TRIVY_CDX, kind="host")

    assert result["target_id"] == "sbom-import-demo-shop"
    assert result["findings_count"] == 5
    assert stored["scans"][0].scanners == ["trivy"]
    assert {f.scan_id for f in stored["findings"]} == {result["scan_id"]}
    assert {f.target_id for f in stored["findings"]} == {"sbom-import-demo-shop"}
    assert "sidecar" not in calls and "severity" in calls


async def test_cyclonedx_without_vulnerabilities_is_still_matched_by_hecate(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    service, stored = _service(monkeypatch, calls)

    async def no_matches(*_a: Any, **_k: Any) -> list[Any]:
        return []

    monkeypatch.setattr(service, "_match_vulnerabilities_for_components", no_matches)
    sbom = {key: value for key, value in TRIVY_CDX.items() if key != "vulnerabilities"}
    await service.import_sbom(sbom)
    assert stored["scans"][0].scanners == ["sbom-import"] and "sidecar" in calls


async def test_a_vex_document_on_the_sbom_import_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    service, stored = _service(monkeypatch, calls)
    vex = {"bomFormat": "CycloneDX", "components": [], "vulnerabilities": [
        {"id": "CVE-2024-0001", "analysis": {"state": "not_affected"}, "affects": [{"ref": "openssl"}]},
    ]}
    with pytest.raises(ValueError, match="VEX import"):
        await service.import_sbom(vex)
    assert stored["scans"] == [] and stored["targets"] == {}
