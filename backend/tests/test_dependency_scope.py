"""Dependency scope: parsing from scanner output, the merge rule, and copying it to findings."""
from __future__ import annotations

from typing import Any

from fake_mongo import FakeCollection

from app.models.scan import ScanFindingDocument, ScanSbomComponentDocument
from app.repositories.scan_finding_repository import ScanFindingRepository
from app.repositories.scan_sbom_repository import ScanSbomRepository
from app.services.dependency_scope import (
    ScopeIndex,
    cyclonedx_component_scope,
    merge_scope,
    normalize_scope,
)
from app.services.scan_parser import parse_cyclonedx_sbom, parse_hecate_json, parse_trivy_json
from app.services.scan_service import ScanService


def test_vocabulary() -> None:
    assert normalize_scope("required") == "runtime"
    assert normalize_scope("excluded") == "dev"
    assert normalize_scope("Optional") == "optional"
    assert normalize_scope("whatever") is None
    assert normalize_scope(None) is None


def test_merge_rule() -> None:
    assert merge_scope("dev", "runtime") == "runtime"
    assert merge_scope("runtime", "dev") == "runtime"
    assert merge_scope("dev", "optional") == "optional"
    assert merge_scope("dev", None) == "dev"
    assert merge_scope(None, "dev") == "dev"
    assert merge_scope(None, "bogus") is None


def test_cyclonedx_scope_prefers_hecate_property() -> None:
    assert cyclonedx_component_scope({"scope": "excluded"}) == "dev"
    assert cyclonedx_component_scope({"scope": "required"}) == "runtime"
    assert cyclonedx_component_scope({
        "scope": "required", "properties": [{"name": "hecate:scope", "value": "optional"}],
    }) == "optional"
    assert cyclonedx_component_scope({}) is None


def test_parsers_read_scope_and_merge_duplicates() -> None:
    components, _ = parse_cyclonedx_sbom({"components": [
        {"type": "library", "name": "lodash", "version": "4.17.21", "scope": "excluded"},
        {"type": "library", "name": "lodash", "version": "4.17.21", "scope": "required"},
        {"type": "library", "name": "jest", "version": "29.0.0", "scope": "excluded"},
        {"type": "library", "name": "plain", "version": "1"},
    ]}, "s", "t")
    scopes = {c.name: c.scope for c in components}
    assert scopes == {"lodash": "runtime", "jest": "dev", "plain": None}

    _, sbom, _ = parse_hecate_json({"components": [
        {"type": "library", "name": "vite", "version": "7.0.0",
         "properties": [{"name": "hecate:scope", "value": "dev"}]},
    ]}, "s", "t")
    assert sbom[0].scope == "dev"

    _, trivy, _ = parse_trivy_json({"Results": [{"Target": "package-lock.json", "Type": "npm", "Packages": [
        {"Name": "mocha", "Version": "10.0.0", "Dev": True},
        {"Name": "express", "Version": "4.21.0"},
    ]}]}, "s", "t")
    assert {c.name: c.scope for c in trivy} == {"mocha": "dev", "express": None}


def test_scope_index_lookup_is_spelling_insensitive_and_falls_back_to_name() -> None:
    index = ScopeIndex([
        ("PyYAML", "6.0.1", "dev"),
        ("requests", "2.32.0", "runtime"),
        ("requests", "2.31.0", "dev"),
        ("unknown-pkg", "1", None),
    ])
    assert index.for_package("pyyaml", "6.0.1") == "dev"
    assert index.for_package("PyYaml", "v6.0.1") == "dev"
    assert index.for_package("ruamel_yaml", "6.0.1") is None
    assert index.for_package("requests", "2.31.0") == "dev"
    assert index.for_package("requests", "9.9.9") == "runtime"  # name fallback: runtime wins
    assert index.for_package("unknown-pkg", "1") is None
    assert index.by_component == {("PyYAML", "6.0.1"): "dev", ("requests", "2.32.0"): "runtime",
                                  ("requests", "2.31.0"): "dev"}


def test_scope_never_crosses_ecosystems() -> None:
    # A polyglot repo: npm dummy-lib is a dev dependency, PyPI dummy_lib runs in
    # production and no scanner scoped it. The npm scope must not reach it.
    index = ScopeIndex([
        ("dummy-lib", "9.0.0", "dev", "npm"),
        ("dummy_lib", "1.2.3", None, "pypi"),
    ])
    assert index.for_package("dummy_lib", "1.2.3", "pypi") is None
    assert index.for_package("dummy-lib", "9.0.0", "npm") == "dev"
    assert index.for_package("dummy-lib", "8.0.0", "npm") == "dev"  # name fallback inside npm
    # Unknown ecosystem: only an exact match while two ecosystems know the name.
    assert index.for_package("dummy_lib", "1.2.3") is None
    assert index.for_package("dummy-lib", "9.0.0") == "dev"


def test_purl_less_components_stand_in_only_without_a_competing_ecosystem() -> None:
    index = ScopeIndex([("left-pad", "1.3.0", "dev", "")])
    assert index.for_package("left-pad", "1.3.0", "npm") == "dev"
    assert index.for_package("left-pad", "1.2.0", "npm") == "dev"
    mixed = ScopeIndex([("left-pad", "1.3.0", "dev", ""), ("left_pad", "0.1", "runtime", "pypi")])
    assert mixed.for_package("left-pad", "1.2.0", "npm") is None
    assert mixed.for_package("left-pad", "1.3.0", "npm") == "dev"  # exact purl-less match still counts


async def test_scan_service_writes_merged_scope_to_sbom_rows_and_findings() -> None:
    sbom = FakeCollection([
        {"scan_id": "s", "name": "lodash", "version": "4.17.21", "scope": "dev"},
        {"scan_id": "s", "name": "lodash", "version": "4.17.21", "scope": None},
        {"scan_id": "s", "name": "lodash", "version": "4.17.21", "scope": "runtime"},
        {"scan_id": "s", "name": "jest", "version": "29.0.0", "scope": "dev"},
    ])
    findings = FakeCollection([
        {"scan_id": "s", "package_name": "lodash", "package_version": "4.17.21", "dependency_scope": None},
        {"scan_id": "s", "package_name": "jest", "package_version": "29.0.0", "dependency_scope": None},
        {"scan_id": "s", "package_name": "zlib", "package_version": "1.3", "dependency_scope": None},
    ])
    service = ScanService(
        target_repo=None, scan_repo=None,  # type: ignore[arg-type]
        finding_repo=ScanFindingRepository(findings),  # type: ignore[arg-type]
        sbom_repo=ScanSbomRepository(sbom),  # type: ignore[arg-type]
        layer_repo=None, audit_service=None,  # type: ignore[arg-type]
    )
    components = [ScanSbomComponentDocument(scan_id="s", target_id="t", name=d["name"], version=d["version"],
                                            scope=d["scope"]) for d in sbom.docs]
    finding_docs = [ScanFindingDocument(scan_id="s", target_id="t", scanner="trivy", package_name=d["package_name"],
                                        package_version=d["package_version"]) for d in findings.docs]

    await service._apply_dependency_scopes("s", components, finding_docs)

    assert {(d["name"], d["scope"]) for d in sbom.docs} == {("lodash", "runtime"), ("jest", "dev")}
    by_pkg: dict[str, Any] = {d["package_name"]: d["dependency_scope"] for d in findings.docs}
    assert by_pkg == {"lodash": "runtime", "jest": "dev", "zlib": None}
    assert [f.dependency_scope for f in finding_docs] == ["runtime", "dev", None]
