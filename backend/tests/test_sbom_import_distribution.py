"""SBOM imports and distribution packages (GitHub issue #2).

With a distro-aware scanner (Grype in the sidecar) answering, distribution
packages are left to it and every finding goes through the passes an image
scan's findings get. Without one, Hecate matches a distribution package as its
source package at the upstream version, never against a language registry's
advisory, and says that a backported fix cannot be seen that way.
"""
from __future__ import annotations

from typing import Any

import pytest

from app.models.scan import ScanFindingDocument
from app.services.os_packages import match_identity, purl_upstream, source_packages, upstream_version
from app.services.possibly_affected import sbom_component_fits
from app.services.sbom_ecosystem import (
    ExcludedVendors,
    affected_entries_by_slug,
    allowed_vendor_slugs,
    component_in_affected_range,
    vendor_names_component,
)
from app.services.scan_service import ScanService

from tests.test_scan_report_import import _service


# ---------------------------------------------------------------- versions and sources


@pytest.mark.parametrize(
    ("version", "purl_type", "expected"),
    [
        ("1:2.36-9+deb12u4", "deb", "2.36"),
        ("3.0.11-1~deb12u2", "deb", "3.0.11"),
        ("2.1.28+dfsg1-9", "deb", "2.1.28"),
        ("1.2.3~rc1-2", "deb", "1.2.3-rc1"),
        ("1.0", "deb", "1.0"),
        ("2.34-100.el9_4.2", "rpm", "2.34"),
        ("3.1.4-r5", "apk", "3.1.4"),
        ("1:1.3.1-1", "alpm", "1.3.1"),
        ("", "deb", ""),
    ],
)
def test_upstream_version(version: str, purl_type: str, expected: str) -> None:
    assert upstream_version(version, purl_type) == expected


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:deb/debian/libc6@2.36-9?arch=amd64&upstream=glibc&distro=debian-12", ("glibc", None)),
        ("pkg:deb/debian/libssl3@3.0.11-1?upstream=openssl%403.0.11-1", ("openssl", "3.0.11-1")),
        ("pkg:rpm/redhat/glibc-common@2.34-100.el9?upstream=glibc-2.34-100.el9.src.rpm", ("glibc", "2.34-100.el9")),
        ("pkg:rpm/redhat/x@1?upstream=broken.src.rpm", (None, None)),
        ("pkg:deb/debian/zlib1g@1.2.13?arch=amd64", (None, None)),
        (None, (None, None)),
    ],
)
def test_purl_upstream(purl: str | None, expected: tuple[str | None, str | None]) -> None:
    assert purl_upstream(purl) == expected


def test_source_packages_from_syft_and_trivy_sboms() -> None:
    cyclonedx = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "libc6", "version": "2.36-9+deb12u4", "purl": "pkg:deb/debian/libc6@2.36-9+deb12u4?upstream=glibc"},
            {"name": "libssl3", "version": "3.0.11-1~deb12u2", "purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u2",
             "properties": [
                 {"name": "aquasecurity:trivy:SrcName", "value": "openssl"},
                 {"name": "aquasecurity:trivy:SrcVersion", "value": "3.0.11"},
                 {"name": "aquasecurity:trivy:SrcRelease", "value": "1~deb12u2"},
             ]},
            {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0?upstream=x"},
            {"name": "app", "version": "1", "components": [
                {"name": "libgcc-s1", "version": "12.2.0-14", "purl": "pkg:deb/debian/libgcc-s1@12.2.0-14?upstream=gcc-12"},
            ]},
        ],
    }
    assert source_packages(cyclonedx) == {
        ("libc6", "2.36-9+deb12u4"): ("glibc", None),
        ("libssl3", "3.0.11-1~deb12u2"): ("openssl", "3.0.11-1~deb12u2"),
        ("libgcc-s1", "12.2.0-14"): ("gcc-12", None),
    }
    spdx = {"spdxVersion": "SPDX-2.3", "packages": [
        {"name": "libc6", "versionInfo": "2.36-9", "externalRefs": [
            {"referenceType": "purl", "referenceLocator": "pkg:deb/debian/libc6@2.36-9?upstream=glibc"},
        ]},
    ]}
    assert source_packages(spdx) == {("libc6", "2.36-9"): ("glibc", None)}
    assert source_packages({"components": "junk"}) == {}


def test_match_identity() -> None:
    sources = {("libssl3", "3.0.11-1~deb12u2"): ("openssl", "3.0.11-1~deb12u2")}
    assert match_identity("libssl3", "3.0.11-1~deb12u2", "pkg:deb/debian/libssl3@3.0.11-1~deb12u2", sources) == (
        "openssl", "3.0.11", "pkg:deb/openssl@3.0.11",
    )
    assert match_identity("libc6", "2.36-9", "pkg:deb/debian/libc6@2.36-9?upstream=glibc", {}) == (
        "glibc", "2.36", "pkg:deb/glibc@2.36",
    )
    assert match_identity("busybox", "1.36.1-r15", "pkg:apk/alpine/busybox@1.36.1-r15", {}) == (
        "busybox", "1.36.1", "pkg:apk/busybox@1.36.1",
    )
    assert match_identity("requests", "2.31.0", "pkg:pypi/requests@2.31.0", {}) is None


# ---------------------------------------------------------------- vendors


def test_distribution_packages_never_take_a_registry_advisory() -> None:
    allowed = allowed_vendor_slugs("pkg:deb/debian/python3-requests@2.28.1-1", "requests")
    assert isinstance(allowed, ExcludedVendors)
    assert not vendor_names_component(allowed, ["pypi"])
    assert not vendor_names_component(allowed, ["PyPI", "pypi"])
    # NVD names CPython "python", the Go toolchain "golang": those stay.
    assert vendor_names_component(allowed, ["python"])
    assert vendor_names_component(allowed, ["psf", "pypi"])
    assert vendor_names_component(allowed, [])
    # Registry and binary packages keep their rules.
    assert vendor_names_component(allowed_vendor_slugs("pkg:pypi/requests@2.31.0", "requests"), ["pypi"])
    assert allowed_vendor_slugs("pkg:generic/openssl@3.0.11", "openssl") is None

    entries, _ = affected_entries_by_slug([
        {"vendor": {"slug": "pypi", "name": "PyPI"}, "product": {"slug": "requests", "name": "requests"},
         "versions": ["< 2.32.0"]},
    ])
    assert not component_in_affected_range(
        entries, name="requests", version="2.28.1", purl="pkg:deb/debian/requests@2.28.1-1",
    )
    assert component_in_affected_range(entries, name="requests", version="2.28.1", purl="pkg:pypi/requests@2.28.1")
    # Possibly affected keeps the plain name match for distribution packages without vendors.
    assert sbom_component_fits({"openssl": set()}, "openssl", "pkg:deb/debian/openssl@3.0.11-1")
    assert not sbom_component_fits({"requests": {"pypi"}}, "requests", "pkg:deb/debian/requests@2.28.1-1")


# ---------------------------------------------------------------- the import


def _sbom() -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"name": "web-01", "type": "operating-system"}},
        "components": [
            {"type": "library", "name": "libc6", "version": "2.36-9+deb12u4",
             "purl": "pkg:deb/debian/libc6@2.36-9+deb12u4?arch=amd64&upstream=glibc&distro=debian-12"},
            {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
        ],
    }


def _fake_local(service: ScanService, monkeypatch: pytest.MonkeyPatch, asked: list[Any]) -> None:
    async def local(keys: list[tuple[str, str, str | None]], vuln_collection: Any = None) -> dict[Any, list[str]]:
        asked.extend(keys)
        found = {}
        for key in keys:
            if key[0] == "glibc" and key[1] == "2.36":
                found[key] = ["CVE-2026-0001"]
            if key[0] == "requests":
                found[key] = ["CVE-2026-0002"]
        return found

    monkeypatch.setattr(service, "_local_vulnerability_matches", local)


async def test_without_a_distro_scanner_packages_match_as_their_source(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    service, stored = _service(monkeypatch, calls)
    asked: list[Any] = []
    _fake_local(service, monkeypatch, asked)

    await service.import_sbom(_sbom(), target_name="web-01")

    assert ("glibc", "2.36", "pkg:deb/glibc@2.36") in asked
    assert ("requests", "2.31.0", "pkg:pypi/requests@2.31.0") in asked
    by_package = {f.package_name: f for f in stored["findings"]}
    libc = by_package["libc6"]
    assert libc.vulnerability_id == "CVE-2026-0001" and libc.package_version == "2.36-9+deb12u4"
    assert "glibc 2.36" in libc.description and "backport" in libc.description
    assert by_package["requests"].description is None
    # The passes of an image scan ran over the import's findings.
    assert {"cve_fallback", "fix_versions", "severity"} <= set(calls)


async def test_a_distro_scanner_owns_the_distribution_packages(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    service, stored = _service(monkeypatch, calls)
    asked: list[Any] = []
    _fake_local(service, monkeypatch, asked)
    grype_finding = ScanFindingDocument(
        scan_id="s", target_id="t", vulnerability_id="CVE-2026-0009", scanner="grype",
        package_name="libc6", package_version="2.36-9+deb12u4", severity="high", fix_version="2.36-9+deb12u7",
    )

    async def sidecar(*_a: Any, **_k: Any) -> tuple[list[ScanFindingDocument], list[str]]:
        return [grype_finding], ["grype"]

    monkeypatch.setattr(service, "_scan_imported_sbom", sidecar)
    seen_by_passes: list[list[str]] = []

    async def severity(_scan_id: str, findings: list[ScanFindingDocument]) -> None:
        seen_by_passes.append(sorted(f"{f.scanner}:{f.package_name}" for f in findings))

    monkeypatch.setattr(service, "_override_severity_from_vuln_db", severity)

    await service.import_sbom(_sbom(), target_name="web-01")

    # The distribution package was not even looked up locally; the language package was.
    assert [key[0] for key in asked] == ["requests"]
    assert sorted(f.vulnerability_id for f in stored["findings"]) == ["CVE-2026-0002", "CVE-2026-0009"]
    # Grype's findings went through the passes too (issue #2: fix versions, severity).
    assert seen_by_passes == [["grype:libc6", "sbom-import:requests"]]
    assert {"cve_fallback", "fix_versions"} <= set(calls)
