"""Native libraries inside prebuilt packages (sharp's libvips)."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from typing import Any

import httpx
import pytest

from app.core.config import settings
from app.models.scan import ScanSbomComponentDocument
from app.services import bundled_libraries as bl
from app.services.bundled_libraries import (
    BundledLibraryResolver,
    carrier_versions,
    fetch_sharp_libvips_manifest,
    libraries_from_manifest,
)
from app.services.scan_service import ScanService
from tests.fake_mongo import FakeCollection

MANIFEST = {"heif": "1.17.6", "xml2": "2.13.5", "vips": "8.16.0", "proxy-libintl": "0.4", "newlib": "1.0"}
CARRIER = "@img/sharp-libvips-linux-x64"


def _tarball(manifest: dict[str, Any] | None = MANIFEST) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        files = {"package/package.json": b'{"name": "x"}'}
        if manifest is not None:
            files["package/versions.json"] = json.dumps(manifest).encode()
        for path, data in files.items():
            info = tarfile.TarInfo(path)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _sri(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def _client(data: bytes, integrity: str | None = None, calls: list[str] | None = None) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(str(request.url))
        if request.url.path.endswith(".tgz"):
            return httpx.Response(200, content=data)
        return httpx.Response(200, json={"dist": {
            "tarball": "https://registry.example/x/-/x-1.0.4.tgz",
            "integrity": integrity if integrity is not None else _sri(data),
        }})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class _Cache:
    def __init__(self) -> None:
        self.docs: dict[str, dict[str, Any]] = {}
        self.ttls: dict[str, float] = {}

    async def get_many(self, keys: list[str]) -> dict[str, dict[str, Any]]:
        return {k: self.docs[k] for k in keys if k in self.docs}

    async def put_many(self, docs: dict[str, dict[str, Any]], ttl_hours: float) -> None:
        for key, doc in docs.items():
            self.docs[key] = doc
            self.ttls[key] = ttl_hours


def test_manifest_maps_known_libraries_and_skips_the_shim() -> None:
    libs = {lib.name: lib for lib in libraries_from_manifest(MANIFEST, f"{CARRIER}@1.0.4")}
    assert "proxy-libintl" not in libs
    heif = libs["libheif"]
    assert heif.version == "1.17.6"
    assert heif.vendor_slugs == ("struktur",)
    assert heif.product_slug == "libheif"
    assert heif.purl == "pkg:generic/libheif@1.17.6"
    assert heif.cpe == "cpe:2.3:a:struktur:libheif:1.17.6:*:*:*:*:*:*:*"
    assert heif.carrier == f"{CARRIER}@1.0.4"
    assert libs["libxml2"].vendor_slugs == ("xmlsoft", "gnome")
    # sharp-libvips 1.0.x calls it "xml".
    assert [lib.name for lib in libraries_from_manifest({"xml": "2.13.3"}, "c@1")] == ["libxml2"]
    # An unknown key keeps its own name and has no vendor, so it matches no advisory.
    assert libs["newlib"].vendor_slugs == ()


def test_one_lookup_per_release_across_platform_variants() -> None:
    components = [
        {"name": "@img/sharp-libvips-linux-x64", "version": "1.0.4"},
        {"name": "@img/sharp-libvips-linuxmusl-x64", "version": "1.0.4"},
        {"name": "@img/sharp-libvips-darwin-arm64", "version": "1.1.0"},
        {"name": "@img/sharp-libvips-linux-x64", "version": "workspace:*"},
        {"name": "sharp", "version": "0.33.5"},
    ]
    assert carrier_versions(components) == {
        "1.0.4": "@img/sharp-libvips-linux-x64@1.0.4",
        "1.1.0": "@img/sharp-libvips-darwin-arm64@1.1.0",
    }


async def test_fetch_reads_the_manifest_after_the_integrity_check() -> None:
    data = _tarball()
    async with _client(data) as client:
        assert await fetch_sharp_libvips_manifest(client, CARRIER, "1.0.4") == MANIFEST
    async with _client(data, integrity=_sri(b"something else")) as client:
        assert await fetch_sharp_libvips_manifest(client, CARRIER, "1.0.4") is None
    async with _client(_tarball(None)) as client:
        assert await fetch_sharp_libvips_manifest(client, CARRIER, "1.0.4") is None


async def test_fetch_stops_past_the_size_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sca_bundled_libraries_max_download_mb", 0)
    async with _client(_tarball()) as client:
        assert await fetch_sharp_libvips_manifest(client, CARRIER, "1.0.4") is None


async def test_resolver_caches_hits_and_failures() -> None:
    calls: list[str] = []
    cache = _Cache()
    components = [{"name": CARRIER, "version": "1.0.4"}]
    async with _client(_tarball(), calls=calls) as client:
        resolver = BundledLibraryResolver(client=client, cache=cache)
        first = await resolver.resolve(components)
        fetched = len(calls)
        second = await resolver.resolve(components)
    assert {lib.name for lib in first} == {"libheif", "libxml2", "libvips", "newlib"}
    assert [(lib.name, lib.version) for lib in first] == [(lib.name, lib.version) for lib in second]
    assert len(calls) == fetched == 2  # metadata + tarball, once
    assert cache.ttls["bundled|sharp-libvips|1.0.4"] == bl._CACHE_TTL_HOURS

    failing = _Cache()
    async with _client(_tarball(None)) as client:
        assert await BundledLibraryResolver(client=client, cache=failing).resolve(components) == []
    assert failing.ttls["bundled|sharp-libvips|1.0.4"] == bl._FAILURE_TTL_HOURS


class _Store:
    def __init__(self) -> None:
        self.rows: list[Any] = []

    async def bulk_insert(self, rows: list[Any]) -> int:
        self.rows.extend(rows)
        return len(rows)


async def test_scan_gets_library_rows_and_vendor_scoped_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    vulns = FakeCollection([
        {   # libheif before 1.18.0: applies to the bundled 1.17.6
            "_id": "CVE-2024-41311",
            "vendor_slugs": ["struktur"], "product_slugs": ["libheif"],
            "impactedProducts": [{"vendor": {"slug": "struktur"}, "product": {"slug": "libheif"},
                                  "versions": ["< 1.18.0"]}],
        },
        {   # fixed before the bundled version
            "_id": "CVE-2023-0001",
            "vendor_slugs": ["struktur"], "product_slugs": ["libheif"],
            "impactedProducts": [{"vendor": {"slug": "struktur"}, "product": {"slug": "libheif"},
                                  "versions": ["< 1.15.0"]}],
        },
        {   # same product name, other vendor: never matched
            "_id": "CVE-2024-9999",
            "vendor_slugs": ["someone-else"], "product_slugs": ["libheif"],
            "impactedProducts": [{"vendor": {"slug": "someone-else"}, "product": {"slug": "libheif"},
                                  "versions": ["< 9"]}],
        },
    ])

    async def database() -> dict[str, FakeCollection]:
        return {settings.mongo_vulnerabilities_collection: vulns}

    monkeypatch.setattr("app.db.mongo.get_database", database)
    cache = _Cache()
    async with _client(_tarball({"heif": "1.17.6", "vips": "8.16.0"})) as client:
        monkeypatch.setattr(bl, "_resolver", BundledLibraryResolver(client=client, cache=cache))
        sbom, findings = _Store(), _Store()
        service = ScanService(
            target_repo=None, scan_repo=None, finding_repo=findings, sbom_repo=sbom,
            layer_repo=None, audit_service=None,
        )
        components = [
            ScanSbomComponentDocument(scan_id="s1", target_id="t1", name=CARRIER, version="1.0.4"),
            # Already listed by a scanner: not added twice.
            ScanSbomComponentDocument(scan_id="s1", target_id="t1", name="libvips", version="8.16.0"),
        ]
        rows, found = await service._add_bundled_libraries("s1", "t1", components)

    assert [(r.name, r.version, r.type, r.bundled_in) for r in rows] == [
        ("libheif", "1.17.6", "library", f"{CARRIER}@1.0.4"),
    ]
    assert sbom.rows == rows
    assert [(f.vulnerability_id, f.package_name, f.scanner) for f in found] == [
        ("CVE-2024-41311", "libheif", "bundled-libraries"),
    ]
    assert findings.rows == found


async def test_disabled_or_failing_lookup_adds_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    service = ScanService(
        target_repo=None, scan_repo=None, finding_repo=_Store(), sbom_repo=_Store(),
        layer_repo=None, audit_service=None,
    )
    components = [{"name": CARRIER, "version": "1.0.4"}]
    monkeypatch.setattr(settings, "sca_bundled_libraries_enabled", False)
    assert await service._add_bundled_libraries("s1", "t1", components) == ([], [])

    monkeypatch.setattr(settings, "sca_bundled_libraries_enabled", True)

    class _Broken:
        async def resolve(self, _components: Any) -> list[Any]:
            raise RuntimeError("registry down")

    monkeypatch.setattr(bl, "_resolver", _Broken())
    assert await service._add_bundled_libraries("s1", "t1", components) == ([], [])


def test_cyclonedx_export_names_the_carrier() -> None:
    from app.services.sbom_export import supply_chain_properties

    props = supply_chain_properties({"bundled_in": f"{CARRIER}@1.0.4"})
    assert {"name": "hecate:bundledIn", "value": f"{CARRIER}@1.0.4"} in props
