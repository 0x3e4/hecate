"""Native libraries bundled inside prebuilt packages (prototype: sharp's libvips).

A package can ship compiled libraries no manifest names. ``sharp`` (npm) pulls
in ``@img/sharp-libvips-<platform>``, a prebuilt libvips with libheif, libxml2,
libpng, libtiff, libwebp and two dozen more linked in. A lockfile and the SBOM
scanners see the npm package, not those libraries, so a libheif CVE never
reaches the scan. The libvips packages carry the exact versions in a
``versions.json`` at the package root (identical across platform variants of
one release), so they can be read from the registry once per release.

The libraries are added to the scan's SBOM as ``native-library`` components
with ``bundled_in`` naming the carrier, and matched against the vulnerability
DB through the inventory matcher with an explicit CPE vendor and product: a
bare name match would let ``glib`` or ``pango`` meet unrelated products.

The library table is curated: a key maps to the CPE vendor(s) NVD files the
library under. Keys without a CPE (cgif, proxy-libintl) or with a commit hash
as version (mozjpeg) still land in the SBOM, the fail-closed matcher just finds
nothing for them.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import quote

import httpx
import structlog

from app.core.config import settings
from app.services.http.ssl import get_http_verify
from app.utils.strings import slugify

log = structlog.get_logger()

SHARP_LIBVIPS_PREFIX = "@img/sharp-libvips-"
_VERSIONS_MEMBER = "package/versions.json"
_MAX_MANIFEST_BYTES = 64 * 1024
_CACHE_KEY = "bundled|sharp-libvips|{version}"
_CACHE_TTL_HOURS = 24 * 30  # a published npm version never changes
_FAILURE_TTL_HOURS = 6
_CONCRETE_VERSION = re.compile(r"^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$")


@dataclass(frozen=True)
class NativeLibrary:
    """One library of the carrier's manifest, with where NVD files it."""

    name: str
    cpe_vendors: tuple[str, ...]
    cpe_product: str


# versions.json key -> library. Vendors as NVD writes them in the CPE; several
# where NVD changed its mind (libxml2 moved from xmlsoft to gnome).
SHARP_LIBVIPS_LIBRARIES: dict[str, NativeLibrary] = {
    "aom": NativeLibrary("libaom", ("aomedia",), "aomedia"),
    "archive": NativeLibrary("libarchive", ("libarchive",), "libarchive"),
    "cairo": NativeLibrary("cairo", ("cairographics",), "cairo"),
    "cgif": NativeLibrary("cgif", (), "cgif"),
    "exif": NativeLibrary("libexif", ("libexif_project", "libexif"), "libexif"),
    "expat": NativeLibrary("libexpat", ("libexpat_project",), "libexpat"),
    "ffi": NativeLibrary("libffi", ("libffi_project",), "libffi"),
    "fontconfig": NativeLibrary("fontconfig", ("fontconfig_project",), "fontconfig"),
    "freetype": NativeLibrary("freetype", ("freetype",), "freetype"),
    "fribidi": NativeLibrary("fribidi", ("gnu", "fribidi"), "fribidi"),
    "glib": NativeLibrary("glib", ("gnome",), "glib"),
    "harfbuzz": NativeLibrary("harfbuzz", ("harfbuzz_project",), "harfbuzz"),
    "heif": NativeLibrary("libheif", ("struktur",), "libheif"),
    "highway": NativeLibrary("highway", ("google",), "highway"),
    "imagequant": NativeLibrary("libimagequant", (), "libimagequant"),
    "lcms": NativeLibrary("lcms2", ("littlecms",), "little_cms_color_engine"),
    "mozjpeg": NativeLibrary("mozjpeg", ("mozilla",), "mozjpeg"),
    "pango": NativeLibrary("pango", ("gnome",), "pango"),
    "pixman": NativeLibrary("pixman", ("pixman",), "pixman"),
    "png": NativeLibrary("libpng", ("libpng",), "libpng"),
    "rsvg": NativeLibrary("librsvg", ("gnome",), "librsvg"),
    "tiff": NativeLibrary("libtiff", ("libtiff",), "libtiff"),
    "uhdr": NativeLibrary("libultrahdr", ("google",), "libultrahdr"),
    "vips": NativeLibrary("libvips", ("libvips",), "libvips"),
    "webp": NativeLibrary("libwebp", ("webmproject",), "libwebp"),
    "xml2": NativeLibrary("libxml2", ("xmlsoft", "gnome"), "libxml2"),
    # libvips 8.15 builds (sharp-libvips 1.0.x) name it "xml".
    "xml": NativeLibrary("libxml2", ("xmlsoft", "gnome"), "libxml2"),
    "spng": NativeLibrary("libspng", (), "libspng"),
    "zlib-ng": NativeLibrary("zlib-ng", ("zlib-ng",), "zlib-ng"),
}
# Build glue, not a library anyone files CVEs against.
_IGNORED_KEYS = frozenset({"proxy-libintl"})


@dataclass(frozen=True)
class BundledLibrary:
    """A library found inside a carrier package of the scan."""

    name: str
    version: str
    cpe_vendors: tuple[str, ...]  # as NVD writes them, e.g. libexpat_project
    cpe_product: str
    carrier: str  # "<package>@<version>"

    @property
    def vendor_slugs(self) -> tuple[str, ...]:
        return tuple(slugify(vendor) for vendor in self.cpe_vendors)

    @property
    def product_slug(self) -> str:
        return slugify(self.cpe_product)

    @property
    def purl(self) -> str:
        return f"pkg:generic/{quote(self.name, safe='')}@{quote(self.version, safe='')}"

    @property
    def cpe(self) -> str | None:
        if not self.cpe_vendors:
            return None
        return f"cpe:2.3:a:{self.cpe_vendors[0]}:{self.cpe_product}:{self.version}:*:*:*:*:*:*:*"


def _field(component: Any, key: str) -> Any:
    return component.get(key) if isinstance(component, dict) else getattr(component, key, None)


def carrier_versions(components: Iterable[Any]) -> dict[str, str]:
    """``{libvips release: carrier}`` for the sharp-libvips packages among ``components``.

    Every platform variant of one release (linux-x64, darwin-arm64, ...) ships
    the same libraries, so one release is one lookup; the first variant seen
    names the carrier.
    """
    found: dict[str, str] = {}
    for component in components:
        name = _field(component, "name")
        version = (_field(component, "version") or "").strip()
        if not isinstance(name, str) or not name.startswith(SHARP_LIBVIPS_PREFIX):
            continue
        if not _CONCRETE_VERSION.match(version):
            continue
        found.setdefault(version, f"{name}@{version}")
    return found


def libraries_from_manifest(manifest: Any, carrier: str) -> list[BundledLibrary]:
    """The libraries of one ``versions.json`` (unknown keys keep their own name)."""
    if not isinstance(manifest, dict):
        return []
    libraries: list[BundledLibrary] = []
    for key, raw_version in sorted(manifest.items()):
        if not isinstance(key, str) or key in _IGNORED_KEYS:
            continue
        version = raw_version.strip() if isinstance(raw_version, str) else ""
        if not version or len(version) > 64:
            continue
        library = SHARP_LIBVIPS_LIBRARIES.get(key) or NativeLibrary(key, (), key)
        libraries.append(BundledLibrary(
            name=library.name,
            version=version,
            cpe_vendors=library.cpe_vendors,
            cpe_product=library.cpe_product,
            carrier=carrier,
        ))
    return libraries


def _manifest_from_tarball(data: bytes) -> dict[str, Any] | None:
    """``package/versions.json`` of an npm tarball, read in memory (nothing is extracted)."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        try:
            member = archive.getmember(_VERSIONS_MEMBER)
        except KeyError:
            return None
        if not member.isfile() or member.size > _MAX_MANIFEST_BYTES:
            return None
        handle = archive.extractfile(member)
        if handle is None:
            return None
        parsed = json.loads(handle.read(_MAX_MANIFEST_BYTES))
    return parsed if isinstance(parsed, dict) else None


def _integrity_ok(data: bytes, integrity: Any) -> bool:
    """Check the tarball against the registry's ``dist.integrity`` (sha512 SRI)."""
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        return False
    expected = integrity.split("-", 1)[1].split()[0]
    actual = base64.b64encode(hashlib.sha512(data).digest()).decode()
    return actual == expected


async def fetch_sharp_libvips_manifest(client: httpx.AsyncClient, name: str, version: str) -> dict[str, Any] | None:
    """Download one sharp-libvips release from the npm registry and read its manifest.

    The tarball (8 to 18 MB) is size-capped and checked against the registry's
    sha512 integrity before anything in it is read.
    """
    base = settings.sca_bundled_libraries_registry_url.rstrip("/")
    meta = await client.get(f"{base}/{quote(name, safe='@')}/{quote(version, safe='')}")
    if meta.status_code != 200:
        log.info("bundled_libraries.metadata_missing", package=name, version=version, status=meta.status_code)
        return None
    dist = (meta.json() or {}).get("dist") or {}
    tarball_url = dist.get("tarball")
    if not isinstance(tarball_url, str) or not tarball_url.startswith(("https://", "http://")):
        return None

    limit = settings.sca_bundled_libraries_max_download_mb * 1024 * 1024
    chunks: list[bytes] = []
    size = 0
    async with client.stream("GET", tarball_url) as response:
        if response.status_code != 200:
            return None
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > limit:
                log.warning("bundled_libraries.tarball_too_large", package=name, version=version, limit=limit)
                return None
            chunks.append(chunk)
    data = b"".join(chunks)
    if not _integrity_ok(data, dist.get("integrity")):
        log.warning("bundled_libraries.integrity_mismatch", package=name, version=version)
        return None
    return await asyncio.to_thread(_manifest_from_tarball, data)


class BundledLibraryResolver:
    """Finds the bundled libraries of a scan's components, through a cache."""

    def __init__(self, client: httpx.AsyncClient | None = None, cache: Any = None) -> None:
        self._client = client
        self._cache = cache
        self._semaphore = asyncio.Semaphore(2)

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(60.0, connect=10.0),
                headers={"User-Agent": settings.ingestion_user_agent},
                verify=get_http_verify(),
                follow_redirects=True,
            )
        return self._client

    async def _cache_repo(self) -> Any:
        if self._cache is None:
            from app.repositories.package_release_repository import PackageReleaseRepository

            self._cache = await PackageReleaseRepository.create()
        return self._cache

    async def _manifest(self, version: str, carrier: str) -> dict[str, Any] | None:
        name = carrier.rsplit("@", 1)[0]
        async with self._semaphore:
            try:
                return await fetch_sharp_libvips_manifest(self._http(), name, version)
            except (httpx.HTTPError, tarfile.TarError, ValueError, OSError) as exc:
                log.warning("bundled_libraries.fetch_failed", package=name, version=version, error=str(exc))
                return None

    async def resolve(self, components: Iterable[Any]) -> list[BundledLibrary]:
        carriers = carrier_versions(components)
        if not carriers:
            return []
        cache = await self._cache_repo()
        keys = {version: _CACHE_KEY.format(version=version) for version in carriers}
        cached = await cache.get_many(list(keys.values()))

        manifests: dict[str, dict[str, Any] | None] = {}
        missing = [version for version, key in keys.items() if key not in cached]
        for version, key in keys.items():
            if key in cached:
                manifests[version] = cached[key].get("libraries")
        fetched = await asyncio.gather(*(self._manifest(v, carriers[v]) for v in missing))
        found = {keys[v]: {"libraries": m} for v, m in zip(missing, fetched) if m is not None}
        failed = {keys[v]: {"libraries": None} for v, m in zip(missing, fetched) if m is None}
        await cache.put_many(found, _CACHE_TTL_HOURS)
        await cache.put_many(failed, _FAILURE_TTL_HOURS)
        manifests.update(zip(missing, fetched))

        libraries: list[BundledLibrary] = []
        seen: set[tuple[str, str]] = set()
        for version, manifest in manifests.items():
            for library in libraries_from_manifest(manifest, carriers[version]):
                if (library.name, library.version) not in seen:
                    seen.add((library.name, library.version))
                    libraries.append(library)
        return libraries


_resolver: BundledLibraryResolver | None = None


def get_bundled_library_resolver() -> BundledLibraryResolver:
    global _resolver
    if _resolver is None:
        _resolver = BundledLibraryResolver()
    return _resolver
