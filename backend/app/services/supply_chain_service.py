"""Supply-chain signals for registry packages: release age, maintenance, publisher.

Worms like Shai-Hulud spread by publishing new versions from taken-over
maintainer accounts, and most get caught within days. Three signals per
SBOM component (and in the package check):

- ``fresh_release``: the installed version was published less than
  ``SCA_FRESH_RELEASE_DAYS`` (7) days ago, a "cooldown" warning.
- ``unmaintained``: the package's latest release is older than
  ``SCA_UNMAINTAINED_DAYS`` (730) days.
- ``publisher_changed`` (npm): the npm account that published the installed
  version published none of the ``SCA_PUBLISHER_HISTORY`` (3) versions
  before it. Also lists maintainers added since the previous version. Only
  checked for versions at most ``SCA_PUBLISHER_CHECK_MAX_AGE_DAYS`` old.

Release dates and the latest version come from deps.dev's GetPackage (npm,
PyPI, Go, Maven, Cargo, NuGet, RubyGems; one request per package covers every
version of it in a scan), Packagist's p2 metadata for Composer, and the npm
registry's per-version documents for the publisher. Everything is cached per
(ecosystem, name, version) in ``package_releases`` with a TTL; publisher
documents of a version never change and are kept for 30 days. Failures are
soft: a lookup that fails leaves the component without signals.

Only npm account *names* are stored, never e-mail addresses.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, unquote

import httpx
import structlog

from app.core.config import settings
from app.services.http.rate_limiter import AsyncRateLimiter
from app.services.http.retry import request_with_retry
from app.services.http.ssl import get_http_verify

log = structlog.get_logger()

# purl type -> Hecate ecosystem name
PURL_ECOSYSTEMS: dict[str, str] = {
    "npm": "npm",
    "pypi": "pypi",
    "golang": "go",
    "maven": "maven",
    "cargo": "cargo",
    "nuget": "nuget",
    "gem": "rubygems",
    "composer": "packagist",
}

# What users and agents type -> Hecate ecosystem name
ECOSYSTEM_ALIASES: dict[str, str] = {
    "npm": "npm", "node": "npm", "yarn": "npm", "pnpm": "npm",
    "pypi": "pypi", "pip": "pypi", "python": "pypi",
    "go": "go", "golang": "go",
    "maven": "maven", "java": "maven",
    "cargo": "cargo", "crates.io": "cargo", "crates": "cargo", "rust": "cargo",
    "nuget": "nuget", ".net": "nuget", "dotnet": "nuget",
    "rubygems": "rubygems", "gem": "rubygems", "ruby": "rubygems",
    "packagist": "packagist", "composer": "packagist", "php": "packagist",
}

_DEPS_DEV_SYSTEMS: dict[str, str] = {
    "npm": "NPM", "pypi": "PYPI", "go": "GO", "maven": "MAVEN",
    "cargo": "CARGO", "nuget": "NUGET", "rubygems": "RUBYGEMS",
}

SUPPORTED_ECOSYSTEMS = frozenset(_DEPS_DEV_SYSTEMS) | {"packagist"}

_NPM_META_TTL_HOURS = 24 * 30
_UNKNOWN_TTL_HOURS = 6
# The unpinned "latest" answer and a pinned version the registry does not list
# (yet): both change with the next publish.
_MUTABLE_TTL_HOURS = 0.25
_DAY_SECONDS = 86400


def canonical_ecosystem(value: str | None) -> str | None:
    if not value:
        return None
    return ECOSYSTEM_ALIASES.get(value.strip().lower())


def normalize_package_name(ecosystem: str, name: str) -> str:
    name = name.strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in ("npm", "packagist", "cargo"):
        return name.lower()
    return name


def package_from_purl(purl: str | None) -> tuple[str, str, str] | None:
    """``(ecosystem, name, version)`` of a registry purl, else ``None``."""
    if not purl or not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    version = ""
    last = body.rsplit("/", 1)[-1]
    if "@" in last:
        body, version = body.rsplit("@", 1)
    parts = [unquote(p) for p in body.split("/") if p]
    if len(parts) < 2:
        return None
    ecosystem = PURL_ECOSYSTEMS.get(parts[0].lower())
    if not ecosystem:
        return None
    namespace, pkg = parts[1:-1], parts[-1]
    if ecosystem == "maven":
        if not namespace:
            return None
        name = f"{'.'.join(namespace)}:{pkg}"
    elif ecosystem in ("npm", "go", "packagist"):
        name = "/".join([*namespace, pkg])
    else:
        name = pkg
    return ecosystem, normalize_package_name(ecosystem, name), unquote(version)


def cache_key(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}|{name}|{version}"


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _version_variants(version: str) -> list[str]:
    v = version.strip()
    out = [v]
    out.append(v[1:] if v.startswith("v") else f"v{v}")
    return out


@dataclass
class VersionRecord:
    version: str
    published_at: datetime | None = None
    is_default: bool = False
    deprecated: bool = False


@dataclass
class ReleaseInfo:
    ecosystem: str
    name: str
    version: str
    package_found: bool = False
    version_found: bool = False
    published_at: datetime | None = None
    latest_version: str | None = None
    latest_published_at: datetime | None = None
    # Newest publish date of any version: "unmaintained" goes by this, since
    # the default version can be an old pre-release (Maven's log4j-core 3.0.0-beta3).
    last_release_at: datetime | None = None
    deprecated: bool | None = None
    publisher: str | None = None
    previous_publishers: list[str] = field(default_factory=list)
    new_maintainers: list[str] = field(default_factory=list)
    publisher_checked: bool = False

    def to_doc(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem, "name": self.name, "version": self.version,
            "package_found": self.package_found, "version_found": self.version_found,
            "published_at": self.published_at, "latest_version": self.latest_version,
            "latest_published_at": self.latest_published_at, "last_release_at": self.last_release_at,
            "deprecated": self.deprecated,
            "publisher": self.publisher, "previous_publishers": self.previous_publishers,
            "new_maintainers": self.new_maintainers, "publisher_checked": self.publisher_checked,
        }

    @classmethod
    def from_doc(cls, doc: dict[str, Any]) -> "ReleaseInfo":
        return cls(
            ecosystem=doc.get("ecosystem", ""), name=doc.get("name", ""), version=doc.get("version", ""),
            package_found=bool(doc.get("package_found")), version_found=bool(doc.get("version_found")),
            published_at=_parse_dt(doc.get("published_at")), latest_version=doc.get("latest_version"),
            latest_published_at=_parse_dt(doc.get("latest_published_at")),
            last_release_at=_parse_dt(doc.get("last_release_at")), deprecated=doc.get("deprecated"),
            publisher=doc.get("publisher"), previous_publishers=list(doc.get("previous_publishers") or []),
            new_maintainers=list(doc.get("new_maintainers") or []),
            publisher_checked=bool(doc.get("publisher_checked")),
        )

    def age_days(self, now: datetime | None = None) -> float | None:
        if not self.published_at:
            return None
        return ((now or datetime.now(UTC)) - self.published_at).total_seconds() / _DAY_SECONDS

    def flags(self, now: datetime | None = None) -> dict[str, bool | None]:
        """The three signals; ``None`` where the data to decide is missing."""
        now = now or datetime.now(UTC)
        fresh: bool | None = None
        if self.published_at:
            fresh = (now - self.published_at).total_seconds() < settings.sca_fresh_release_days * _DAY_SECONDS
        unmaintained: bool | None = None
        last = self.last_release_at or self.latest_published_at
        if last:
            unmaintained = (now - last).total_seconds() > settings.sca_unmaintained_days * _DAY_SECONDS
        changed: bool | None = None
        if self.publisher_checked and self.publisher and self.previous_publishers:
            changed = self.publisher not in self.previous_publishers
        return {"fresh_release": fresh, "unmaintained": unmaintained, "publisher_changed": changed}


def detect_publisher_change(
    installed: dict[str, Any] | None,
    previous: list[dict[str, Any] | None],
) -> tuple[str | None, list[str], list[str]]:
    """``(publisher, previous publishers, maintainers added)`` from npm version docs.

    ``previous`` runs newest first; the maintainer delta compares with the
    version right before the installed one.
    """
    publisher = (installed or {}).get("publisher")
    prev_publishers: list[str] = []
    for doc in previous:
        p = (doc or {}).get("publisher")
        if p and p not in prev_publishers:
            prev_publishers.append(p)
    added: list[str] = []
    if installed and previous and previous[0]:
        before = set(previous[0].get("maintainers") or [])
        if before:
            added = sorted(set(installed.get("maintainers") or []) - before)
    return publisher, prev_publishers, added


class ReleaseInfoClient:
    """HTTP side: deps.dev, Packagist, npm registry. Every call is fail-soft."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(
            timeout=settings.deps_dev_timeout_seconds,
            headers={"User-Agent": settings.ingestion_user_agent, "Accept": "application/json"},
            verify=get_http_verify(),
            follow_redirects=False,
        )
        self._deps_dev_limiter = AsyncRateLimiter(settings.deps_dev_rate_limit_seconds)
        self._registry_limiter = AsyncRateLimiter(0.05)

    async def close(self) -> None:
        await self._client.aclose()

    async def _get_json(self, url: str, limiter: AsyncRateLimiter, context: dict[str, Any]) -> Any:
        response = await request_with_retry(
            self._client, "GET", url,
            rate_limiter=limiter,
            max_retries=settings.deps_dev_max_retries,
            backoff_base=settings.deps_dev_retry_backoff_seconds,
            log_prefix="release_info",
            validate_json=True,
            context=context,
        )
        if response is None or response.status_code >= 400:
            return None
        try:
            return response.json()
        except Exception:  # noqa: BLE001
            return None

    async def fetch_versions(self, ecosystem: str, name: str) -> list[VersionRecord] | None:
        if ecosystem == "packagist":
            return await self._fetch_packagist(name)
        system = _DEPS_DEV_SYSTEMS.get(ecosystem)
        if not system:
            return None
        url = f"{settings.deps_dev_base_url.rstrip('/')}/systems/{system}/packages/{quote(name, safe='')}"
        data = await self._get_json(url, self._deps_dev_limiter, {"system": system, "package": name})
        if not isinstance(data, dict) or not isinstance(data.get("versions"), list):
            return None
        out: list[VersionRecord] = []
        for v in data["versions"]:
            key = v.get("versionKey") if isinstance(v, dict) else None
            version = key.get("version") if isinstance(key, dict) else None
            if not isinstance(version, str) or not version:
                continue
            out.append(VersionRecord(
                version=version,
                published_at=_parse_dt(v.get("publishedAt")),
                is_default=bool(v.get("isDefault")),
                deprecated=bool(v.get("isDeprecated")),
            ))
        return out

    async def _fetch_packagist(self, name: str) -> list[VersionRecord] | None:
        if name.count("/") != 1:
            return None
        url = f"https://repo.packagist.org/p2/{quote(name, safe='/')}.json"
        data = await self._get_json(url, self._registry_limiter, {"package": name})
        packages = data.get("packages") if isinstance(data, dict) else None
        entries = packages.get(name) if isinstance(packages, dict) else None
        if not isinstance(entries, list):
            return None
        out: list[VersionRecord] = []
        current: dict[str, Any] = {}
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            # Composer 2 "minified" metadata: each entry only lists what changed.
            current = {**current, **entry}
            version = current.get("version")
            if isinstance(version, str) and version:
                out.append(VersionRecord(
                    version=version,
                    published_at=_parse_dt(current.get("time")),
                    is_default=(i == 0),
                    deprecated=bool(current.get("abandoned")),
                ))
        return out

    async def fetch_npm_version_meta(self, name: str, version: str) -> dict[str, Any] | None:
        """Publisher account name and maintainer names of one npm version."""
        url = f"https://registry.npmjs.org/{quote(name, safe='@/')}/{quote(version, safe='')}"
        data = await self._get_json(url, self._registry_limiter, {"package": name, "version": version})
        if not isinstance(data, dict):
            return None
        user = data.get("_npmUser")
        publisher = user.get("name") if isinstance(user, dict) and isinstance(user.get("name"), str) else None
        maintainers = sorted({
            m["name"] for m in (data.get("maintainers") or [])
            if isinstance(m, dict) and isinstance(m.get("name"), str)
        })
        return {"publisher": publisher, "maintainers": maintainers}


def _pick(records: list[VersionRecord], version: str) -> VersionRecord | None:
    by_version = {r.version: r for r in records}
    for variant in _version_variants(version):
        if variant in by_version:
            return by_version[variant]
    lowered = {r.version.lower(): r for r in records}
    for variant in _version_variants(version):
        if variant.lower() in lowered:
            return lowered[variant.lower()]
    return None


def _latest(records: list[VersionRecord]) -> VersionRecord | None:
    defaults = [r for r in records if r.is_default]
    if defaults:
        return defaults[0]
    dated = [r for r in records if r.published_at]
    return max(dated, key=lambda r: r.published_at) if dated else None  # type: ignore[arg-type,return-value]


class SupplyChainService:
    def __init__(self, cache_repo: Any, client: ReleaseInfoClient | None = None) -> None:
        self.cache_repo = cache_repo
        self.client = client or ReleaseInfoClient()
        self._semaphore = asyncio.Semaphore(max(1, settings.sca_release_info_concurrency))

    async def close(self) -> None:
        await self.client.close()

    async def get_release_info(self, ecosystem: str, name: str, version: str) -> ReleaseInfo | None:
        infos = await self.get_many({(ecosystem, normalize_package_name(ecosystem, name), version)})
        return next(iter(infos.values()), None)

    async def get_many(self, keys: set[tuple[str, str, str]]) -> dict[tuple[str, str, str], ReleaseInfo]:
        """Release info per (ecosystem, name, version), from the cache or the registries."""
        keys = {k for k in keys if k[0] in SUPPORTED_ECOSYSTEMS and k[1]}
        cached = await self.cache_repo.get_many([cache_key(*k) for k in keys])
        out: dict[tuple[str, str, str], ReleaseInfo] = {}
        missing: dict[tuple[str, str], set[str]] = {}
        for key in keys:
            doc = cached.get(cache_key(*key))
            if doc is not None:
                out[key] = ReleaseInfo.from_doc(doc)
            else:
                missing.setdefault((key[0], key[1]), set()).add(key[2])

        async def _one(ecosystem: str, name: str, versions: set[str]) -> dict[str, ReleaseInfo]:
            async with self._semaphore:
                try:
                    return await self._lookup_package(ecosystem, name, versions)
                except Exception:  # noqa: BLE001 - one package never fails the batch
                    log.warning("supply_chain.lookup_failed", ecosystem=ecosystem, package=name, exc_info=True)
                    return {}

        results = await asyncio.gather(*[_one(e, n, v) for (e, n), v in missing.items()])
        found: dict[str, dict[str, Any]] = {}
        unknown: dict[str, dict[str, Any]] = {}
        mutable: dict[str, dict[str, Any]] = {}
        for (ecosystem, name), per_version in zip(missing.keys(), results):
            for version, info in per_version.items():
                out[(ecosystem, name, version)] = info
                key = cache_key(ecosystem, name, version)
                if not info.package_found:
                    unknown[key] = info.to_doc()
                elif not version or not info.version_found:
                    mutable[key] = info.to_doc()
                else:
                    found[key] = info.to_doc()
        ttl = settings.sca_release_info_cache_ttl_hours
        await self.cache_repo.put_many(found, ttl)
        # "Which version is latest" and "this version does not exist yet" turn
        # false on the next publish, the moment a takeover release is worth
        # catching; held for a day they hid it from the check and the scan.
        await self.cache_repo.put_many(mutable, min(ttl, _MUTABLE_TTL_HOURS))
        # A private package or a failed request: ask again sooner.
        await self.cache_repo.put_many(unknown, min(ttl, _UNKNOWN_TTL_HOURS))
        return out

    async def _lookup_package(self, ecosystem: str, name: str, versions: set[str]) -> dict[str, ReleaseInfo]:
        records = await self.client.fetch_versions(ecosystem, name)
        if records is None:
            # Unknown package (private, typo) or a failed request.
            return {v: ReleaseInfo(ecosystem=ecosystem, name=name, version=v) for v in versions}
        latest = _latest(records)
        dated = [r.published_at for r in records if r.published_at]
        last_release = max(dated) if dated else None
        out: dict[str, ReleaseInfo] = {}
        for version in versions:
            # An empty version asks for the latest release (an unpinned install).
            record = _pick(records, version) if version else latest
            info = ReleaseInfo(
                ecosystem=ecosystem, name=name, version=version or (record.version if record else ""),
                package_found=True,
                version_found=record is not None,
                published_at=record.published_at if record else None,
                latest_version=latest.version if latest else None,
                latest_published_at=latest.published_at if latest else None,
                last_release_at=last_release,
                deprecated=record.deprecated if record else None,
            )
            if ecosystem == "npm" and record and record.published_at:
                age = info.age_days() or 0
                if age <= settings.sca_publisher_check_max_age_days:
                    await self._check_npm_publisher(info, record, records)
            out[version] = info
        return out

    async def _npm_meta(self, name: str, version: str) -> dict[str, Any] | None:
        key = f"npm-meta|{name}|{version}"
        cached = await self.cache_repo.get_many([key])
        if key in cached:
            return cached[key].get("meta")
        meta = await self.client.fetch_npm_version_meta(name, version)
        if meta is not None:
            await self.cache_repo.put_many({key: {"meta": meta}}, _NPM_META_TTL_HOURS)
        return meta

    async def _check_npm_publisher(
        self, info: ReleaseInfo, record: VersionRecord, records: list[VersionRecord]
    ) -> None:
        earlier = sorted(
            (r for r in records if r.published_at and record.published_at and r.published_at < record.published_at),
            key=lambda r: r.published_at,  # type: ignore[arg-type,return-value]
            reverse=True,
        )[: max(1, settings.sca_publisher_history)]
        installed = await self._npm_meta(info.name, record.version)
        if installed is None:
            return
        previous = [await self._npm_meta(info.name, r.version) for r in earlier]
        info.publisher, info.previous_publishers, info.new_maintainers = detect_publisher_change(installed, previous)
        info.publisher_checked = True


# --- SBOM enrichment after a scan ---------------------------------------------

def component_fields(info: ReleaseInfo, now: datetime | None = None) -> dict[str, Any]:
    flags = info.flags(now)
    return {
        "published_at": info.published_at,
        "latest_version": info.latest_version,
        "latest_published_at": info.latest_published_at,
        "publisher": info.publisher,
        "previous_publishers": info.previous_publishers or None,
        "new_maintainers": info.new_maintainers or None,
        **flags,
    }


def summarize(fields_by_component: list[dict[str, Any]], checked: int) -> dict[str, Any]:
    return {
        "checked": checked,
        "fresh_release": sum(1 for f in fields_by_component if f.get("fresh_release")),
        "unmaintained": sum(1 for f in fields_by_component if f.get("unmaintained")),
        "publisher_changed": sum(1 for f in fields_by_component if f.get("publisher_changed")),
    }


async def enrich_scan_components(service: SupplyChainService, sbom_collection: Any, scan_id: str) -> dict[str, Any]:
    """Look up every registry component of a scan and store the signals on its rows."""
    from pymongo import UpdateMany

    groups: dict[tuple[str, str], tuple[str, str, str]] = {}
    async for row in sbom_collection.find({"scan_id": scan_id}, {"name": 1, "version": 1, "purl": 1}):
        name, version = row.get("name") or "", row.get("version") or ""
        if (name, version) in groups:
            continue
        parsed = package_from_purl(row.get("purl"))
        if not parsed:
            continue
        ecosystem, pkg, purl_version = parsed
        groups[(name, version)] = (ecosystem, pkg, version or purl_version)
        if len(groups) >= settings.sca_release_info_max_components:
            break
    keys = {k for k in groups.values() if k[2]}
    infos = await service.get_many(keys)
    now = datetime.now(UTC)
    ops = []
    stored: list[dict[str, Any]] = []
    for (name, version), key in groups.items():
        info = infos.get(key)
        if info is None or not info.version_found:
            continue
        fields = component_fields(info, now)
        stored.append(fields)
        ops.append(UpdateMany({"scan_id": scan_id, "name": name, "version": version}, {"$set": fields}))
    if ops:
        await sbom_collection.bulk_write(ops, ordered=False)
    return summarize(stored, checked=len(stored))


async def run_scan_enrichment(scan_id: str, sbom_collection: Any, scan_repo: Any) -> dict[str, Any]:
    """Background job after a scan or SBOM import; records its outcome on the scan.

    ``supply_chain_summary`` on the scan: ``{state: running|done|failed,
    checked, fresh_release, unmaintained, publisher_changed, finished_at}``.
    """
    from app.repositories.package_release_repository import PackageReleaseRepository

    await scan_repo.update_fields(scan_id, {"supply_chain_summary": {"state": "running"}})
    service: SupplyChainService | None = None
    summary: dict[str, Any]
    try:
        service = SupplyChainService(await PackageReleaseRepository.create())
        result = await asyncio.wait_for(
            enrich_scan_components(service, sbom_collection, scan_id),
            timeout=settings.sca_release_info_timeout_seconds,
        )
        summary = {"state": "done", **result}
    except Exception as exc:  # noqa: BLE001 - signals are best effort
        log.warning("supply_chain.scan_enrichment_failed", scan_id=scan_id, error=str(exc) or type(exc).__name__)
        summary = {"state": "failed"}
    finally:
        if service is not None:
            await service.close()
    summary["finished_at"] = datetime.now(UTC)
    await scan_repo.update_fields(scan_id, {"supply_chain_summary": summary})
    log.info("supply_chain.scan_enriched", scan_id=scan_id, **{k: v for k, v in summary.items() if k != "finished_at"})
    return summary


_shared_service: SupplyChainService | None = None
_shared_lock = asyncio.Lock()


async def get_supply_chain_service() -> SupplyChainService:
    """Process-wide instance for the package check (REST + MCP): one HTTP client, one rate limit."""
    global _shared_service
    if _shared_service is None:
        async with _shared_lock:
            if _shared_service is None:
                from app.repositories.package_release_repository import PackageReleaseRepository

                _shared_service = SupplyChainService(await PackageReleaseRepository.create())
    return _shared_service
