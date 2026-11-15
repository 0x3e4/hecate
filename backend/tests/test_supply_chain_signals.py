"""Release age, unmaintained and npm publisher change on SBOM components."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.core.config import settings
from app.services import supply_chain_service as sc
from app.services.sbom_export import supply_chain_properties
from app.services.supply_chain_service import (
    ReleaseInfo,
    SupplyChainService,
    VersionRecord,
    detect_publisher_change,
    enrich_scan_components,
    package_from_purl,
)

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


def days_ago(n: float) -> datetime:
    return datetime.now(UTC) - timedelta(days=n)


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:npm/left-pad@1.3.0", ("npm", "left-pad", "1.3.0")),
        ("pkg:npm/%40babel/core@7.0.0", ("npm", "@babel/core", "7.0.0")),
        ("pkg:pypi/Django_Rest@3.1?arch=x", ("pypi", "django-rest", "3.1")),
        ("pkg:golang/golang.org/x/text@v0.3.0", ("go", "golang.org/x/text", "v0.3.0")),
        ("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", ("maven", "org.apache.logging.log4j:log4j-core", "2.14.1")),
        ("pkg:gem/rack@3.0.0", ("rubygems", "rack", "3.0.0")),
        ("pkg:composer/monolog/monolog@3.0.0", ("packagist", "monolog/monolog", "3.0.0")),
        ("pkg:deb/debian/openssl@3.0", None),
        ("pkg:maven/log4j-core@1", None),
        ("not-a-purl", None),
        (None, None),
    ],
)
def test_package_from_purl(purl: str | None, expected: tuple[str, str, str] | None) -> None:
    assert package_from_purl(purl) == expected


def test_flag_thresholds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sca_fresh_release_days", 7)
    monkeypatch.setattr(settings, "sca_unmaintained_days", 730)
    info = ReleaseInfo("npm", "a", "1", package_found=True, version_found=True,
                       published_at=NOW - timedelta(days=6), latest_published_at=NOW - timedelta(days=6))
    assert info.flags(NOW) == {"fresh_release": True, "unmaintained": False, "publisher_changed": None}
    info.published_at = NOW - timedelta(days=8)
    info.latest_published_at = NOW - timedelta(days=731)
    assert info.flags(NOW)["fresh_release"] is False
    assert info.flags(NOW)["unmaintained"] is True
    assert ReleaseInfo("npm", "a", "1").flags(NOW) == {"fresh_release": None, "unmaintained": None, "publisher_changed": None}
    # An old default version (a stale pre-release) doesn't make a package with recent releases unmaintained.
    info.last_release_at = NOW - timedelta(days=30)
    assert info.flags(NOW)["unmaintained"] is False


def test_publisher_change_detection() -> None:
    installed = {"publisher": "attacker", "maintainers": ["alice", "attacker"]}
    previous = [{"publisher": "alice", "maintainers": ["alice"]}, {"publisher": "bob", "maintainers": ["alice", "bob"]}]
    assert detect_publisher_change(installed, previous) == ("attacker", ["alice", "bob"], ["attacker"])
    same = {"publisher": "alice", "maintainers": ["alice"]}
    assert detect_publisher_change(same, previous)[0] == "alice"
    assert detect_publisher_change(None, previous) == (None, ["alice", "bob"], [])

    info = ReleaseInfo("npm", "a", "1", publisher="attacker", previous_publishers=["alice"], publisher_checked=True)
    assert info.flags()["publisher_changed"] is True
    info.publisher = "alice"
    assert info.flags()["publisher_changed"] is False
    info.previous_publishers = []
    assert info.flags()["publisher_changed"] is None


class FakeCache:
    def __init__(self, docs: dict[str, dict[str, Any]] | None = None) -> None:
        self.docs = dict(docs or {})
        self.ttls: dict[str, float] = {}

    async def get_many(self, keys: list[str]) -> dict[str, dict[str, Any]]:
        return {k: self.docs[k] for k in keys if k in self.docs}

    async def put_many(self, docs: dict[str, dict[str, Any]], ttl_hours: float) -> None:
        for key, doc in docs.items():
            self.docs[key] = doc
            self.ttls[key] = ttl_hours


class FakeClient:
    def __init__(self, versions: dict[tuple[str, str], list[VersionRecord] | None],
                 npm_meta: dict[tuple[str, str], dict[str, Any]] | None = None, fail: bool = False) -> None:
        self.versions = versions
        self.npm_meta = npm_meta or {}
        self.fail = fail
        self.calls: list[tuple[str, ...]] = []

    async def fetch_versions(self, ecosystem: str, name: str) -> list[VersionRecord] | None:
        self.calls.append(("versions", ecosystem, name))
        if self.fail:
            raise RuntimeError("boom")
        return self.versions.get((ecosystem, name))

    async def fetch_npm_version_meta(self, name: str, version: str) -> dict[str, Any] | None:
        self.calls.append(("npm", name, version))
        return self.npm_meta.get((name, version))

    async def close(self) -> None:
        pass


def _records() -> list[VersionRecord]:
    return [
        VersionRecord("1.0.0", days_ago(400)),
        VersionRecord("1.1.0", days_ago(200)),
        VersionRecord("1.2.0", days_ago(100)),
        VersionRecord("1.3.0", days_ago(2), is_default=True),
    ]


async def test_one_request_per_package_and_cache_hits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sca_publisher_check_max_age_days", 0)
    cache = FakeCache()
    client = FakeClient({("pypi", "requests"): _records()})
    service = SupplyChainService(cache, client)  # type: ignore[arg-type]
    infos = await service.get_many({("pypi", "requests", "1.1.0"), ("pypi", "requests", "1.3.0")})
    assert client.calls == [("versions", "pypi", "requests")]
    assert infos[("pypi", "requests", "1.3.0")].flags()["fresh_release"] is True
    assert infos[("pypi", "requests", "1.1.0")].latest_version == "1.3.0"
    assert infos[("pypi", "requests", "1.1.0")].flags()["fresh_release"] is False

    client.calls.clear()
    again = await service.get_many({("pypi", "requests", "1.1.0")})
    assert client.calls == []
    assert again[("pypi", "requests", "1.1.0")].published_at is not None


async def test_unknown_package_is_cached_briefly_and_failures_are_soft(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sca_release_info_cache_ttl_hours", 24)
    cache = FakeCache()
    service = SupplyChainService(cache, FakeClient({}))  # type: ignore[arg-type]
    infos = await service.get_many({("npm", "no-such-pkg-xyz", "1.0.0")})
    info = infos[("npm", "no-such-pkg-xyz", "1.0.0")]
    assert info.package_found is False
    assert cache.ttls["npm|no-such-pkg-xyz|1.0.0"] == 6

    broken = SupplyChainService(FakeCache(), FakeClient({}, fail=True))  # type: ignore[arg-type]
    assert await broken.get_many({("npm", "a", "1")}) == {}


async def test_answers_that_change_on_the_next_publish_are_cached_briefly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sca_release_info_cache_ttl_hours", 24)
    monkeypatch.setattr(settings, "sca_publisher_check_max_age_days", 0)
    cache = FakeCache()
    service = SupplyChainService(cache, FakeClient({("pypi", "requests"): _records()}))  # type: ignore[arg-type]
    await service.get_many({("pypi", "requests", ""), ("pypi", "requests", "9.9.9"), ("pypi", "requests", "1.1.0")})
    # A pinned, published version is fixed data.
    assert cache.ttls["pypi|requests|1.1.0"] == 24
    # "Latest" and "not published yet" were held for a day and hid a takeover release.
    assert cache.ttls["pypi|requests|"] <= 0.25
    assert cache.ttls["pypi|requests|9.9.9"] <= 0.25


async def test_empty_version_resolves_to_latest() -> None:
    service = SupplyChainService(FakeCache(), FakeClient({("pypi", "requests"): _records()}))  # type: ignore[arg-type]
    info = await service.get_release_info("pypi", "Requests", "")
    assert info is not None and info.version == "1.3.0" and info.version_found


async def test_npm_publisher_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sca_publisher_check_max_age_days", 365)
    monkeypatch.setattr(settings, "sca_publisher_history", 2)
    meta = {
        ("lib", "1.3.0"): {"publisher": "mallory", "maintainers": ["alice", "mallory"]},
        ("lib", "1.2.0"): {"publisher": "alice", "maintainers": ["alice"]},
        ("lib", "1.1.0"): {"publisher": "alice", "maintainers": ["alice"]},
    }
    client = FakeClient({("npm", "lib"): _records()}, meta)
    service = SupplyChainService(FakeCache(), client)  # type: ignore[arg-type]
    info = await service.get_release_info("npm", "lib", "1.3.0")
    assert info is not None
    assert info.publisher == "mallory"
    assert info.previous_publishers == ["alice"]
    assert info.new_maintainers == ["mallory"]
    assert info.flags()["publisher_changed"] is True
    # Only the two versions before 1.3.0 were asked for, never 1.0.0.
    assert ("npm", "lib", "1.0.0") not in client.calls

    # An old version is not checked (takeovers publish new versions).
    old = await service.get_release_info("npm", "lib", "1.0.0")
    assert old is not None and old.publisher_checked is False


class FakeSbomCollection:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.ops: list[Any] = []

    def find(self, query: dict[str, Any], projection: dict[str, Any] | None = None):
        rows = [r for r in self.rows if r["scan_id"] == query["scan_id"]]

        async def _gen():
            for r in rows:
                yield r

        return _gen()

    async def bulk_write(self, ops: list[Any], ordered: bool = False) -> None:
        self.ops.extend(ops)


async def test_enrich_scan_components_writes_signals(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sca_publisher_check_max_age_days", 0)
    rows = [
        {"scan_id": "s", "name": "requests", "version": "1.3.0", "purl": "pkg:pypi/requests@1.3.0"},
        {"scan_id": "s", "name": "requests", "version": "1.3.0", "purl": "pkg:pypi/requests@1.3.0"},
        {"scan_id": "s", "name": "openssl", "version": "3.0", "purl": "pkg:deb/debian/openssl@3.0"},
        {"scan_id": "s", "name": "ghost", "version": "9.9.9", "purl": "pkg:pypi/requests@9.9.9"},
    ]
    collection = FakeSbomCollection(rows)
    service = SupplyChainService(FakeCache(), FakeClient({("pypi", "requests"): _records()}))  # type: ignore[arg-type]
    summary = await enrich_scan_components(service, collection, "s")
    assert summary == {"checked": 1, "fresh_release": 1, "unmaintained": 0, "publisher_changed": 0}
    (op,) = collection.ops
    assert op._filter == {"scan_id": "s", "name": "requests", "version": "1.3.0"}
    fields = op._doc["$set"]
    assert fields["fresh_release"] is True and fields["latest_version"] == "1.3.0"


def test_cyclonedx_properties() -> None:
    props = supply_chain_properties({
        "published_at": datetime(2026, 11, 10, tzinfo=UTC), "latest_version": "2.0.0",
        "fresh_release": True, "unmaintained": False, "publisher": "alice", "publisher_changed": None,
    })
    assert {"name": "hecate:release:publishedAt", "value": "2026-11-10T00:00:00Z"} in props
    assert {"name": "hecate:release:fresh", "value": "true"} in props
    assert {"name": "hecate:release:unmaintained", "value": "false"} in props
    assert not any(p["name"] == "hecate:npm:publisherChanged" for p in props)
    assert supply_chain_properties({}) == []


def test_module_exports_cover_registries() -> None:
    assert sc.SUPPORTED_ECOSYSTEMS >= {"npm", "pypi", "go", "maven", "cargo", "nuget", "rubygems", "packagist"}
    assert sc.canonical_ecosystem("PIP") == "pypi" and sc.canonical_ecosystem("crates.io") == "cargo"
    assert sc.canonical_ecosystem("apt") is None
