"""Pre-install package check: verdicts, REST endpoint and MCP tool."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import packages as packages_api
from app.core.config import settings
from app.services.package_check_service import (
    PackageCheckError,
    check_package,
    evaluate_package,
    package_purl,
    validate_input,
)
from app.services.supply_chain_service import ReleaseInfo

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


def entry(vendor: str, product: str, versions: list[str], **extra: Any) -> dict[str, Any]:
    return {"vendor": {"name": vendor, "slug": vendor.lower()}, "product": {"name": product, "slug": product},
            "versions": versions, **extra}


def doc(doc_id: str, entries: list[dict[str, Any]], *, severity: str = "high", kev: bool = False,
        aliases: list[str] | None = None) -> dict[str, Any]:
    return {
        "_id": doc_id, "aliases": aliases or [], "title": f"{doc_id} title", "summary": "s",
        "cvss": {"severity": severity, "base_score": 7.5}, "epss_score": 0.1,
        "exploitation": {"dateAdded": "2026-01-01"} if kev else None,
        "impactedProducts": entries,
    }


def release(**kw: Any) -> ReleaseInfo:
    base = dict(ecosystem="npm", name="lib", version="1.2.0", package_found=True, version_found=True,
                published_at=NOW - timedelta(days=90), latest_version="1.3.0",
                latest_published_at=NOW - timedelta(days=30))
    base.update(kw)
    return ReleaseInfo(**base)


def codes(result: dict[str, Any]) -> set[str]:
    return {r["code"] for r in result["reasons"]}


def test_ok_when_nothing_matches() -> None:
    result = evaluate_package("npm", "lib", "1.2.0", [], release(), now=NOW)
    assert result["verdict"] == "ok"
    assert result["reasons"] == []
    assert result["release"]["latestVersion"] == "1.3.0"


def test_whole_package_malware_blocks() -> None:
    mal = doc("MAL-2026-1", [entry("npm", "lib", [">=0"])])
    result = evaluate_package("npm", "lib", "1.2.0", [mal], release(), now=NOW)
    assert result["verdict"] == "block"
    assert result["malicious"][0]["wholePackage"] is True
    assert "malicious" in codes(result)


def test_compromised_versions_block_only_the_covered_version() -> None:
    mal = doc("GHSA-xxxx", [entry("npm", "lib", ["1.2.1", "1.2.2"])], aliases=["MAL-2026-2"])
    hit = evaluate_package("npm", "lib", "1.2.1", [mal], release(version="1.2.1"), now=NOW)
    assert hit["verdict"] == "block"
    clean = evaluate_package("npm", "lib", "1.2.0", [mal], release(), now=NOW)
    assert clean["verdict"] == "ok"
    assert clean["malicious"][0]["coversVersion"] is False
    no_version = evaluate_package("npm", "lib", None, [mal], None, now=NOW)
    assert no_version["verdict"] == "warn" and "malicious_versions" in codes(no_version)


def test_registry_vendor_rule_ignores_other_ecosystems() -> None:
    netscaler = doc("CVE-2026-120869", [entry("Citrix", "console", ["< 14.1-74.34"])], severity="critical")
    pypi_mal = doc("MAL-2026-3", [entry("PyPI", "console", [">=0"])])
    result = evaluate_package("npm", "console", "0.15.11", [netscaler, pypi_mal], None, now=NOW)
    assert result["verdict"] == "ok"
    assert result["advisoriesForPackage"] == 0


def test_kev_and_critical_block_others_warn_with_recommendation() -> None:
    kev = doc("CVE-1", [entry("npm", "lib", [">= 1.0.0, < 1.2.5"], patchedVersions=["1.2.5"])], kev=True)
    medium = doc("CVE-2", [entry("npm", "lib", ["< 1.4.0"], patchedVersions=["1.4.0"])], severity="medium")
    result = evaluate_package("npm", "lib", "1.2.0", [kev, medium], release(), now=NOW)
    assert result["verdict"] == "block"
    assert codes(result) >= {"kev", "vulnerable"}
    assert [v["id"] for v in result["vulnerabilities"]] == ["CVE-1", "CVE-2"]
    assert result["vulnerabilities"][0]["kev"] is True
    # 1.2.5 still carries CVE-2, 1.3.0 (latest) too; 1.4.0 is the first clean fix.
    assert result["recommendedVersion"] == "1.4.0"

    only_medium = evaluate_package("npm", "lib", "1.2.0", [medium], release(), now=NOW)
    assert only_medium["verdict"] == "warn"


def test_fresh_release_warns_unless_it_is_the_fix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sca_fresh_release_days", 7)
    fresh = release(version="1.3.0", published_at=NOW - timedelta(days=1))
    result = evaluate_package("npm", "lib", "1.3.0", [], fresh, now=NOW)
    assert result["verdict"] == "warn" and "fresh_release" in codes(result)

    fix = doc("CVE-3", [entry("npm", "lib", ["< 1.3.0"], patchedVersions=["1.3.0"])])
    waived = evaluate_package("npm", "lib", "1.3.0", [fix], fresh, now=NOW)
    assert waived["verdict"] == "ok"
    assert "fresh_release_fix" in codes(waived)


def test_publisher_change_unmaintained_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sca_unmaintained_days", 730)
    taken_over = release(publisher="mallory", previous_publishers=["alice"], publisher_checked=True,
                         new_maintainers=["mallory"])
    result = evaluate_package("npm", "lib", "1.2.0", [], taken_over, now=NOW)
    assert result["verdict"] == "warn"
    assert codes(result) >= {"publisher_changed", "new_maintainers"}

    stale = release(latest_published_at=NOW - timedelta(days=1000), deprecated=True)
    assert codes(evaluate_package("npm", "lib", "1.2.0", [], stale, now=NOW)) >= {"unmaintained", "deprecated"}

    unknown = ReleaseInfo("npm", "reqeusts", "")
    result = evaluate_package("npm", "reqeusts", None, [], unknown, now=NOW)
    assert result["verdict"] == "warn" and "unknown_package" in codes(result)


@pytest.mark.parametrize(
    ("eco", "name", "version"),
    [("apt", "curl", None), ("npm", "", None), ("npm", "a b", None), ("npm", "-rf", None),
     ("npm", "lib", "1.0; rm -rf /"), ("npm", "x" * 400, None)],
)
def test_invalid_input(eco: str, name: str, version: str | None) -> None:
    with pytest.raises(PackageCheckError):
        validate_input(eco, name, version)


def test_input_normalisation_and_purl() -> None:
    assert validate_input("PIP", "Django_Rest", " 3.1 ") == ("pypi", "django-rest", "3.1")
    assert package_purl("npm", "@babel/core", "7.0.0") == "pkg:npm/%40babel/core@7.0.0"
    assert package_purl("maven", "org.apache.logging.log4j:log4j-core") == "pkg:maven/org.apache.logging.log4j/log4j-core"


class FakeCursor:
    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self.docs = docs

    def limit(self, _n: int) -> "FakeCursor":
        return self

    def max_time_ms(self, _ms: int) -> "FakeCursor":
        return self

    def __aiter__(self):
        async def _gen():
            for d in self.docs:
                yield d
        return _gen()


class FakeVulnCollection:
    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self.docs = docs
        self.queries: list[dict[str, Any]] = []

    def find(self, query: dict[str, Any], projection: dict[str, Any] | None = None) -> FakeCursor:
        self.queries.append(query)
        return FakeCursor(self.docs)


class FakeSupplyChain:
    def __init__(self, info: ReleaseInfo | None) -> None:
        self.info = info
        self.asked: list[tuple[str, str, str]] = []

    async def get_release_info(self, ecosystem: str, name: str, version: str) -> ReleaseInfo | None:
        self.asked.append((ecosystem, name, version))
        return self.info


async def test_check_package_uses_latest_when_unpinned() -> None:
    collection = FakeVulnCollection([doc("CVE-9", [entry("npm", "lib", ["< 2.0.0"])], severity="medium")])
    supply = FakeSupplyChain(release(version="1.3.0"))
    result = await check_package("npm", "lib", None, vuln_collection=collection, supply_chain=supply)  # type: ignore[arg-type]
    assert supply.asked == [("npm", "lib", "")]
    assert result["version"] == "1.3.0" and result["versionSource"] == "latest"
    assert result["verdict"] == "warn"
    assert collection.queries == [{"product_slugs": {"$in": ["lib"]}}]


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    collection = FakeVulnCollection([doc("MAL-2026-9", [entry("npm", "evil-pkg", [">=0"])])])

    async def fake_db():
        return {settings.mongo_vulnerabilities_collection: collection}

    async def fake_supply():
        return FakeSupplyChain(release(name="evil-pkg", version="1.0.0"))

    monkeypatch.setattr(packages_api, "get_database", fake_db)
    monkeypatch.setattr(packages_api, "get_supply_chain_service", fake_supply)
    monkeypatch.setattr(packages_api, "_buckets", {})
    app = FastAPI()
    app.include_router(packages_api.router, prefix="/packages")
    return TestClient(app)


def test_rest_endpoint_blocks_malware(client: TestClient) -> None:
    response = client.get("/packages/check", params={"ecosystem": "npm", "name": "evil-pkg"})
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "block"
    assert body["malicious"][0]["id"] == "MAL-2026-9"
    assert body["versionSource"] == "latest"
    assert body["release"]["packageFound"] is True


def test_rest_endpoint_rejects_bad_input(client: TestClient) -> None:
    response = client.get("/packages/check", params={"ecosystem": "apt", "name": "curl"})
    assert response.status_code == 400


def test_anonymous_clients_are_rate_limited(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    # Every uncached check queues on the deps.dev rate limit all users share.
    monkeypatch.setattr(settings, "package_check_rate_per_minute", 3)
    codes = [
        client.get("/packages/check", params={"ecosystem": "npm", "name": f"zz-junk-{i}"}).status_code
        for i in range(5)
    ]
    assert codes == [200, 200, 200, 429, 429]


def test_the_bucket_refills_and_zero_disables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(packages_api, "_buckets", {})
    monkeypatch.setattr(settings, "package_check_rate_per_minute", 60)
    assert all(packages_api._allow("c", now=0.0) for _ in range(60))
    assert packages_api._allow("c", now=0.0) is False
    assert packages_api._allow("c", now=1.0) is True  # one token per second
    monkeypatch.setattr(settings, "package_check_rate_per_minute", 0)
    assert packages_api._allow("c", now=1.0) is True


class SlowSupplyChain(FakeSupplyChain):
    async def get_release_info(self, ecosystem: str, name: str, version: str) -> ReleaseInfo | None:
        import asyncio

        await asyncio.sleep(10)
        return self.info


async def test_a_slow_release_lookup_falls_back_to_advisory_data(monkeypatch: pytest.MonkeyPatch) -> None:
    # A backlog on the shared limiter must not push a check past a hook's
    # 20 s timeout; the verdict then rests on the advisories alone.
    monkeypatch.setattr(settings, "package_check_release_timeout_seconds", 0.05)
    collection = FakeVulnCollection([doc("MAL-2026-9", [entry("npm", "evil-pkg", [">=0"])])])
    result = await check_package(
        "npm", "evil-pkg", "1.0.0", vuln_collection=collection,
        supply_chain=SlowSupplyChain(release(name="evil-pkg", version="1.0.0")),  # type: ignore[arg-type]
    )
    assert result["verdict"] == "block"


async def test_mcp_tool_is_registered_and_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp.server.fastmcp import FastMCP

    from app.db import mongo
    from app.mcp.tools import packages as mcp_packages
    from app.services import supply_chain_service

    collection = FakeVulnCollection([])

    async def fake_db():
        return {settings.mongo_vulnerabilities_collection: collection}

    async def fake_supply():
        return FakeSupplyChain(release())

    monkeypatch.setattr(mongo, "get_database", fake_db)
    monkeypatch.setattr(supply_chain_service, "get_supply_chain_service", fake_supply)
    mcp = FastMCP("test")
    mcp_packages.register(mcp)
    fns = {tool.name: tool.fn for tool in mcp._tool_manager.list_tools()}
    assert "check_package" in fns
    result = await fns["check_package"](ecosystem="npm", name="lib", version="1.2.0")
    assert result["verdict"] == "ok"
    bad = await fns["check_package"](ecosystem="npm", name="bad name")
    assert "error" in bad
