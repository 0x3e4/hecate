"""Merging CERT advisories into topics, and the overview built from them."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pymongo.errors import PyMongoError

from app.services import stats_service
from app.repositories.cert_advisory_repository import feed_kind
from app.services.cert_topics import COMMUNITY_TOPIC_MAX_CVES, ROUNDUP_MIN_CVES, group_advisories
from app.services.stats_service import StatsService

NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)


def advisory(key: str, feed: str, cves: list[str], *, age: int = 1, kind: str = "cert") -> dict:
    return {
        "_id": f"{feed}:{key}",
        "feed": feed,
        "kind": kind,
        "title": f"{feed} {key}",
        "url": f"https://{feed}.example/{key}",
        "published": NOW - timedelta(days=age),
        "cve_ids": cves,
    }


def post(key: str, account: str, cves: list[str], *, age: int = 1) -> dict:
    return advisory(key, account, cves, age=age, kind="community")


def roundup(key: str, shared: str | None = None) -> dict:
    cves = [f"CVE-2026-{n}" for n in range(1000, 1000 + ROUNDUP_MIN_CVES)]
    return advisory(key, "CERT-FR", [*cves, *([shared] if shared else [])])


def test_advisories_sharing_a_cve_merge_across_certs():
    topics, _ = group_advisories([
        advisory("a", "CERT-FR", ["CVE-2026-1"]),
        advisory("b", "CCCS", ["CVE-2026-1"]),
        advisory("c", "NCSC-NL", ["CVE-2026-2"]),
    ])

    assert len(topics) == 2
    merged = next(t for t in topics if len(t["advisories"]) == 2)
    assert merged["cve_ids"] == ["CVE-2026-1"]


def test_merging_follows_a_chain_of_shared_cves():
    topics, _ = group_advisories([
        advisory("a", "CERT-FR", ["CVE-2026-1"]),
        advisory("b", "CCCS", ["CVE-2026-1", "CVE-2026-2"]),
        advisory("c", "JPCERT/CC", ["CVE-2026-2"]),
    ])

    assert len(topics) == 1
    assert topics[0]["cve_ids"] == ["CVE-2026-1", "CVE-2026-2"]


def test_a_roundup_does_not_tie_topics_together():
    topics, roundups = group_advisories([
        advisory("a", "CCCS", ["CVE-2026-1"]),
        advisory("b", "NCSC-NL", ["CVE-2026-2"]),
        roundup("kernel", shared="CVE-2026-1"),
        roundup("mozilla", shared="CVE-2026-2"),
    ])

    assert len(topics) == 2
    assert len(roundups) == 2


def test_an_advisory_just_below_the_limit_is_still_a_topic():
    cves = [f"CVE-2026-{n}" for n in range(ROUNDUP_MIN_CVES - 1)]

    topics, roundups = group_advisories([advisory("a", "CERT-FR", cves)])

    assert len(topics) == 1
    assert roundups == []


def test_newest_topics_come_first():
    topics, _ = group_advisories([
        advisory("old", "CERT-FR", ["CVE-2026-1"], age=9),
        advisory("new", "CCCS", ["CVE-2026-2"], age=1),
    ])

    assert [t["advisories"][0]["title"] for t in topics] == ["CCCS new", "CERT-FR old"]


def test_a_topics_id_stays_when_a_later_advisory_joins():
    first, _ = group_advisories([advisory("a", "CERT-FR", ["CVE-2026-1"])])
    second, _ = group_advisories([
        advisory("z", "NCSC-NL", ["CVE-2026-1"]),
        advisory("a", "CERT-FR", ["CVE-2026-1"]),
    ])

    assert first[0]["id"] == second[0]["id"]


def test_a_community_post_naming_two_flaws_does_not_merge_them():
    topics, _ = group_advisories([
        advisory("a", "CERT-FR", ["CVE-2026-1"]),
        advisory("b", "CCCS", ["CVE-2026-2"]),
        post("p", "@analyst", ["CVE-2026-1", "CVE-2026-2"]),
    ])

    assert len(topics) == 2
    assert all(any(a["kind"] == "community" for a in t["advisories"]) for t in topics)
    assert [t["cve_ids"] for t in sorted(topics, key=lambda t: t["cve_ids"])] == [["CVE-2026-1"], ["CVE-2026-2"]]


def test_a_post_joining_a_topic_adds_none_of_its_other_cves():
    topics, _ = group_advisories([
        advisory("a", "CERT-FR", ["CVE-2026-1"]),
        post("p", "@analyst", ["CVE-2026-1", "CVE-2026-7"]),
    ])

    [topic] = topics
    assert topic["cve_ids"] == ["CVE-2026-1"]
    assert len(topic["advisories"]) == 2


def test_posts_that_touch_no_topic_group_among_themselves():
    topics, _ = group_advisories([
        post("p", "@one", ["CVE-2026-5"]),
        post("q", "@two", ["CVE-2026-5"]),
        advisory("a", "CERT-FR", ["CVE-2026-1"]),
    ])

    assert sorted(len(t["advisories"]) for t in topics) == [1, 2]


def test_a_post_listing_many_cves_is_a_roundup():
    cves = [f"CVE-2026-{n}" for n in range(COMMUNITY_TOPIC_MAX_CVES + 1)]

    topics, roundups = group_advisories([advisory("a", "CERT-FR", [cves[0]]), post("p", "@list", cves)])

    assert len(topics) == 1
    assert len(topics[0]["advisories"]) == 1
    assert [r["feed"] for r in roundups] == ["@list"]


def test_a_post_does_not_change_the_id_of_the_topic_it_joins():
    alone, _ = group_advisories([advisory("z", "CERT-FR", ["CVE-2026-1"])])
    joined, _ = group_advisories([advisory("z", "CERT-FR", ["CVE-2026-1"]), post("a", "@first", ["CVE-2026-1"])])

    assert alone[0]["id"] == joined[0]["id"]


def test_the_configured_kind_wins_over_the_stored_one():
    document = {"feed": "Cloudflare", "kind": "cert"}

    assert feed_kind(document, {"Cloudflare": "vendor"}) == "vendor"
    assert feed_kind(document, {}) == "cert"
    assert feed_kind({"feed": "Old"}, None) == "cert"


class _Repository:
    def __init__(self, advisories=(), error=None):
        self.advisories = list(advisories)
        self.error = error

    async def list_since(self, _since, kinds=None):
        if self.error:
            raise self.error
        return [{**a, "kind": feed_kind(a, kinds)} for a in self.advisories]


class _Inventory:
    async def list_all_cached(self):
        return []


class _Assets:
    async def find_vendors_by_slugs(self, slugs):
        return [{"_id": slug, "displayName": slug.title()} for slug in slugs]

    async def find_products_by_slugs(self, slugs):
        return [{"_id": slug, "displayName": slug.upper()} for slug in slugs]


def _wire(monkeypatch, repository, hits=()):
    bodies: list[dict] = []

    async def search(_index, body, **_kwargs):
        bodies.append(body)
        return {"hits": {"hits": [{"_source": h} for h in hits], "total": {"value": len(hits)}}}

    async def create_repository():
        return repository

    async def get_inventory():
        return _Inventory()

    async def create_assets():
        return _Assets()

    async def kinds():
        return {}

    monkeypatch.setattr(stats_service, "async_search", search)
    monkeypatch.setattr(stats_service.CertAdvisoryRepository, "create", staticmethod(create_repository))
    monkeypatch.setattr(stats_service, "get_inventory_service", get_inventory)
    monkeypatch.setattr(stats_service.AssetRepository, "create", staticmethod(create_assets))
    monkeypatch.setattr(stats_service, "feed_kinds", kinds)
    return bodies


DOC = {
    "vuln_id": "CVE-2026-1",
    "title": "Heap overflow",
    "cvss": {"severity": "HIGH", "base_score": 8.1},
    "exploited": True,
    "vendorSlugs": ["acme"],
    "productSlugs": ["widget"],
}


async def test_overview_describes_a_topic_from_hecates_own_data(monkeypatch):
    _wire(
        monkeypatch,
        _Repository([advisory("a", "CERT-FR", ["CVE-2026-1"]), advisory("b", "CCCS", ["CVE-2026-1"], age=3)]),
        hits=[DOC],
    )

    result = await StatsService().get_cert_overview(days=30)

    [topic] = result["topics"]
    assert topic["sources"] == [{"name": "CERT-FR", "kind": "cert"}, {"name": "CCCS", "kind": "cert"}]
    assert {a["kind"] for a in topic["advisories"]} == {"cert"}
    assert topic["worstSeverity"] == "high"
    assert topic["firstSeen"] < topic["lastSeen"]
    [row] = topic["cves"]
    assert row["known"] is True
    assert row["exploited"] is True
    assert row["products"] == [{"slug": "widget", "name": "WIDGET"}]


async def test_overview_keeps_a_cve_hecate_does_not_know(monkeypatch):
    _wire(monkeypatch, _Repository([advisory("a", "CERT-FR", ["CVE-2026-404"])]))

    result = await StatsService().get_cert_overview()

    [row] = result["topics"][0]["cves"]
    assert row == {**row, "vulnId": "CVE-2026-404", "severity": "unknown", "known": False}
    assert result["topics"][0]["worstSeverity"] == "unknown"


async def test_overview_finds_a_cve_stored_under_another_id(monkeypatch):
    doc = {**DOC, "vuln_id": "MAL-2026-1", "aliases": ["cve-2026-1"]}
    _wire(monkeypatch, _Repository([advisory("a", "CERT-FR", ["CVE-2026-1"])]), hits=[doc])

    result = await StatsService().get_cert_overview()

    assert [row["vulnId"] for row in result["topics"][0]["cves"]] == ["MAL-2026-1"]


async def test_overview_lists_roundups_without_loading_their_cves(monkeypatch):
    bodies = _wire(monkeypatch, _Repository([roundup("kernel")]))

    result = await StatsService().get_cert_overview()

    assert result["topics"] == []
    assert len(result["roundups"][0]["cveIds"]) == ROUNDUP_MIN_CVES
    assert bodies == []


async def test_overview_is_empty_when_mongodb_fails(monkeypatch):
    _wire(monkeypatch, _Repository(error=PyMongoError("down")))

    result = await StatsService().get_cert_overview()

    assert result["topics"] == []
    assert result["roundups"] == []
