"""CERT advisory feeds: remote XML, links that end up in an href, and how the pipeline spends its requests."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.core.config import settings
from app.services.ingestion import cert_feed_pipeline
from app.services.ingestion.cert_feed_client import (
    CertAdvisoryItem,
    CertFeed,
    CertFeedClient,
    extract_cve_ids,
    parse_feed,
    parse_feed_config,
    safe_url,
)
from app.services.ingestion.cert_feed_pipeline import CertFeedPipeline

RSS = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel>
  <title>A CERT</title>
  <item>
    <title>Critical flaw in PHP</title>
    <link>https://cert.example/advisory/1#top</link>
    <guid>adv-1</guid>
    <pubDate>Fri, 30 Oct 2026 18:32:29 GMT</pubDate>
    <description><![CDATA[<p>See CVE-2026-109618 and cve-2026-109619.</p>]]></description>
    <content:encoded>Also CVE-2026-109618.</content:encoded>
  </item>
</channel></rss>"""

ATOM = b"""<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Linux advisory</title>
    <id>tag:example,2026:1</id>
    <link rel="self" href="https://cert.example/self"/>
    <link rel="alternate" href="https://cert.example/en/1"/>
    <updated>2026-10-30T21:34:05Z</updated>
    <content type="html">&lt;li&gt;CVE-2026-98432&lt;/li&gt;</content>
  </entry>
</feed>"""

RDF = b"""<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel rdf:about="https://cert.example/"><title>A CERT</title></channel>
  <item rdf:about="https://cert.example/wr.html#1">
    <title>Weekly</title>
    <link>https://cert.example/wr.html#1</link>
    <dc:date>2026-10-28T10:00+09:00</dc:date>
  </item>
</rdf:RDF>"""

ENTITY_BOMB = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
<rss><channel><item><guid>1</guid><title>&lol2;</title></item></channel></rss>"""


def test_parses_rss_items():
    [item] = parse_feed(RSS)

    assert item.guid == "adv-1"
    assert item.title == "Critical flaw in PHP"
    assert item.url == "https://cert.example/advisory/1#top"
    assert item.published == datetime(2026, 10, 30, 18, 32, 29, tzinfo=UTC)
    assert item.cve_ids == ["CVE-2026-109618", "CVE-2026-109619"]


def test_parses_atom_and_prefers_the_alternate_link():
    [item] = parse_feed(ATOM)

    assert item.url == "https://cert.example/en/1"
    assert item.cve_ids == ["CVE-2026-98432"]
    assert item.published == datetime(2026, 10, 30, 21, 34, 5, tzinfo=UTC)


def test_parses_rdf_feeds_and_falls_back_to_the_link_as_guid():
    [item] = parse_feed(RDF)

    assert item.guid == "https://cert.example/wr.html#1"
    assert item.cve_ids == []
    assert item.published is not None


def test_refuses_a_dtd():
    with pytest.raises(ValueError, match="DTD"):
        parse_feed(ENTITY_BOMB)


def test_refuses_a_dtd_behind_a_bom_and_a_comment():
    with pytest.raises(ValueError, match="DTD"):
        parse_feed(b"\xef\xbb\xbf<?xml version='1.0'?>\n<!-- note --><!DOCTYPE rss><rss/>")


def test_refuses_a_dtd_behind_a_second_processing_instruction():
    feed = (
        b'<?xml version="1.0"?><?xml-stylesheet href="x"?>'
        b'<!DOCTYPE r [<!ENTITY a "CVE-2099-0001">]><rss><item><guid>g</guid><title>&a;</title></item></rss>'
    )
    with pytest.raises(ValueError, match="DTD"):
        parse_feed(feed)


def test_refuses_a_dtd_in_utf16():
    feed = (
        '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE r [<!ENTITY a "CVE-2099-0002">]>'
        "<rss><item><guid>g</guid><title>&a;</title></item></rss>"
    ).encode("utf-16")
    with pytest.raises(ValueError, match="DTD"):
        parse_feed(feed)


def test_a_feed_that_starts_with_a_comment_is_read():
    feed = b'<?xml version="1.0"?><!-- generated --><rss><channel><item><guid>1</guid><title>CVE-2026-1234</title></item></channel></rss>'

    assert parse_feed(feed)[0].cve_ids == ["CVE-2026-1234"]


def test_a_doctype_in_escaped_content_is_not_a_dtd():
    feed = b"<rss><channel><item><guid>1</guid><description>&lt;!DOCTYPE html&gt; CVE-2026-1234</description></item></channel></rss>"

    assert parse_feed(feed)[0].cve_ids == ["CVE-2026-1234"]


def test_rejects_something_that_is_not_xml():
    with pytest.raises(ValueError, match="valid XML"):
        parse_feed(b"<html><body>Bad gateway")


@pytest.mark.parametrize(
    "link",
    ["javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "//cert.example/x", "https://", " ", None],
)
def test_only_http_links_survive(link):
    assert safe_url(link) is None


def test_a_hostile_item_link_is_dropped_but_the_item_stays():
    feed = b"<rss><channel><item><guid>1</guid><link>javascript:alert(1)</link><title>CVE-2026-1234</title></item></channel></rss>"

    [item] = parse_feed(feed)

    assert item.url is None
    assert item.cve_ids == ["CVE-2026-1234"]


def test_extracts_typographic_hyphens_and_ignores_short_ids():
    assert extract_cve_ids("CVE‑2026‑12345, cve-2026-1234, CVE-2026-12") == ["CVE-2026-1234", "CVE-2026-12345"]


def test_feed_config_merges_extras_and_lets_them_replace_a_default():
    feeds = parse_feed_config(
        "CISA|https://cisa.example/all.xml, CERT-FR|https://fr.example/feed",
        "CERT.at|https://cert.at/warnings.xml,CISA|https://cisa.example/other.xml",
    )

    assert {feed.name: feed.url for feed in feeds} == {
        "CISA": "https://cisa.example/other.xml",
        "CERT-FR": "https://fr.example/feed",
        "CERT.at": "https://cert.at/warnings.xml",
    }


@pytest.mark.parametrize("entry", ["no-separator", "|https://x.example/", "Name|", "Name|ftp://x.example/", ""])
def test_feed_config_skips_a_broken_entry(entry):
    assert parse_feed_config(f"{entry},Good|https://good.example/feed") == [CertFeed("Good", "https://good.example/feed")]


def test_the_default_feeds_parse():
    feeds = parse_feed_config(settings.cert_feeds)

    assert len(feeds) >= 5
    assert all(feed.url.startswith("https://") for feed in feeds)


def _client(handler) -> CertFeedClient:
    return CertFeedClient(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False),
        max_retries=0,
        retry_backoff=0,
    )


FEED = CertFeed("A CERT", "https://www.cert.example/feed")


async def test_page_fetch_stays_on_the_feeds_host():
    requested = []

    def handler(request):
        requested.append(str(request.url))
        return httpx.Response(200, text="CVE-2026-1234")

    client = _client(handler)

    assert await client.fetch_page_cves(FEED, "https://169.254.169.254/latest/meta-data") == []
    assert await client.fetch_page_cves(FEED, "https://cert.example.evil.test/a") == []
    assert requested == []


async def test_page_fetch_reads_the_cves_without_the_fragment():
    requested = []

    def handler(request):
        requested.append(str(request.url))
        return httpx.Response(200, text="<p>CVE-2026-1234</p>")

    assert await _client(handler).fetch_page_cves(FEED, "https://cert.example/a#2") == ["CVE-2026-1234"]
    assert requested == ["https://cert.example/a"]


async def test_page_fetch_does_not_follow_a_redirect():
    def handler(request):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/"})

    assert await _client(handler).fetch_page_cves(FEED, "https://cert.example/a") == []


async def test_a_server_error_on_a_page_means_try_again():
    assert await _client(lambda _: httpx.Response(503)).fetch_page_cves(FEED, "https://cert.example/a") is None


async def test_a_broken_feed_is_reported_and_not_raised():
    assert await _client(lambda _: httpx.Response(200, text="not xml")).fetch_feed(FEED) is None
    assert await _client(lambda _: httpx.Response(403)).fetch_feed(FEED) is None


class _Repository:
    def __init__(self, known=()):
        self.known = set(known)
        self.saved: dict[str, list[str]] = {}

    async def existing_ids(self, ids):
        return {i for i in ids if i in self.known}

    async def insert(self, feed, item, cve_ids):
        self.saved[item.guid] = cve_ids


class _FakeClient:
    def __init__(self, pages=None):
        self.pages = pages or {}
        self.requested: list[str] = []

    async def fetch_page_cves(self, _feed, url):
        self.requested.append(url)
        return self.pages.get(url.split("#")[0], [])


def _item(guid, *, cves=(), url=None, age_days=1):
    return CertAdvisoryItem(
        guid=guid,
        title=guid,
        url=url,
        published=datetime.now(UTC) - timedelta(days=age_days),
        cve_ids=list(cves),
    )


async def _store(items, *, pages=None, known=()):
    client = _FakeClient(pages)
    repository = _Repository(known)
    stats = await CertFeedPipeline(client=client)._store_new_items(repository, FEED, items)
    return stats, repository, client


async def test_a_feed_item_with_cves_needs_no_page():
    stats, repository, client = await _store([_item("1", cves=["CVE-2026-1"], url="https://cert.example/1")])

    assert repository.saved == {"1": ["CVE-2026-1"]}
    assert client.requested == []
    assert stats["with_cves"] == 1


async def test_an_item_without_cves_reads_its_page_once():
    url = "https://cert.example/wr.html"
    stats, repository, client = await _store(
        [_item("1", url=f"{url}#1"), _item("2", url=f"{url}#2")],
        pages={url: ["CVE-2026-1"]},
    )

    assert client.requested == [f"{url}#1"]
    assert stats["pages"] == 1
    assert repository.saved == {"1": ["CVE-2026-1"], "2": ["CVE-2026-1"]}


async def test_known_items_cost_no_request():
    _, repository, client = await _store([_item("1", url="https://cert.example/1")], known={"A CERT:1"})

    assert repository.saved == {}
    assert client.requested == []


async def test_an_old_item_does_not_read_its_page():
    _, repository, client = await _store([_item("1", url="https://cert.example/1", age_days=90)])

    assert client.requested == []
    assert repository.saved == {"1": []}


async def test_a_failed_page_is_retried_next_run():
    class Failing(_FakeClient):
        async def fetch_page_cves(self, _feed, url):
            return None

    repository = _Repository()
    await CertFeedPipeline(client=Failing())._store_new_items(repository, FEED, [_item("1", url="https://cert.example/1")])

    assert repository.saved == {}


async def test_the_page_budget_leaves_the_rest_for_the_next_run(monkeypatch):
    monkeypatch.setattr(settings, "cert_feeds_max_page_fetches_per_run", 1)
    items = [_item(str(n), url=f"https://cert.example/{n}") for n in range(3)]

    _, repository, client = await _store(items)

    assert len(client.requested) == 1
    assert list(repository.saved) == ["0"]


async def test_one_broken_feed_does_not_stop_the_others(monkeypatch):
    feeds = "Bad|https://bad.example/feed,Good|https://good.example/feed"
    monkeypatch.setattr(settings, "cert_feeds", feeds)
    monkeypatch.setattr(settings, "cert_feeds_extra", "")
    finished = {}

    class Tracker:
        def __init__(self, _state):
            pass

        async def start(self, *_args, **_kwargs):
            return object()

        async def finish(self, _ctx, **result):
            finished.update(result)

        async def fail(self, _ctx, error):
            finished["error"] = error

    class Client(_FakeClient):
        async def fetch_feed(self, feed):
            return None if feed.name == "Bad" else [_item("1", cves=["CVE-2026-1"])]

    async def create():
        return _Repository()

    monkeypatch.setattr(cert_feed_pipeline, "JobTracker", Tracker)
    monkeypatch.setattr(cert_feed_pipeline.CertAdvisoryRepository, "create", staticmethod(create))
    monkeypatch.setattr(cert_feed_pipeline.IngestionStateRepository, "create", staticmethod(create))

    result = await CertFeedPipeline(client=Client()).sync()

    assert result["failedFeeds"] == ["Bad"]
    assert result["withCves"] == 1
    assert "error" not in finished
