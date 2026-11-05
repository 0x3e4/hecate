"""Advisory feeds managed on the System page: who may add what, and what the public list shows."""
from __future__ import annotations

import pytest
from pymongo.errors import DuplicateKeyError, ServerSelectionTimeoutError

from app.core.config import settings
from app.schemas.advisory_feed import AdvisoryFeedCreateRequest, AdvisoryFeedUpdateRequest
from app.services import advisory_feed_service
from app.services.advisory_feed_service import (
    AdvisoryFeedService,
    FeedConflictError,
    active_feeds,
    feed_kinds,
    redact_feed_url,
)
from app.services.http.public_host import is_public_address, is_public_url


class _Repository:
    def __init__(self, documents=()):
        self.documents = {doc["_id"]: dict(doc) for doc in documents}

    async def list_all(self):
        return list(self.documents.values())

    async def get(self, feed_id):
        return self.documents.get(feed_id)

    async def insert(self, document):
        if any(doc["name_key"] == document["name_key"] for doc in self.documents.values()):
            raise DuplicateKeyError("name_key")
        self.documents[document["_id"]] = document

    async def update(self, feed_id, fields):
        if feed_id not in self.documents:
            return None
        self.documents[feed_id].update(fields)
        return self.documents[feed_id]

    async def delete(self, feed_id):
        return self.documents.pop(feed_id, None)


@pytest.fixture(autouse=True)
def _config(monkeypatch):
    monkeypatch.setattr(settings, "cert_feeds", "CERT-FR|https://fr.example/feed")
    monkeypatch.setattr(settings, "cert_feeds_extra", "")
    monkeypatch.setattr(settings, "cert_feeds_allow_private_hosts", False)

    async def public(_url):
        return True

    monkeypatch.setattr(advisory_feed_service, "is_public_url", public)


def _use(monkeypatch, repository):
    async def create():
        return repository

    monkeypatch.setattr(advisory_feed_service.AdvisoryFeedRepository, "create", staticmethod(create))


def _doc(feed_id, name, *, kind="community", enabled=True):
    return {
        "_id": feed_id,
        "name": name,
        "name_key": name.casefold(),
        "url": f"https://m.example/{name}.rss",
        "kind": kind,
        "enabled": enabled,
    }


async def test_a_feed_is_added_with_its_kind():
    service = AdvisoryFeedService(_Repository())

    created = await service.create_feed(
        AdvisoryFeedCreateRequest(name="@analyst", url="https://m.example/@analyst.rss", kind="community")
    )

    assert (created.origin, created.kind, created.enabled) == ("ui", "community", True)
    listed = await service.list_feeds()
    assert [(feed.name, feed.origin) for feed in listed] == [("CERT-FR", "env"), ("@analyst", "ui")]


async def test_a_name_from_env_cannot_be_taken():
    with pytest.raises(FeedConflictError):
        await AdvisoryFeedService(_Repository()).create_feed(
            AdvisoryFeedCreateRequest(name="cert-fr", url="https://other.example/feed")
        )


async def test_two_ui_feeds_cannot_share_a_name():
    service = AdvisoryFeedService(_Repository())
    await service.create_feed(AdvisoryFeedCreateRequest(name="Vendor", url="https://a.example/feed"))

    with pytest.raises(FeedConflictError):
        await service.create_feed(AdvisoryFeedCreateRequest(name="VENDOR", url="https://b.example/feed"))


@pytest.mark.parametrize("url", ["javascript:alert(1)", "file:///etc/passwd", "ftp://a.example/feed"])
async def test_only_http_feeds_are_accepted(url):
    with pytest.raises(ValueError, match="http"):
        await AdvisoryFeedService(_Repository()).create_feed(AdvisoryFeedCreateRequest(name="X", url=url))


async def test_a_private_host_is_refused_unless_allowed(monkeypatch):
    async def private(_url):
        return False

    monkeypatch.setattr(advisory_feed_service, "is_public_url", private)
    request = AdvisoryFeedCreateRequest(name="Intranet", url="https://feeds.corp.example/rss")

    with pytest.raises(ValueError, match="CERT_FEEDS_ALLOW_PRIVATE_HOSTS"):
        await AdvisoryFeedService(_Repository()).create_feed(request)

    monkeypatch.setattr(settings, "cert_feeds_allow_private_hosts", True)
    assert (await AdvisoryFeedService(_Repository()).create_feed(request)).name == "Intranet"


async def test_an_update_changes_only_what_was_sent():
    service = AdvisoryFeedService(_Repository())
    created = await service.create_feed(AdvisoryFeedCreateRequest(name="Cloudflare", url="https://cf.example/rss"))

    updated = await service.update_feed(created.id, AdvisoryFeedUpdateRequest(kind="vendor", enabled=False))

    assert (updated.name, updated.url, updated.kind, updated.enabled) == (
        "Cloudflare",
        "https://cf.example/rss",
        "vendor",
        False,
    )


async def test_the_sync_reads_enabled_ui_feeds_after_the_env_ones(monkeypatch):
    _use(monkeypatch, _Repository([_doc("1", "@on"), _doc("2", "@off", enabled=False)]))

    feeds = await active_feeds()

    assert [(feed.name, feed.kind, feed.guard_host) for feed in feeds] == [
        ("CERT-FR", "cert", False),
        ("@on", "community", True),
    ]


async def test_kinds_come_from_env_and_ui_feeds(monkeypatch):
    _use(monkeypatch, _Repository([_doc("1", "Cloudflare", kind="vendor")]))

    assert await feed_kinds() == {"Cloudflare": "vendor", "CERT-FR": "cert"}


async def test_env_feeds_still_run_when_mongodb_is_down(monkeypatch):
    async def down():
        raise ServerSelectionTimeoutError("down")

    monkeypatch.setattr(advisory_feed_service.AdvisoryFeedRepository, "create", staticmethod(down))

    assert [feed.name for feed in await active_feeds()] == ["CERT-FR"]
    assert await feed_kinds() == {"CERT-FR": "cert"}


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://cert.example/feed?lang=en", "https://cert.example/feed?lang=en"),
        ("https://intel.example/rss?api_key=s3cret&lang=en", "https://intel.example/rss?api_key=***&lang=en"),
        ("https://user:pw@intel.example/rss", "https://***@intel.example/rss"),
    ],
)
def test_the_public_list_masks_credentials_in_a_feed_url(url, expected):
    assert redact_feed_url(url) == expected


@pytest.mark.parametrize(
    ("address", "public"),
    [
        ("8.8.8.8", True),
        ("2606:4700::1111", True),
        ("127.0.0.1", False),
        ("10.1.2.3", False),
        ("169.254.169.254", False),
        ("100.64.0.1", False),
        ("::1", False),
        ("fd00::1", False),
        ("::ffff:127.0.0.1", False),
        ("fe80::1%eth0", False),
    ],
)
def test_which_addresses_count_as_public(address, public):
    assert is_public_address(address) is public


async def test_a_literal_private_address_is_refused_without_a_lookup():
    assert await is_public_url("https://169.254.169.254/latest/meta-data") is False
    assert await is_public_url("https://[::1]:8443/feed") is False


async def test_a_host_that_does_not_resolve_is_refused():
    assert await is_public_url("https://does-not-exist.invalid/feed") is False
