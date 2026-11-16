"""Support page version check: release badge and build relation.

A beta built from an unpushed commit must not be told that an older release
or an older ``main-<sha>`` image is an update.
"""
from __future__ import annotations

import httpx
import pytest

from app.api.v1 import version as version_module
from app.api.v1.version import _build_relation, release_available, version_key


def test_a_prerelease_sorts_below_its_release_and_above_the_previous_one():
    assert version_key("2.3.0-beta.8") > version_key("2.2.1")
    assert version_key("2.3.0") > version_key("2.3.0-beta.8")
    assert version_key("2.3.0-beta.10") > version_key("2.3.0-beta.9")
    assert version_key("2.3.0-rc.1") > version_key("2.3.0-beta.9")
    assert version_key("v2.3") == version_key("2.3.0")
    assert version_key("main") is None


def test_release_available_only_for_a_newer_release():
    assert release_available("2.2.1", "2.3.0-beta.8") is False
    assert release_available("2.2.1", "2.2.1") is False
    assert release_available("2.3.0", "2.3.0-beta.8") is True
    assert release_available("2.2.1", "2.2.0") is True
    assert release_available(None, "2.3.0") is None
    assert release_available("2.2.1", "dev") is None


async def test_prerelease_tags_are_never_the_release_on_offer(monkeypatch):
    tags = [{"name": "2.3.0-beta.8"}, {"name": "2.2.1"}, {"name": "2.2.0"}, {"name": "latest"}]

    async def fake_request(*_args, **_kwargs):
        return httpx.Response(200, json=tags)

    monkeypatch.setattr(version_module, "request_with_retry", fake_request)
    async with httpx.AsyncClient() as client:
        found = await version_module._fetch_latest_semver_tag(client)

    assert found is not None and found.tag == "2.2.1"


@pytest.fixture(autouse=True)
def _empty_relation_cache():
    version_module._relation_cache.clear()
    yield
    version_module._relation_cache.clear()


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_same_commit_needs_no_lookup():
    def handler(_request):  # pragma: no cover - must not be called
        raise AssertionError("no GitHub call expected")

    async with _client(handler) as client:
        assert await _build_relation(client, "90a305c", "90a305cabcdef") == "identical"


async def test_relation_comes_from_the_compare_api_and_is_cached():
    calls: list[str] = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={"status": "ahead"})

    async with _client(handler) as client:
        assert await _build_relation(client, "90a305c", "7f05946") == "ahead"
        assert await _build_relation(client, "90a305c", "7f05946") == "ahead"

    assert calls == ["/repos/0x3e4/hecate/compare/90a305c...7f05946"]


async def test_a_commit_github_does_not_know_is_a_local_build():
    async with _client(lambda _r: httpx.Response(404, json={"message": "Not Found"})) as client:
        assert await _build_relation(client, "90a305c", "d3cc1ba") == "unknown_commit"


async def test_failures_and_unusable_input_answer_none():
    async with _client(lambda _r: httpx.Response(403, json={})) as client:
        assert await _build_relation(client, "90a305c", "d3cc1ba") is None
        assert await _build_relation(client, None, "d3cc1ba") is None
        assert await _build_relation(client, "90a305c", "../../etc") is None
    assert version_module._relation_cache == {}
