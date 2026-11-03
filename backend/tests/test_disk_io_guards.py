"""Guards against full reads of the vulnerabilities collection.

The collection is tens of GB on disk. A history entry used to copy the whole
document (and every raw upstream payload) up to three times, and the stats
fallback plus the per-sync source counts scanned the collection without an
index, which stalled the disk for every service on the host.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from opensearchpy.exceptions import ConnectionError as OSConnectionError

from app.repositories import vulnerability_repository as repo_mod
from app.repositories.vulnerability_repository import (
    VulnerabilityRepository,
    _build_change_entry,
    _compact_history,
)
from app.services import stats_service
from app.services.stats_service import StatsService

RAW = {"cve": {"id": "CVE-2025-1", "descriptions": ["x" * 5000]}}


def _source(name: str, ingested: str, raw=RAW) -> dict:
    return {"source": name, "url": f"https://{name}.example", "ingested_at": ingested, "raw": raw}


def test_change_entry_has_no_snapshot_and_no_raw_payloads():
    existing = {"_id": "CVE-2025-1", "summary": "old", "sources": [_source("NVD", "t1")]}
    payload = {"summary": "new", "sources": [_source("NVD", "t2", raw={"changed": True})]}

    entry = _build_change_entry(existing, payload, {"job_name": "nvd_sync"})

    assert "snapshot" not in entry
    fields = {f["name"]: f for f in entry["fields"]}
    assert fields["summary"]["current"] == "new"
    for side in ("previous", "current"):
        (src,) = fields["sources"][side]
        assert src == {"source": "NVD", "url": "https://NVD.example", "raw": "present"}


def test_refetch_that_only_moves_ingested_at_is_not_a_change():
    existing = {"_id": "CVE-2025-1", "summary": "same", "sources": [_source("NVD", "t1")]}
    payload = {"summary": "same", "sources": [_source("NVD", "t2")]}

    assert _build_change_entry(existing, payload, {"job_name": "osv_initial_sync"}) is None


def test_insert_entry_keeps_sources_compact():
    entry = _build_change_entry(None, {"sources": [_source("OSV", "t1")]}, {"job_name": "osv"})
    (field,) = entry["fields"]
    assert field["previous"] is None
    assert field["current"] == [{"source": "OSV", "url": "https://OSV.example", "raw": "present"}]


def test_compact_history_shrinks_legacy_entries():
    legacy = [
        {
            "changed_at": datetime(2026, 10, 30, tzinfo=UTC),
            "job_name": "osv_initial_sync",
            "fields": [
                {"name": "sources", "previous": [_source("NVD", "t1")], "current": [_source("NVD", "t2")]},
                {"name": "summary", "previous": "a", "current": "b"},
            ],
            "snapshot": {"summary": "b", "sources": [_source("NVD", "t2")]},
        },
        {"changed_at": datetime(2026, 10, 31, tzinfo=UTC), "job_name": "kev"},
    ]

    compact = _compact_history(legacy)

    assert "snapshot" not in compact[0]
    assert compact[0]["fields"][0]["current"] == [
        {"source": "NVD", "url": "https://NVD.example", "raw": "present"}
    ]
    assert compact[0]["fields"][1] == {"name": "summary", "previous": "a", "current": "b"}
    assert compact[1] == {"changed_at": datetime(2026, 10, 31, tzinfo=UTC), "job_name": "kev"}
    # The input is not touched: callers still hold the existing document.
    assert "snapshot" in legacy[0]


def test_every_write_path_compacts_the_copied_history():
    source = open(repo_mod.__file__, encoding="utf-8").read()
    assert 'copy.deepcopy(existing["change_history"])' not in source
    assert "_build_snapshot" not in source


@pytest.mark.asyncio
async def test_source_count_comes_from_opensearch(monkeypatch):
    bodies = []

    async def search(_index, body, **_kwargs):
        bodies.append(body)
        return {"hits": {"total": {"value": 4211}}}

    monkeypatch.setattr(repo_mod, "async_search", search)
    repo = VulnerabilityRepository.__new__(VulnerabilityRepository)
    repo.index_name = "hecate-vulnerabilities"
    repo.collection = None  # any MongoDB access would fail the test

    assert await repo.count_with_source_data("NVD") == 4211
    assert bodies[0]["query"] == {"term": {"sourceNames": "NVD"}}


@pytest.mark.asyncio
async def test_source_count_failure_is_none_not_a_mongo_scan(monkeypatch):
    async def search(*_args, **_kwargs):
        raise OSConnectionError("N/A", "down", None)

    monkeypatch.setattr(repo_mod, "async_search", search)
    repo = VulnerabilityRepository.__new__(VulnerabilityRepository)
    repo.index_name = "hecate-vulnerabilities"
    repo.collection = None

    assert await repo.count_with_source_data("EUVD") is None


class _Collection:
    """Answers only index-backed calls; aggregate() would be a collection scan."""

    def __init__(self):
        self.max_times: list[int | None] = []

    async def estimated_document_count(self, maxTimeMS=None):
        self.max_times.append(maxTimeMS)
        return 10

    async def distinct(self, field, maxTimeMS=None):
        self.max_times.append(maxTimeMS)
        return {"source": ["NVD", "EUVD"], "cvss.severity": ["high", None]}[field]

    async def count_documents(self, query, maxTimeMS=None):
        self.max_times.append(maxTimeMS)
        return {"NVD": 7, "EUVD": 3, "high": 4}[next(iter(query.values()))]

    def aggregate(self, *_args, **_kwargs):
        raise AssertionError("the fallback must not run aggregations")


@pytest.mark.asyncio
async def test_mongo_fallback_uses_only_bounded_index_queries(monkeypatch):
    collection = _Collection()

    class _Repo:
        pass

    async def create():
        repo = _Repo()
        repo.collection = collection
        return repo

    monkeypatch.setattr(stats_service.VulnerabilityRepository, "create", create)
    monkeypatch.setattr(stats_service, "_LAST_GOOD_VULN_STATS", {})

    stats = await StatsService()._fetch_vulnerability_stats_from_mongo()

    assert stats["total"] == 10
    assert stats["sources"] == [{"key": "NVD", "doc_count": 7}, {"key": "EUVD", "doc_count": 3}]
    assert stats["severities"] == [{"key": "HIGH", "doc_count": 4}]
    assert collection.max_times and all(t == stats_service.MONGO_FALLBACK_MAX_TIME_MS for t in collection.max_times)


@pytest.mark.asyncio
async def test_outage_serves_last_opensearch_result(monkeypatch):
    calls = {"n": 0}

    async def search(_index, _body, **_kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"hits": {"total": {"value": 99}}, "aggregations": {}}
        raise OSConnectionError("N/A", "down", None)

    async def no_mongo():
        raise AssertionError("MongoDB must not be touched while a last result exists")

    monkeypatch.setattr(stats_service, "async_search", search)
    monkeypatch.setattr(stats_service, "_LAST_GOOD_VULN_STATS", {})
    monkeypatch.setattr(stats_service, "OPENSEARCH_RETRY_DELAY_SECONDS", 0)
    monkeypatch.setattr(stats_service.VulnerabilityRepository, "create", no_mongo)

    service = StatsService()
    first = await service._fetch_vulnerability_stats()
    second = await service._fetch_vulnerability_stats()

    assert first["total"] == 99
    assert second == first
    assert calls["n"] == 3  # success, then the failure and its one retry


@pytest.mark.asyncio
async def test_startup_503_is_retried_before_falling_back(monkeypatch):
    calls = {"n": 0}

    async def search(_index, _body, **_kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSConnectionError("N/A", "starting", None)
        return {"hits": {"total": {"value": 5}}, "aggregations": {}}

    async def no_mongo():
        raise AssertionError("the retry should have answered")

    monkeypatch.setattr(stats_service, "async_search", search)
    monkeypatch.setattr(stats_service, "_LAST_GOOD_VULN_STATS", {})
    monkeypatch.setattr(stats_service, "OPENSEARCH_RETRY_DELAY_SECONDS", 0)
    monkeypatch.setattr(stats_service.VulnerabilityRepository, "create", no_mongo)

    stats = await StatsService()._fetch_vulnerability_stats()
    assert stats["total"] == 5


def test_cli_main_guard_comes_after_every_command():
    # A function defined below the guard is a NameError when run as a script.
    from app import cli

    source = open(cli.__file__, encoding="utf-8").read()
    assert source.rstrip().endswith('if __name__ == "__main__":\n    main()')
