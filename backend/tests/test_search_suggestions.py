"""Dashboard search suggestions: the query, and what each candidate carries."""
from __future__ import annotations

from typing import Any

import pytest

from app.services import search_suggestions as ss
from app.services.search_suggestions import build_suggestion_query


def _should(body: dict[str, Any]) -> list[dict[str, Any]]:
    return body["query"]["bool"]["should"]


def test_too_short_asks_nothing() -> None:
    assert build_suggestion_query(" a ") is None


def test_an_id_prefix_searches_ids_only() -> None:
    body = build_suggestion_query("cve-2026-11")
    kinds = [next(iter(clause)) for clause in _should(body)]
    assert kinds == ["term", "prefix", "prefix"]
    assert _should(body)[1]["prefix"]["vuln_id"]["value"] == "CVE-2026-11"


def test_free_text_also_searches_text_and_names_with_escaped_wildcards() -> None:
    body = build_suggestion_query("log*4j")
    wildcards = [c["wildcard"] for c in _should(body) if "wildcard" in c]
    assert wildcards[0]["products"]["value"] == "*log\\*4j*"
    assert any("multi_match" in c for c in _should(body))
    assert body["size"] == ss.CANDIDATES


async def test_candidates_carry_inventory_and_sbom_hits(monkeypatch: pytest.MonkeyPatch) -> None:
    sources = [
        {"vuln_id": "CVE-1", "title": "T1", "summary": "x " * 200, "cvss": {"severity": "HIGH", "base_score": 8.1},
         "epssScore": 0.4, "exploitation": {"dateAdded": "2026-11-01"}, "products": ["Brotli"]},
        {"vuln_id": "CVE-2", "title": "T2", "cvss": {"severity": "low"}},
    ]

    async def fake_search(index: str, body: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        return {"hits": {"hits": [{"_source": s} for s in sources]}}

    class FakeInventory:
        async def list_all_cached(self) -> list[dict[str, Any]]:
            return [{"_id": "inv1"}]

    async def fake_inventory_service() -> FakeInventory:
        return FakeInventory()

    async def fake_sbom(srcs: list[dict[str, Any]]) -> dict[str, str]:
        return {"CVE-2": "scan9"}

    monkeypatch.setattr(ss, "async_search", fake_search)
    monkeypatch.setattr(ss, "items_for_vuln", lambda source, inv: inv if source["vuln_id"] == "CVE-1" else [])
    monkeypatch.setattr("app.services.inventory_service.get_inventory_service", fake_inventory_service)
    monkeypatch.setattr("app.services.stats_service.StatsService._sbom_scan_ids", staticmethod(fake_sbom))

    items = await ss.suggest("brotli")

    first, second = items
    assert first["inventoryMatchIds"] == ["inv1"] and first["sbomScanId"] is None
    assert first["severity"] == "high" and first["kevListed"] is True and first["cvssScore"] == 8.1
    assert len(first["info"]) <= ss.INFO_LENGTH and first["info"].endswith("…")
    assert second["sbomScanId"] == "scan9" and second["inventoryMatchIds"] == []
    assert second["info"] == "T2"


async def test_a_search_error_gives_no_suggestions(monkeypatch: pytest.MonkeyPatch) -> None:
    async def broken(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("opensearch down")

    monkeypatch.setattr(ss, "async_search", broken)
    assert await ss.suggest("brotli") == []
