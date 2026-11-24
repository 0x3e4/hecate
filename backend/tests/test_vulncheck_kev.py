"""VulnCheck KEV as an opt-in exploit signal."""
from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.core.config import settings
from app.services import exploit_signals
from app.services.attack_path_service import AttackPathService
from app.services.ingestion import vulncheck_kev as vk
from app.services.ingestion.vulncheck_kev import VulnCheckKevPipeline, entries_from_records

RECORD = {
    "vendorProject": "PHP Group",
    "product": "PHP",
    "shortDescription": "argument injection",
    "vulnerabilityName": "PHP-CGI OS Command Injection",
    "knownRansomwareCampaignUse": "Known",
    "cve": ["CVE-2024-4577", "not-a-cve"],
    "vulncheck_xdb": [
        {"xdb_id": "1", "xdb_url": "https://vulncheck.com/xdb/1"},
        {"xdb_id": "2", "xdb_url": "javascript:alert(1)"},
    ],
    "vulncheck_reported_exploitation": [
        {"url": "https://a.example/1"}, {"url": "https://a.example/1"},
        {"url": "https://b.example/2"}, {"url": "https://c.example/3"}, {"url": "https://d.example/4"},
    ],
    "reported_exploited_by_vulncheck_canaries": True,
    "date_added": "2024-06-07T00:00:00Z",
    "cisa_date_added": "2024-06-12T00:00:00Z",
}


def test_record_summary_keeps_links_short_and_safe() -> None:
    entries = entries_from_records([RECORD, "junk"])  # type: ignore[list-item]
    assert list(entries) == ["CVE-2024-4577"]
    entry = entries["CVE-2024-4577"]
    assert entry["name"] == "PHP-CGI OS Command Injection"
    assert entry["ransomware"] == "Known"
    assert entry["canaries"] is True
    assert entry["report_count"] == 5
    assert entry["report_urls"] == ["https://a.example/1", "https://b.example/2", "https://c.example/3"]
    assert entry["exploit_count"] == 2
    assert entry["exploit_urls"] == ["https://vulncheck.com/xdb/1"]


def _client(pages: list[dict[str, Any]], seen: list[httpx.Request], status: int = 200) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if status != 200:
            return httpx.Response(status, json={"error": True, "errors": ["unauthorized"]})
        index = 0 if "start_cursor" in request.url.params else int(request.url.params["cursor"])
        return httpx.Response(200, json=pages[index])

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_fetch_follows_the_cursor_with_a_bearer_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "vulncheck_api_token", "vulncheck_secret")
    pages = [
        {"_meta": {"next_cursor": "1"}, "data": [RECORD]},
        {"_meta": {}, "data": [{**RECORD, "cve": ["CVE-2021-44228"]}]},
    ]
    seen: list[httpx.Request] = []
    async with _client(pages, seen) as client:
        records = await VulnCheckKevPipeline(client).fetch_records()
    assert [r["cve"][0] for r in records] == ["CVE-2024-4577", "CVE-2021-44228"]
    assert all(r.headers["Authorization"] == "Bearer vulncheck_secret" for r in seen)
    assert all("vulncheck_secret" not in str(r.url) for r in seen)


async def test_fetch_needs_a_token_and_reports_a_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "vulncheck_api_token", None)
    with pytest.raises(RuntimeError, match="VULNCHECK_API_TOKEN"):
        await VulnCheckKevPipeline(httpx.AsyncClient()).fetch_records()

    monkeypatch.setattr(settings, "vulncheck_api_token", "bad")
    seen: list[httpx.Request] = []
    async with _client([], seen, status=401) as client:
        with pytest.raises(RuntimeError, match="refused the token"):
            await VulnCheckKevPipeline(client).fetch_records()


class _Repo:
    def __init__(self, existing: int) -> None:
        self.existing = {f"CVE-2020-{i:04d}": {} for i in range(existing)}
        self.replaced: dict[str, Any] | None = None

    async def source_entries(self, _source: str) -> dict[str, Any]:
        return self.existing

    async def replace_source(self, _source: str, incoming: dict[str, Any]) -> dict[str, int]:
        self.replaced = incoming
        return {"total": len(incoming), "written": len(incoming), "removed": 0}


class _Tracker:
    async def start(self, *_a: Any, **_k: Any) -> str:
        return "ctx"

    async def finish(self, *_a: Any, **_k: Any) -> None:
        return None

    async def fail(self, *_a: Any) -> None:
        return None


async def test_sync_refuses_a_shrunken_catalogue(monkeypatch: pytest.MonkeyPatch) -> None:
    async def state_repo() -> None:
        return None

    monkeypatch.setattr(vk, "JobTracker", lambda _repo: _Tracker())
    monkeypatch.setattr(vk.IngestionStateRepository, "create", state_repo)
    monkeypatch.setattr(settings, "vulncheck_api_token", "t")
    pages = [{"_meta": {}, "data": [RECORD]}]

    repo = _Repo(existing=0)
    async with _client(pages, []) as client:
        await VulnCheckKevPipeline(client).sync(repo)
    assert list(repo.replaced or {}) == ["CVE-2024-4577"]

    shrunk = _Repo(existing=10)
    async with _client(pages, []) as client:
        with pytest.raises(RuntimeError, match="refusing"):
            await VulnCheckKevPipeline(client).sync(shrunk)
    assert shrunk.replaced is None


def test_rows_carry_the_attribution() -> None:
    summary = entries_from_records([RECORD])["CVE-2024-4577"]
    rows = exploit_signals.signals_from_documents({"CVE-2024-4577": {"vulncheck_kev": summary}})
    assert len(rows) == 1
    row = rows[0]
    assert row["source"] == "vulncheck_kev"
    assert row["attribution"] == "VulnCheck KEV"
    assert row["url"] == "https://vulncheck.com/kev"
    assert row["dateAdded"] == "2024-06-07T00:00:00Z"
    assert row["reportCount"] == 5


def test_vulncheck_kev_means_high_exploit_maturity() -> None:
    from app.schemas.vulnerability import VulnerabilityDetail

    vuln = VulnerabilityDetail.model_validate({
        "vulnId": "CVE-2024-4577", "source": "NVD", "title": "t", "summary": "s",
        "ingestedAt": "2024-01-01T00:00:00Z", "exploitSignals": [{"source": "vulncheck_kev"}],
    })
    assert AttackPathService._exploit_maturity(vuln) == "high"


def test_signals_reach_the_ai_prompt() -> None:
    from app.services.ai_service import format_exploit_signals

    summary = entries_from_records([RECORD])["CVE-2024-4577"]
    rows = exploit_signals.signals_from_documents({"CVE-2024-4577": {
        "vulncheck_kev": summary,
        "nuclei": {"name": "PHP-CGI RCE", "path": "http/cves/2024/CVE-2024-4577.yaml", "protocol": "http"},
    }})
    lines = format_exploit_signals(rows)
    assert lines[0].startswith("Public Nuclei template (CVE-2024-4577): PHP-CGI RCE")
    assert lines[1] == (
        "VulnCheck KEV (CVE-2024-4577): reported exploited, listed 2024-06-07, CISA 2024-06-12, "
        "ransomware use: Known, 5 exploitation reports, 2 public exploits"
    )
    assert format_exploit_signals(None) == []
