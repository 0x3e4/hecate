"""Public Nuclei templates as an exploit signal."""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.repositories.exploit_signal_repository import plan_source_update
from app.services import exploit_signals
from app.services.attack_path_service import AttackPathService
from app.services.ingestion import nuclei_templates as nt
from app.services.ingestion.nuclei_templates import NucleiTemplatesPipeline, parse_index

LINES = [
    {"ID": "CVE-2024-3400", "Info": {"Name": "PAN-OS  GlobalProtect - RCE", "Severity": "critical",
                                     "Description": "x", "Classification": {"CVSSScore": "10"}},
     "file_path": "http/cves/2024/CVE-2024-3400.yaml"},
    {"ID": "cve-2021-44228", "Info": {"Name": "Log4Shell", "Severity": "weird"},
     "file_path": "network/cves/2021/CVE-2021-44228.yaml"},
    {"ID": "CVE-2020-1", "Info": {"Name": "bad id"}, "file_path": "http/cves/x.yaml"},
    {"ID": "CVE-2022-0001", "Info": {"Name": "escape"}, "file_path": "../../etc/passwd.yaml"},
    {"ID": "CVE-2022-0002", "Info": {"Name": "no yaml"}, "file_path": "http/cves/2022/x.txt"},
]


def _index(lines: list[dict[str, Any]] = LINES) -> str:
    return "\n".join(json.dumps(line) for line in lines) + "\nnot json\n\n"


def test_parse_keeps_valid_entries_only() -> None:
    entries = parse_index(_index())
    assert set(entries) == {"CVE-2024-3400", "CVE-2021-44228"}
    assert entries["CVE-2024-3400"] == {
        "name": "PAN-OS GlobalProtect - RCE",
        "severity": "critical",
        "path": "http/cves/2024/CVE-2024-3400.yaml",
        "protocol": "http",
    }
    assert entries["CVE-2021-44228"]["severity"] == "unknown"
    assert entries["CVE-2021-44228"]["protocol"] == "network"


def test_plan_writes_only_changes() -> None:
    existing = {"CVE-1": {"name": "a"}, "CVE-2": {"name": "b"}, "CVE-3": {"name": "c"}}
    incoming = {"CVE-1": {"name": "a"}, "CVE-2": {"name": "B"}, "CVE-4": {"name": "d"}}
    upserts, removals = plan_source_update(existing, incoming)
    assert upserts == {"CVE-2": {"name": "B"}, "CVE-4": {"name": "d"}}
    assert removals == ["CVE-3"]


class _Repo:
    def __init__(self, existing: dict[str, dict[str, Any]]) -> None:
        self.existing = existing
        self.replaced: dict[str, dict[str, Any]] | None = None

    async def source_entries(self, source: str) -> dict[str, dict[str, Any]]:
        return self.existing

    async def replace_source(self, source: str, incoming: dict[str, dict[str, Any]]) -> dict[str, int]:
        self.replaced = incoming
        return {"total": len(incoming), "written": len(incoming), "removed": 0}


class _Tracker:
    def __init__(self, *_args: Any) -> None:
        self.failed: list[str] = []

    async def start(self, *_args: Any, **_kwargs: Any) -> str:
        return "ctx"

    async def finish(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    async def fail(self, _ctx: Any, error: str) -> None:
        self.failed.append(error)


@pytest.fixture
def tracker(monkeypatch: pytest.MonkeyPatch) -> _Tracker:
    instance = _Tracker()

    async def state_repo() -> None:
        return None

    monkeypatch.setattr(nt, "JobTracker", lambda _repo: instance)
    monkeypatch.setattr(nt.IngestionStateRepository, "create", state_repo)
    return instance


def _client(body: str, status: int = 200) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(lambda _r: httpx.Response(status, text=body)))


async def test_sync_replaces_the_source(tracker: _Tracker) -> None:
    repo = _Repo({})
    async with _client(_index()) as client:
        result = await NucleiTemplatesPipeline(client).sync(repo)
    assert set(repo.replaced or {}) == {"CVE-2024-3400", "CVE-2021-44228"}
    assert result["total"] == 2
    assert tracker.failed == []


async def test_sync_refuses_a_shrunken_index(tracker: _Tracker) -> None:
    repo = _Repo({f"CVE-2020-{i:04d}": {} for i in range(10)})
    async with _client(_index()) as client:
        with pytest.raises(RuntimeError, match="refusing"):
            await NucleiTemplatesPipeline(client).sync(repo)
    assert repo.replaced is None
    assert tracker.failed


async def test_sync_fails_when_the_download_fails(tracker: _Tracker, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.services.http.retry.asyncio.sleep", _no_sleep)
    repo = _Repo({})
    async with _client("", status=404) as client:
        with pytest.raises(RuntimeError, match="downloaded"):
            await NucleiTemplatesPipeline(client).sync(repo)
    assert repo.replaced is None


async def _no_sleep(*_args: Any) -> None:
    return None


def test_rows_link_the_template() -> None:
    rows = exploit_signals.signals_from_documents({
        "CVE-2024-3400": {"nuclei": {"name": "PAN-OS", "severity": "critical",
                                     "path": "http/cves/2024/CVE-2024-3400.yaml", "protocol": "http"}},
        "CVE-2024-0001": {"updated_at": "x"},
    })
    assert rows == [{
        "source": "nuclei",
        "cveId": "CVE-2024-3400",
        "name": "PAN-OS",
        "severity": "critical",
        "protocol": "http",
        "url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2024/CVE-2024-3400.yaml",
    }]


def test_a_template_raises_exploit_maturity_to_poc() -> None:
    from app.schemas.vulnerability import VulnerabilityDetail

    base = {"vulnId": "CVE-2024-3400", "source": "NVD", "title": "t", "summary": "s", "ingestedAt": "2024-01-01T00:00:00Z"}
    plain = VulnerabilityDetail.model_validate(base)
    signalled = VulnerabilityDetail.model_validate({**base, "exploitSignals": [{"source": "nuclei"}]})
    assert AttackPathService._exploit_maturity(plain) == "unknown"
    assert AttackPathService._exploit_maturity(signalled) == "poc"
