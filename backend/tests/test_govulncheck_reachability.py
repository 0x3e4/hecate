"""govulncheck: parser, reachability summary and the VEX statements it backs.

The fixture is real ``govulncheck -json`` output (v1.9.0, trimmed OSV bodies)
for a module on golang.org/x/text v0.3.0 that calls the vulnerable UTF-16
decoder (GO-2020-0015), imports ``language`` without calling ``Parse``
(GO-2021-0113, GO-2022-1059) and requires the module for two more entries
whose packages it never imports (GO-2026-5970, GO-2026-6629). The scanner's
own stdlib entry (GO-2026-6859) must be ignored.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from app.repositories.scan_finding_repository import REACHABILITY_ACTOR_PREFIX as REPO_PREFIX
from app.schemas.scan import VALID_SCANNERS, normalize_scanners
from app.services.reachability import (
    GOVULNCHECK_ACTOR,
    REACHABILITY_ACTOR_PREFIX,
    apply_reachability_vex,
    plan_reachability_vex,
    summarize_govulncheck,
)
from app.services.scan_parser import parse_govulncheck_json

FIXTURE = Path(__file__).parent / "fixtures" / "govulncheck_sample.json"


@pytest.fixture
def report() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_scanner_is_valid_and_actor_prefix_shared() -> None:
    assert "govulncheck" in VALID_SCANNERS
    assert normalize_scanners(["govulncheck", "trivy", "govulncheck"]) == ["govulncheck", "trivy"]
    assert REACHABILITY_ACTOR_PREFIX == REPO_PREFIX
    assert GOVULNCHECK_ACTOR.startswith(REACHABILITY_ACTOR_PREFIX)


def test_summary_levels_and_stdlib_skipped(report: dict[str, Any]) -> None:
    summary = summarize_govulncheck(report)
    levels = {osv: entry.level for (osv, _module), entry in summary.entries.items()}
    assert levels == {
        "GO-2020-0015": "symbol",
        "GO-2021-0113": "package",
        "GO-2022-1059": "package",
        "GO-2026-5970": "module",
        "GO-2026-6629": "module",
    }
    assert all(module == "golang.org/x/text" for _osv, module in summary.entries)
    assert summary.complete is True


def test_parser_emits_only_called_vulnerabilities(report: dict[str, Any]) -> None:
    findings, summary = parse_govulncheck_json(report, "scan-1", "target-1")
    assert summary.total == 1
    (finding,) = findings
    assert finding.scanner == "govulncheck"
    assert finding.vulnerability_id == "CVE-2020-14040"
    assert finding.title and finding.title.startswith("GO-2020-0015")
    assert finding.package_name == "golang.org/x/text"
    assert finding.package_version == "v0.3.0"
    assert finding.fix_version == "v0.3.3"
    assert finding.package_path == "go.mod"
    assert "Reachable through:" in (finding.description or "")
    assert "utf16Decoder.Transform" in (finding.description or "")
    assert any("pkg.go.dev/vuln/GO-2020-0015" in url for url in finding.urls)


def test_primary_id_falls_back_to_ghsa_then_go_id(report: dict[str, Any]) -> None:
    data = copy.deepcopy(report)
    for message in data["modules"][0]["messages"]:
        if "osv" in message and message["osv"]["id"] == "GO-2020-0015":
            message["osv"]["aliases"] = ["GHSA-5rcv-m4m3-hfh7"]
    findings, _ = parse_govulncheck_json(data, "s", "t")
    assert findings[0].vulnerability_id == "GHSA-5rcv-m4m3-hfh7"
    for message in data["modules"][0]["messages"]:
        if "osv" in message and message["osv"]["id"] == "GO-2020-0015":
            message["osv"]["aliases"] = []
    findings, _ = parse_govulncheck_json(data, "s", "t")
    assert findings[0].vulnerability_id == "GO-2020-0015"


def _finding(fid: str, cve: str, **extra: Any) -> dict[str, Any]:
    return {
        "_id": fid, "scanner": "trivy", "vulnerability_id": cve, "package_name": "golang.org/x/text",
        "package_type": "gomod", "package_path": "go.mod", "vex_status": None, "vex_updated_by": None,
        **extra,
    }


def test_plan_sets_not_affected_for_uncalled_only(report: dict[str, Any]) -> None:
    summary = summarize_govulncheck(report)
    findings = [
        _finding("called", "CVE-2020-14040"),
        _finding("imported", "CVE-2021-38561"),
        _finding("required", "CVE-2026-56852"),
        _finding("ghsa", "GHSA-69CH-W2M2-3VJP"),
        _finding("other-module", "CVE-2021-38561", package_name="golang.org/x/net"),
        _finding("binary", "CVE-2021-38561", package_type="gobinary"),
        _finding("fixture", "CVE-2021-38561", package_path="internal/testdata/go.mod"),
        _finding("own-tool", "CVE-2021-38561", scanner="govulncheck"),
    ]
    to_set, to_clear = plan_reachability_vex(findings, summary)
    decided = {fid: justification for fid, justification, _detail in to_set}
    assert decided == {
        "imported": "vulnerable_code_not_in_execute_path",
        "ghsa": "vulnerable_code_not_in_execute_path",
        "required": "vulnerable_code_not_present",
    }
    detail = next(d for fid, _j, d in to_set if fid == "imported")
    assert "GO-2021-0113" in detail and "golang.org/x/text/language" in detail
    assert to_clear == []


@pytest.mark.parametrize("actor", ["user", "vex-import", "vex-source", "Claude - MCP", "carry-forward"])
def test_plan_never_touches_someone_elses_status(report: dict[str, Any], actor: str) -> None:
    summary = summarize_govulncheck(report)
    findings = [
        _finding("imported", "CVE-2021-38561", vex_status="affected", vex_updated_by=actor),
        _finding("called", "CVE-2020-14040", vex_status="not_affected", vex_updated_by=actor),
    ]
    assert plan_reachability_vex(findings, summary) == ([], [])


def test_plan_replaces_a_rule_status_but_never_clears_it(report: dict[str, Any]) -> None:
    summary = summarize_govulncheck(report)
    findings = [
        _finding("imported", "CVE-2021-38561", vex_status="affected", vex_updated_by="vex-rule:r1"),
        _finding("called", "CVE-2020-14040", vex_status="not_affected", vex_updated_by="vex-rule:r1"),
        _finding("gone", "CVE-2019-0001", vex_status="not_affected", vex_updated_by="vex-rule:r1"),
    ]
    to_set, to_clear = plan_reachability_vex(findings, summary)
    assert [fid for fid, _j, _d in to_set] == ["imported"]
    assert to_clear == []


def test_plan_clears_own_status_when_symbol_is_called_now(report: dict[str, Any]) -> None:
    summary = summarize_govulncheck(report)
    findings = [
        _finding("called", "CVE-2020-14040", vex_status="not_affected", vex_updated_by=GOVULNCHECK_ACTOR),
        _finding("imported", "CVE-2021-38561", vex_status="not_affected", vex_updated_by=GOVULNCHECK_ACTOR),
        _finding("gone", "CVE-2019-0001", vex_status="not_affected", vex_updated_by=GOVULNCHECK_ACTOR),
    ]
    to_set, to_clear = plan_reachability_vex(findings, summary)
    assert [fid for fid, _j, _d in to_set] == ["imported"]
    assert sorted(to_clear) == ["called", "gone"]


def test_incomplete_run_sets_nothing_and_keeps_own_statuses(report: dict[str, Any]) -> None:
    data = copy.deepcopy(report)
    data["modules"].append({"dir": "tools", "module": "example.com/tools", "messages": [], "error": "go: boom"})
    summary = summarize_govulncheck(data)
    assert summary.complete is False
    findings = [
        _finding("imported", "CVE-2021-38561"),
        _finding("kept", "CVE-2022-32149", vex_status="not_affected", vex_updated_by=GOVULNCHECK_ACTOR),
        _finding("called", "CVE-2020-14040", vex_status="not_affected", vex_updated_by=GOVULNCHECK_ACTOR),
        _finding("gone", "CVE-2019-0001", vex_status="not_affected", vex_updated_by=GOVULNCHECK_ACTOR),
    ]
    to_set, to_clear = plan_reachability_vex(findings, summary)
    assert to_set == []
    # The call is a positive answer even in a partial run.
    assert to_clear == ["called"]

    truncated = summarize_govulncheck({**report, "truncated": True})
    assert truncated.complete is False


# --- the database writer, against a small in-memory collection ---------------


class _Result:
    def __init__(self, n: int) -> None:
        self.modified_count = n


class FakeCollection:
    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self.docs = docs

    def find(self, query: dict[str, Any], projection: dict[str, Any] | None = None):
        docs = [dict(d) for d in self.docs if d["scan_id"] == query["scan_id"]]

        async def _gen():
            for doc in docs:
                yield doc

        return _gen()

    async def update_many(self, query: dict[str, Any], update: dict[str, Any]) -> _Result:
        ids = set(query["_id"]["$in"])
        n = 0
        for doc in self.docs:
            if doc["_id"] not in ids:
                continue
            actor = doc["vex_updated_by"] or ""
            if "$or" in query and not (
                doc["vex_status"] is None or actor == GOVULNCHECK_ACTOR or actor.startswith("vex-rule:")
            ):
                continue
            if "vex_updated_by" in query and doc["vex_updated_by"] != query["vex_updated_by"]:
                continue
            doc.update(update["$set"])
            n += 1
        return _Result(n)


async def test_apply_writes_and_clears_with_guard(report: dict[str, Any]) -> None:
    docs = [
        {**_finding("imported", "CVE-2021-38561"), "scan_id": "s1"},
        {**_finding("called", "CVE-2020-14040", vex_status="not_affected", vex_updated_by=GOVULNCHECK_ACTOR),
         "scan_id": "s1"},
        {**_finding("manual", "CVE-2022-32149", vex_status="affected", vex_updated_by="user"), "scan_id": "s1"},
        {**_finding("ruled", "CVE-2022-32149", vex_status="affected", vex_updated_by="vex-rule:r1",
                    package_path="tools/go.mod"), "scan_id": "s1"},
        {**_finding("other-scan", "CVE-2021-38561"), "scan_id": "s2"},
    ]
    collection = FakeCollection(docs)
    result = await apply_reachability_vex(collection, "s1", summarize_govulncheck(report))
    assert result == {"applied": 2, "cleared": 1}
    by_id = {d["_id"]: d for d in docs}
    assert by_id["imported"]["vex_status"] == "not_affected"
    assert by_id["imported"]["vex_updated_by"] == GOVULNCHECK_ACTOR
    assert by_id["imported"]["vex_justification"] == "vulnerable_code_not_in_execute_path"
    assert by_id["called"]["vex_status"] is None and by_id["called"]["vex_updated_by"] is None
    assert by_id["manual"]["vex_status"] == "affected"
    assert by_id["ruled"]["vex_status"] == "not_affected"
    assert by_id["ruled"]["vex_updated_by"] == GOVULNCHECK_ACTOR
    assert by_id["other-scan"]["vex_status"] is None
