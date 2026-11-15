"""OpenVEX in the manual import, and the VEX tools of the MCP server."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from app.mcp import auth as mcp_auth
from app.mcp.tools import vex as vex_tools
from app.services.vex_service import VexService

VEX_DIR = Path(__file__).resolve().parents[2] / "vex"
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"


class FakeFindingRepo:
    def __init__(self, hits: int = 1) -> None:
        self.hits = hits
        self.calls: list[dict[str, Any]] = []

    async def bulk_update_vex_by_vulnerability_ids(self, target_id: str, ids: list[str], status: str, **kwargs: Any) -> int:
        self.calls.append({"target_id": target_id, "ids": ids, "status": status, **kwargs})
        return self.hits

    async def bulk_update_vex_by_vulnerability(self, **kwargs: Any) -> int:
        self.calls.append(kwargs)
        return self.hits

    async def bulk_update_vex_by_ids(self, **kwargs: Any) -> int:
        self.calls.append(kwargs)
        return len(kwargs["finding_ids"])


def _openvex(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"@context": OPENVEX_CONTEXT, "statements": list(statements)}


# ---------------------------------------------------------------- import


async def test_openvex_is_imported_with_aliases() -> None:
    repo = FakeFindingRepo()
    document = _openvex({
        "vulnerability": {"name": "CVE-2026-1", "aliases": ["GHSA-aaaa-bbbb-cccc"]},
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "impact_statement": "Only the CLI uses it.",
    })

    result = await VexService(repo, None).import_vex_document(document, "t")  # type: ignore[arg-type]

    assert result == {"applied": 1, "skipped": 0, "not_found": 0, "format": "openvex"}
    call = repo.calls[0]
    assert call["ids"] == ["CVE-2026-1", "GHSA-aaaa-bbbb-cccc", "GHSA-AAAA-BBBB-CCCC"]
    assert call["status"] == "not_affected"
    assert call["package_names"] is None
    assert call["vex_justification"] == "vulnerable_code_not_in_execute_path"
    assert call["vex_detail"] == "Only the CLI uses it."
    assert call["vex_updated_by"] == "vex-import"


async def test_openvex_conflicts_are_scoped_to_packages_and_unknown_statuses_skipped() -> None:
    repo = FakeFindingRepo(hits=0)
    document = _openvex(
        {"vulnerability": {"name": "CVE-1"}, "status": "not_affected",
         "products": [{"@id": "pkg:oci/app", "subcomponents": [{"@id": "pkg:golang/github.com/a/skopeo@1"}]}]},
        {"vulnerability": {"name": "CVE-1"}, "status": "affected",
         "products": [{"@id": "pkg:oci/app", "subcomponents": [{"@id": "pkg:deb/debian/grype@2"}]}]},
        {"vulnerability": {"name": "CVE-2"}, "status": "exploitable"},
    )

    result = await VexService(repo, None).import_vex_document(document, "t")  # type: ignore[arg-type]

    assert result["skipped"] == 1
    assert result["not_found"] == 2
    assert [c["package_names"] for c in repo.calls] == [
        ["github.com/a/skopeo", "github.com/a:skopeo", "skopeo"],
        ["debian/grype", "debian:grype", "grype"],
    ]


async def test_repeated_openvex_statements_are_applied_once() -> None:
    repo = FakeFindingRepo()
    statement = {"vulnerability": {"name": "CVE-1"}, "status": "fixed",
                 "products": [{"@id": "pkg:npm/a@1"}]}
    other = {**statement, "products": [{"@id": "pkg:npm/b@1"}]}

    result = await VexService(repo, None).import_vex_document(_openvex(statement, other), "t")  # type: ignore[arg-type]

    assert result["applied"] == 1
    assert len(repo.calls) == 1


async def test_cyclonedx_still_goes_through_its_own_import() -> None:
    repo = FakeFindingRepo()
    document = {"vulnerabilities": [{"id": "CVE-1", "analysis": {"state": "resolved"}}]}

    result = await VexService(repo, None).import_vex_document(document, "t")  # type: ignore[arg-type]

    assert result["format"] == "cyclonedx"
    assert repo.calls[0]["vex_status"] == "fixed"


@pytest.mark.parametrize("document", [{}, {"statements": []}, {"@context": "x", "statements": "y"}])
async def test_a_document_in_neither_format_is_refused(document: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        await VexService(FakeFindingRepo(), None).import_vex_document(document, "t")  # type: ignore[arg-type]


@pytest.mark.skipif(not (VEX_DIR / "hecate-backend.openvex.json").exists(), reason="vex/ not present")
async def test_hecates_own_openvex_file_imports() -> None:
    repo = FakeFindingRepo()
    document = json.loads((VEX_DIR / "hecate-backend.openvex.json").read_text(encoding="utf-8"))

    result = await VexService(repo, None).import_vex_document(document, "t")  # type: ignore[arg-type]

    assert result["format"] == "openvex"
    assert repo.calls


# ---------------------------------------------------------------- MCP


class FakeTargetRepo:
    def __init__(self) -> None:
        self.sources: dict[str, list[str]] = {}

    async def set_vex_sources(self, target_id: str, urls: list[str]) -> bool:
        self.sources[target_id] = urls
        return True


class FakeScanService:
    def __init__(self) -> None:
        self.finding_repo = FakeFindingRepo()
        self.target_repo = FakeTargetRepo()
        self.scan_repo = None
        self.applied: list[str] = []

    async def resolve_target_id(self, raw: str) -> str | None:
        return "https://github.com/org/app" if "org/app" in raw else None

    async def apply_vex_sources(self, target_id: str) -> None:
        self.applied.append(target_id)

    async def get_target(self, target_id: str) -> dict[str, Any]:
        return {"_id": target_id, "vex_sources": self.target_repo.sources.get(target_id, [])}


class AllowAll:
    def check(self, _client: str) -> bool:
        return True


@pytest.fixture
def tools(monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, Any], FakeScanService]:
    service = FakeScanService()

    async def get_scan_service() -> FakeScanService:
        return service

    async def no_audit(**_kwargs: Any) -> None:
        return None

    monkeypatch.setattr("app.services.scan_service.get_scan_service", get_scan_service)
    monkeypatch.setattr(vex_tools, "log_tool_invocation", no_audit)
    monkeypatch.setattr(vex_tools, "get_rate_limiter", lambda: AllowAll())
    mcp = FastMCP("test")
    vex_tools.register(mcp)
    fns = {tool.name: tool.fn for tool in mcp._tool_manager.list_tools()}
    return fns, service


@pytest.fixture
def write_scope() -> Any:
    token = mcp_auth.mcp_token_scope.set("mcp:read mcp:write")
    yield
    mcp_auth.mcp_token_scope.reset(token)


def test_the_vex_tools_are_registered(tools: tuple[dict[str, Any], FakeScanService]) -> None:
    assert set(tools[0]) == {
        "set_finding_vex", "import_vex", "get_target_vex_sources",
        "set_target_vex_sources", "apply_target_vex_sources", "export_scan_vex",
    }


async def test_writes_need_the_write_scope(tools: tuple[dict[str, Any], FakeScanService]) -> None:
    fns, service = tools
    result = await fns["set_finding_vex"](status="not_affected", finding_ids=["a" * 24])
    assert "Write access denied" in result["error"]
    result = await fns["set_target_vex_sources"](target_id="org/app", urls=["https://example.com/v.json"])
    assert "Write access denied" in result["error"]
    assert service.finding_repo.calls == []
    assert service.target_repo.sources == {}


async def test_set_finding_vex_by_vulnerability_counts_as_set_by_hand(
    tools: tuple[dict[str, Any], FakeScanService], write_scope: None,
) -> None:
    fns, service = tools
    result = await fns["set_finding_vex"](
        status="not_affected", target_id="org/app", vulnerability_id="CVE-2026-1",
        justification="component_not_present", client_name="Claude",
    )
    assert result["updated"] == 1
    call = service.finding_repo.calls[0]
    assert call["target_id"] == "https://github.com/org/app"
    assert call["vex_updated_by"] == "Claude - MCP"
    assert call["vex_updated_by"] != "vex-source"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status": "exploitable", "finding_ids": ["x"]},
        {"status": "fixed"},
        {"status": "fixed", "finding_ids": ["x"], "target_id": "org/app", "vulnerability_id": "CVE-1"},
        {"status": None, "target_id": "org/app", "vulnerability_id": "CVE-1"},
        {"status": "fixed", "finding_ids": ["x"] * 501},
    ],
)
async def test_set_finding_vex_refuses_bad_input(
    tools: tuple[dict[str, Any], FakeScanService], write_scope: None, kwargs: dict[str, Any],
) -> None:
    fns, service = tools
    assert "error" in await fns["set_finding_vex"](**kwargs)
    assert service.finding_repo.calls == []


async def test_set_finding_vex_passes_the_review_date(
    tools: tuple[dict[str, Any], FakeScanService], write_scope: None,
) -> None:
    fns, service = tools
    result = await fns["set_finding_vex"](
        status="not_affected", finding_ids=["a" * 24], review_due="2027-03-01T00:00:00Z",
    )
    assert result["reviewDue"] == "2027-03-01"
    assert service.finding_repo.calls[0]["vex_review_due"] == "2027-03-01"
    await fns["set_finding_vex"](
        status="affected", target_id="org/app", vulnerability_id="CVE-2026-1", review_due="2027-04-02",
    )
    assert service.finding_repo.calls[1]["vex_review_due"] == "2027-04-02"


async def test_set_finding_vex_refuses_a_bad_review_date(
    tools: tuple[dict[str, Any], FakeScanService], write_scope: None,
) -> None:
    fns, service = tools
    result = await fns["set_finding_vex"](status="fixed", finding_ids=["a" * 24], review_due="next week")
    assert "review_due" in result["error"]
    assert service.finding_repo.calls == []


async def test_clearing_by_finding_ids_drops_the_actor(
    tools: tuple[dict[str, Any], FakeScanService], write_scope: None,
) -> None:
    fns, service = tools
    await fns["set_finding_vex"](status=None, finding_ids=["a" * 24], justification="x")
    call = service.finding_repo.calls[0]
    assert call["vex_status"] is None
    assert call["vex_justification"] is None
    assert call["vex_updated_by"] is None
    assert call["vex_review_due"] is None


async def test_import_vex_reads_openvex_given_as_a_string(
    tools: tuple[dict[str, Any], FakeScanService], write_scope: None,
) -> None:
    fns, service = tools
    document = json.dumps(_openvex({"vulnerability": {"name": "CVE-1"}, "status": "fixed"}))
    result = await fns["import_vex"](target_id="org/app", document=document)
    assert result["format"] == "openvex"
    assert result["applied"] == 1
    assert "error" in await fns["import_vex"](target_id="org/app", document="not json")
    assert "error" in await fns["import_vex"](target_id="unknown", document=document)


async def test_set_target_vex_sources_validates_and_applies(
    tools: tuple[dict[str, Any], FakeScanService], write_scope: None,
) -> None:
    fns, service = tools
    refused = await fns["set_target_vex_sources"](target_id="org/app", urls=["http://example.com/v.json"])
    assert "error" in refused

    result = await fns["set_target_vex_sources"](
        target_id="org/app",
        urls=["https://github.com/org/app/blob/main/vex/app.openvex.json"],
    )
    assert result["urls"] == ["https://raw.githubusercontent.com/org/app/main/vex/app.openvex.json"]
    assert service.applied == ["https://github.com/org/app"]
