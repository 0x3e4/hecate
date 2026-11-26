"""MCP tools for inventory systems, against the in-memory system service (conftest)."""
from __future__ import annotations

from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from app.mcp import auth as mcp_auth
from app.mcp.tools import inventory as inventory_tools
from app.mcp.tools import inventory_systems as system_tools
from app.services.inventory_system_service import get_inventory_system_service


class AllowAll:
    def check(self, _client: str) -> bool:
        return True


@pytest.fixture
def audit(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    async def record(**kwargs: Any) -> None:
        calls.append(kwargs)

    for module in (system_tools, inventory_tools):
        monkeypatch.setattr(module, "log_tool_invocation", record)
        monkeypatch.setattr(module, "get_rate_limiter", lambda: AllowAll())
    return calls


@pytest.fixture
def fns(audit: list[dict[str, Any]]) -> dict[str, Any]:
    mcp = FastMCP("test")
    system_tools.register(mcp)
    inventory_tools.register(mcp)
    return {tool.name: tool.fn for tool in mcp._tool_manager.list_tools()}


@pytest.fixture
def write_scope() -> Any:
    token = mcp_auth.mcp_token_scope.set("mcp:read mcp:write")
    yield
    mcp_auth.mcp_token_scope.reset(token)


LIST = "[web]\nweb-01.example.com\nweb-02.example.com\n[db]\ndb-01.example.com hecate_kind=host\n[all:vars]\nhecate_environment=prod\n"


def test_the_system_tools_are_registered(fns: dict[str, Any]) -> None:
    assert {
        "list_inventory_systems", "get_inventory_system", "create_inventory_system",
        "update_inventory_system", "delete_inventory_system", "import_inventory_system_list",
    } <= set(fns)


async def test_writes_need_the_write_scope(fns: dict[str, Any]) -> None:
    for name, kwargs in (
        ("create_inventory_system", {"name": "web-01"}),
        ("update_inventory_system", {"system": "web-01", "owner": "ops"}),
        ("delete_inventory_system", {"system": "web-01"}),
        ("import_inventory_system_list", {"content": LIST, "dry_run": False}),
    ):
        result = await fns[name](**kwargs)
        assert "Write access denied" in result["error"], name
    assert (await get_inventory_system_service().list_systems()).total == 0


async def test_create_get_by_name_update_and_delete(fns: dict[str, Any], write_scope: None) -> None:
    created = await fns["create_inventory_system"](
        name="web-01.example.com", kind="host", exposure="internet", groups=["edge", "Edge", "vienna"],
    )
    assert created["kind"] == "host" and created["groups"] == ["edge", "vienna"]
    assert created["reportStatus"] == "never"

    taken = await fns["create_inventory_system"](name="WEB-01.example.com")
    assert "already exists" in taken["error"]
    bad = await fns["create_inventory_system"](name="x", kind="mainframe")
    assert bad["error"].startswith("Failed to create the system: kind:")

    fetched = await fns["get_inventory_system"](system="Web-01.Example.com")
    assert fetched["id"] == created["id"]
    assert (await fns["get_inventory_system"](system=created["id"]))["name"] == "web-01.example.com"
    assert (await fns["get_inventory_system"](system="nope"))["error"] == "System not found."

    updated = await fns["update_inventory_system"](system="web-01.example.com", owner="ops", exposure="")
    assert updated["owner"] == "ops" and updated["exposure"] is None and updated["kind"] == "host"
    assert (await fns["update_inventory_system"](system="web-01.example.com"))["error"] == "No fields to update."

    deleted = await fns["delete_inventory_system"](system="web-01.example.com")
    assert deleted == {"deleted": True, "systemId": created["id"], "name": "web-01.example.com"}
    assert (await fns["delete_inventory_system"](system="web-01.example.com"))["error"] == "System not found."


async def test_list_filters(fns: dict[str, Any], write_scope: None) -> None:
    await fns["create_inventory_system"](name="web-01", kind="host", exposure="internet", groups=["edge"])
    await fns["create_inventory_system"](name="node-1", kind="kubernetes-node", owner="platform team")
    await fns["create_inventory_system"](name="db-01", kind="host", notes="primary database")

    everything = await fns["list_inventory_systems"]()
    assert everything["total"] == 3 and everything["staleAfterDays"] >= 1
    names = lambda r: sorted(s["name"] for s in r["items"])  # noqa: E731
    assert names(await fns["list_inventory_systems"](kind="host")) == ["db-01", "web-01"]
    assert names(await fns["list_inventory_systems"](exposure="internet")) == ["web-01"]
    assert names(await fns["list_inventory_systems"](group="EDGE")) == ["web-01"]
    assert names(await fns["list_inventory_systems"](search="platform")) == ["node-1"]
    assert names(await fns["list_inventory_systems"](search="database")) == ["db-01"]
    assert (await fns["list_inventory_systems"](report_status="stale"))["total"] == 0
    assert "report_status" in (await fns["list_inventory_systems"](report_status="late"))["error"]
    limited = await fns["list_inventory_systems"](limit=1)
    assert limited["total"] == 3 and len(limited["items"]) == 1


async def test_list_import_previews_by_default_then_applies(
    fns: dict[str, Any], write_scope: None, audit: list[dict[str, Any]],
) -> None:
    preview = await fns["import_inventory_system_list"](content=LIST, source="ansible")
    assert preview["dryRun"] is True and preview["createdCount"] == 3
    assert (await get_inventory_system_service().list_systems()).total == 0
    # The audit entry describes the list, never carries it.
    assert audit[-1]["inputs"]["content_chars"] == len(LIST) and "content" not in audit[-1]["inputs"]

    applied = await fns["import_inventory_system_list"](content=LIST, source="ansible", dry_run=False)
    assert applied["createdCount"] == 3 and applied["format"] == "ansible-ini"
    db = await fns["get_inventory_system"](system="db-01.example.com")
    assert db["kind"] == "host" and db["environment"] == "prod" and db["listSources"] == ["ansible"]

    shrunk = "[web]\nweb-01.example.com\n"
    refused = await fns["import_inventory_system_list"](content=shrunk, source="ansible", mode="replace", dry_run=False)
    assert "would retire 2 of the 3" in refused["error"]
    assert (await fns["list_inventory_systems"]())["total"] == 3

    forced = await fns["import_inventory_system_list"](
        content=shrunk, source="ansible", mode="replace", dry_run=False, force=True,
    )
    assert forced["retiredCount"] == 2
    assert (await fns["list_inventory_systems"]())["total"] == 1
    assert (await fns["list_inventory_systems"](include_retired=True))["total"] == 3


async def test_list_import_refuses_bad_input(fns: dict[str, Any], write_scope: None) -> None:
    assert "source" in (await fns["import_inventory_system_list"](content=LIST, source="-bad"))["error"]
    assert "mode" in (await fns["import_inventory_system_list"](content=LIST, mode="wipe"))["error"]
    broken = await fns["import_inventory_system_list"](content="{not json", format="json")
    assert broken["error"].startswith("Not a server list:")


class FakeInventoryService:
    def __init__(self) -> None:
        self.created: list[Any] = []
        self.updated: list[Any] = []

    async def create_item(self, payload: Any, **_kwargs: Any) -> Any:
        self.created.append(payload)
        return payload

    async def update_item(self, item_id: str, payload: Any, **_kwargs: Any) -> Any:
        self.updated.append(payload)
        return payload


async def test_inventory_items_link_systems_by_name(
    fns: dict[str, Any], write_scope: None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeInventoryService()

    async def get_inventory_service() -> FakeInventoryService:
        return fake

    monkeypatch.setattr("app.services.inventory_service.get_inventory_service", get_inventory_service)
    web = await fns["create_inventory_system"](name="web-01")
    db = await fns["create_inventory_system"](name="db-01")

    await fns["create_inventory_item"](
        name="nginx", vendor_slug="f5", product_slug="nginx", version="1.27.4", systems=["WEB-01", db["id"], "web-01"],
    )
    assert fake.created[-1].system_ids == [web["id"], db["id"]]

    unknown = await fns["update_inventory_item"](item_id="i1", systems=["web-01", "ghost"])
    assert unknown == {"error": "No system named 'ghost'."}
    assert fake.updated == []

    await fns["update_inventory_item"](item_id="i1", systems=[])
    assert fake.updated[-1].system_ids == []
