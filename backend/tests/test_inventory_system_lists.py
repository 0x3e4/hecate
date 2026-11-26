"""Server lists for inventory systems: the formats, applying them, and the push gate."""
from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core import auth_throttle, write_auth
from app.core.config import settings
from app.services import inventory_system_service as system_module
from app.services.inventory_system_lists import (
    ListError,
    detect_list_format,
    expand_host_pattern,
    parse_system_list,
)
from app.services.inventory_system_service import ListTooDestructive

from tests.test_inventory_systems import _service, _target

INI = """
# production
[web]
web[01:03].example.com ansible_host=10.0.0.1 hecate_exposure=internet
[db]
db-01.example.com hecate_owner="dba team" hecate_kind=router

[nodes]
node-[a:b]
[nodes:vars]
hecate_kind=kubernetes-node

[prod:children]
web
db
[prod:vars]
hecate_environment=prod
hecate_kind=host
"""

YAML = """
all:
  vars:
    hecate_kind: host
  children:
    web:
      hosts:
        web-01.example.com:
          hecate_exposure: internet
        web-02.example.com:
    k8s:
      vars:
        hecate_kind: kubernetes-node
      hosts:
        node-[1:2]:
"""

ANSIBLE_JSON = json.dumps({
    "_meta": {"hostvars": {"web-01": {"hecate_exposure": "internet", "ansible_host": "10.0.0.1"}}},
    "all": {"children": ["ungrouped", "web"]},
    "web": {"hosts": ["web-01", "web-02"], "vars": {"hecate_kind": "host"}},
    "ungrouped": {"hosts": ["lonely"]},
})


def _by_name(content: str, fmt: str | None = None) -> dict[str, Any]:
    return {s.name: s for s in parse_system_list(content, fmt).systems}


@pytest.mark.parametrize(
    ("content", "fmt"),
    [
        (INI, "ansible-ini"),
        (YAML, "ansible-yaml"),
        (ANSIBLE_JSON, "ansible-json"),
        ("hostname,kind\nweb-01,host\n", "csv"),
        ("web-01\nweb-02\n", "text"),
        ('{"systems": [{"name": "web-01"}]}', "json"),
        ('[{"name": "web-01"}]', "json"),
        ("web-01 ansible_host=10.0.0.1\n", "ansible-ini"),
    ],
)
def test_formats_are_detected(content: str, fmt: str) -> None:
    assert detect_list_format(content) == fmt


def test_ini_groups_children_vars_and_ranges() -> None:
    systems = _by_name(INI)
    assert sorted(systems) == [
        "db-01.example.com", "node-a", "node-b", "web01.example.com", "web02.example.com", "web03.example.com",
    ]
    web = systems["web02.example.com"]
    assert web.groups == ["prod", "web"]
    assert web.fields == {"kind": "host", "exposure": "internet", "environment": "prod"}
    # An invalid host value is reported; the group's value stays.
    db = systems["db-01.example.com"]
    assert db.fields == {"kind": "host", "environment": "prod", "owner": "dba team"}
    assert any("router" in s["reason"] for s in parse_system_list(INI).skipped)
    assert systems["node-a"].fields == {"kind": "kubernetes-node"}


def test_yaml_and_ansible_inventory_json() -> None:
    yaml_systems = _by_name(YAML)
    assert yaml_systems["web-01.example.com"].fields == {"kind": "host", "exposure": "internet"}
    assert yaml_systems["node-2"].fields == {"kind": "kubernetes-node"} and yaml_systems["node-2"].groups == ["k8s"]
    json_systems = _by_name(ANSIBLE_JSON)
    assert json_systems["web-01"].fields == {"kind": "host", "exposure": "internet"}
    assert json_systems["lonely"].groups == []  # "ungrouped" and "all" are no groups


def test_csv_text_and_hecate_json() -> None:
    csv_systems = _by_name("Hostname,Kind,Exposure,Env,Groups,Owner\nweb-01,HOST,internet,prod,dmz;shop,ops\nWEB-01,,,,eu,\n,,,,,\n")
    assert list(csv_systems) == ["web-01"]
    assert csv_systems["web-01"].groups == ["dmz", "shop", "eu"]
    assert csv_systems["web-01"].fields == {"kind": "host", "exposure": "internet", "environment": "prod", "owner": "ops"}
    parsed = parse_system_list("web-01\n# comment\nweb-02  # why\nnot one name\n")
    assert [s.name for s in parsed.systems] == ["web-01", "web-02"] and parsed.skipped[0]["where"] == "line 4"
    backup_rows = {"systems": [{"id": "x", "name": "db", "kind": "host", "groups": ["a"], "source": "manual"}, {"name": ""}]}
    hecate = parse_system_list(json.dumps(backup_rows))
    assert hecate.systems[0].fields == {"kind": "host"} and hecate.skipped[0]["where"] == "entry 2"


@pytest.mark.parametrize(
    ("content", "fmt", "message"),
    [
        ("kind\nhost\n", "csv", "name column"),
        ("all: [", "ansible-yaml", "YAML"),
        ("{", "json", "JSON"),
        ("x", "nessus", "Unknown format"),
    ],
)
def test_unreadable_lists_are_refused(content: str, fmt: str, message: str) -> None:
    with pytest.raises(ListError, match=message):
        parse_system_list(content, fmt)


def test_ranges_are_bounded() -> None:
    assert expand_host_pattern("web[08:10]") == ["web08", "web09", "web10"]
    assert expand_host_pattern("rack[a:b]-[1:2]") == ["racka-1", "racka-2", "rackb-1", "rackb-2"]
    assert len(expand_host_pattern("h[0:999999]", budget=50)) == 50


def test_yaml_is_read_safely() -> None:
    with pytest.raises(ListError):
        parse_system_list("!!python/object/apply:os.system ['echo pwned']", "ansible-yaml")


# ---------------------------------------------------------------- applying a list


async def test_merge_adds_updates_and_links_an_existing_target() -> None:
    svc = _service([_target("sbom-import-web01.example.com", kind="host")])
    await svc.create_system(__import__("app.schemas.inventory_system", fromlist=["x"]).InventorySystemCreateRequest(
        name="db-01.example.com", owner="old",
    ))
    result = await svc.apply_list(parse_system_list(INI), source="ansible-prod", mode="merge")
    assert result.created_count == 5 and result.updated == ["db-01.example.com"] and result.retired == []
    docs = {d["name"]: d for d in (await svc.repo()).collection.docs}
    assert docs["db-01.example.com"]["owner"] == "dba team" and docs["db-01.example.com"]["groups"] == ["db", "prod"]
    assert docs["web02.example.com"]["source"] == "list" and docs["web02.example.com"]["list_sources"] == ["ansible-prod"]
    # The host that pushed before the list named it is linked right away.
    assert docs["web01.example.com"]["target_id"] == "sbom-import-web01.example.com"
    again = await svc.apply_list(parse_system_list(INI), source="ansible-prod", mode="merge")
    assert (again.created_count, again.updated_count, again.unchanged_count) == (0, 0, 6)


async def test_replace_retires_only_what_this_source_dropped() -> None:
    svc = _service()
    await svc.apply_list(parse_system_list("a\nb\nc\nd\n"), source="cmdb", mode="replace")
    await svc.apply_list(parse_system_list("d\ne\n"), source="ansible", mode="replace")
    manual = (await svc.create_system(__import__("app.schemas.inventory_system", fromlist=["x"]).InventorySystemCreateRequest(name="m"))).id

    result = await svc.apply_list(parse_system_list("a\nb\nc\n"), source="cmdb", mode="replace")
    docs = {d["name"]: d for d in (await svc.repo()).collection.docs}
    # d is still on the ansible list: it only leaves the cmdb list.
    assert result.retired == [] and docs["d"]["list_sources"] == ["ansible"] and "retired_at" not in docs["d"]

    result = await svc.apply_list(parse_system_list("e\n"), source="ansible", mode="replace")
    docs = {d["name"]: d for d in (await svc.repo()).collection.docs}
    assert result.retired == ["d"] and docs["d"]["retired_at"] is not None
    assert "retired_at" not in docs["m"] and docs["m"]["_id"] == manual

    # Named again: back.
    back = await svc.apply_list(parse_system_list("d\ne\n"), source="ansible", mode="replace")
    assert back.restored == ["d"]
    assert "retired_at" not in next(d for d in (await svc.repo()).collection.docs if d["name"] == "d")


async def test_a_replace_that_would_empty_the_fleet_needs_force() -> None:
    svc = _service()
    await svc.apply_list(parse_system_list("a\nb\nc\nd\n"), source="cmdb", mode="replace")
    with pytest.raises(ListTooDestructive):
        await svc.apply_list(parse_system_list("a\n"), source="cmdb", mode="replace")
    result = await svc.apply_list(parse_system_list("a\n"), source="cmdb", mode="replace", force=True)
    assert sorted(result.retired) == ["b", "c", "d"]


async def test_a_dry_run_writes_nothing() -> None:
    svc = _service()
    result = await svc.apply_list(parse_system_list(YAML), source="x", mode="replace", dry_run=True)
    assert result.created_count == 4 and result.dry_run
    assert (await svc.repo()).collection.docs == []


async def test_a_push_brings_a_retired_system_back() -> None:
    svc = _service([_target("sbom-import-a", kind="host")])
    await svc.apply_list(parse_system_list("a\nb\nc\n"), source="cmdb", mode="replace")
    await svc.apply_list(parse_system_list("b\nc\n"), source="cmdb", mode="replace")
    assert next(d for d in (await svc.repo()).collection.docs if d["name"] == "a").get("retired_at")
    await svc.link_import("sbom-import-a", "a", None, None)
    doc = next(d for d in (await svc.repo()).collection.docs if d["name"] == "a")
    assert "retired_at" not in doc and doc["target_id"] == "sbom-import-a"


async def test_list_classification_reaches_the_linked_target() -> None:
    svc = _service([_target("sbom-import-web-01")])
    await svc.link_import("sbom-import-web-01", "web-01", "host", None)
    await svc.apply_list(parse_system_list("name,exposure\nweb-01,internet\n"), source="csv", mode="merge")
    assert (await svc.target_repo()).collection.docs[0]["exposure"] == "internet"


# ---------------------------------------------------------------- the push gate


PASSWORD = "admin-password"


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    from app.api.v1 import inventory_systems
    from app.services.api_token_service import ApiTokenService
    from tests.test_api_tokens import FakeRepo

    tokens = ApiTokenService(FakeRepo())  # type: ignore[arg-type]

    async def get_tokens() -> ApiTokenService:
        return tokens

    svc = _service()
    monkeypatch.setattr(system_module, "_service", svc)
    monkeypatch.setattr(write_auth, "get_api_token_service", get_tokens)
    monkeypatch.setattr(settings, "system_password", PASSWORD)
    monkeypatch.setattr(auth_throttle, "_throttle", auth_throttle.AuthThrottle())
    app = FastAPI()
    app.include_router(inventory_systems.sync_router, prefix="/inventory/systems")
    return TestClient(app), tokens, svc


async def _token(tokens: Any, *scopes: str) -> str:
    from app.schemas.api_token import ApiTokenCreateRequest

    return (await tokens.create_token(ApiTokenCreateRequest(name="ansible", scopes=list(scopes)))).token


async def test_push_with_a_sync_token(client) -> None:
    http, tokens, svc = client
    sync = await _token(tokens, "inventory:sync")
    other = await _token(tokens, "sbom:import")

    body = {"content": INI, "source": "ansible-prod", "mode": "replace"}
    assert http.post("/inventory/systems/import", json=body, headers={"X-API-Key": other}).status_code == 403
    assert http.post("/inventory/systems/import", json=body, headers={"X-API-Key": "hct_" + "x" * 43}).status_code == 401
    assert http.post("/inventory/systems/import", json=body).status_code == 401  # no session, wrong/no password

    preview = http.post("/inventory/systems/import", json={**body, "dryRun": True}, headers={"X-API-Key": sync})
    assert preview.status_code == 200 and preview.json()["createdCount"] == 6 and (await svc.repo()).collection.docs == []
    applied = http.post("/inventory/systems/import", json=body, headers={"X-API-Key": sync}).json()
    assert applied["format"] == "ansible-ini" and applied["createdCount"] == 6 and applied["skipped"]

    upload = http.post(
        "/inventory/systems/import/upload?source=ansible-prod&mode=replace",
        files={"file": ("hosts.ini", "[web]\nweb01.example.com\n")}, headers={"X-API-Key": sync},
    )
    assert upload.status_code == 409  # five of six would go
    forced = http.post(
        "/inventory/systems/import/upload?source=ansible-prod&mode=replace&force=true",
        files={"file": ("hosts.ini", "[web]\nweb01.example.com\n")}, headers={"X-API-Key": sync},
    )
    assert forced.status_code == 200 and forced.json()["retiredCount"] == 5

    assert http.post("/inventory/systems/import", json={"content": "x", "format": "nessus"},
                     headers={"X-API-Key": sync}).status_code == 422
    assert http.post("/inventory/systems/import", json={"content": "kind\nhost\n", "format": "csv"},
                     headers={"X-API-Key": sync}).status_code == 400
    assert http.post("/inventory/systems/import", json={"content": "a", "source": "../x"},
                     headers={"X-API-Key": sync}).status_code == 422
    assert http.post("/inventory/systems/import", json={"content": "a"},
                     headers={"X-System-Password": PASSWORD}).status_code == 200
