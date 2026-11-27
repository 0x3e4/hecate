"""Server lists Hecate fetches itself: URL checks, the fetcher, applying, scheduling and the admin gate."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core import auth_throttle
from app.core.config import settings
from app.repositories.inventory_list_source_repository import InventoryListSourceRepository, ListSourceTaken
from app.schemas.inventory_system import InventoryListSourceCreateRequest, InventoryListSourceUpdateRequest
from app.services import inventory_list_source_service as module
from app.services.inventory_list_source_service import (
    MAX_LIST_SOURCES,
    InventoryListSourceService,
    ListFetchError,
    check_url,
    fetch_list,
    next_run_at,
)

from tests.fake_mongo import FakeCollection
from tests.test_inventory_systems import _service

INI = "[web]\nweb-01\nweb-02\nweb-03\n[db]\ndb-01 hecate_kind=host\n"


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def record_event(self, job_name: str, **kwargs: Any) -> None:
        self.events.append({"job": job_name, **kwargs})


@pytest.fixture(autouse=True)
def _public_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    async def public(url: str) -> bool:
        return "internal" not in url

    monkeypatch.setattr(module, "is_public_url", public)
    monkeypatch.setattr(settings, "inventory_list_sources_allow_private_hosts", False)


def _sources(fetch_answers: list[Any] | None = None):
    """A service with an in-memory store, systems service and audit; the fetcher answers in turn."""
    answers = list(fetch_answers or [])
    calls: list[tuple[str, Any]] = []
    audit = FakeAudit()
    failures: list[tuple[str, str]] = []

    async def fetcher(url: str, header: Any) -> str:
        calls.append((url, header))
        answer = answers.pop(0) if len(answers) > 1 else answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer

    async def audit_factory() -> FakeAudit:
        return audit

    async def notify(source: str, error: str) -> None:
        failures.append((source, error))

    systems = _service()
    svc = InventoryListSourceService(
        InventoryListSourceRepository(FakeCollection(unique=("source_key",))),
        systems,
        fetcher=fetcher,
        audit_factory=audit_factory,
        notify_failed=notify,
    )
    return svc, systems, calls, audit, failures


def _create(**fields: Any) -> InventoryListSourceCreateRequest:
    return InventoryListSourceCreateRequest(**{"source": "cmdb", "url": "https://cmdb.example.com/hosts.ini", **fields})


# ---------------------------------------------------------------- URLs


@pytest.mark.parametrize(
    ("url", "credential", "error"),
    [
        ("https://cmdb.example.com/x", True, None),
        ("http://cmdb.example.com/x", False, None),
        ("http://cmdb.example.com/x", True, "only sent over https"),
        ("ftp://cmdb.example.com/x", False, "http(s)"),
        ("https:///x", False, "http(s)"),
        ("https://user:pw@cmdb.example.com/x", False, "header field"),
        ("file:///etc/passwd", False, "http(s)"),
        ("https://10.0.0.1\x00.cmdb.example.com/x", False, "control characters"),
        ("https://cmdb.example.com/x\ty", False, "control characters"),
    ],
)
def test_check_url(url: str, credential: bool, error: str | None) -> None:
    if error is None:
        assert check_url(url, with_credential=credential) == url
    else:
        with pytest.raises(ValueError, match=error.replace("(", r"\(").replace(")", r"\)")):
            check_url(url, with_credential=credential)


# ---------------------------------------------------------------- the fetcher


@pytest.fixture
def transport(monkeypatch: pytest.MonkeyPatch):
    """Route fetch_list's httpx client through a handler the test sets."""
    state: dict[str, Any] = {}
    real = httpx.AsyncClient

    def client(**kwargs: Any) -> httpx.AsyncClient:
        state["kwargs"] = kwargs
        return real(transport=httpx.MockTransport(state["handler"]), **kwargs)

    monkeypatch.setattr(module.httpx, "AsyncClient", client)
    return state


async def test_fetch_sends_the_credential_and_reads_text(transport) -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, content="﻿web-01\n".encode())

    transport["handler"] = handler
    assert await fetch_list("https://cmdb.example.com/x", ("Authorization", "Token abc")) == "web-01\n"
    assert seen["authorization"] == "Token abc"
    assert transport["kwargs"]["follow_redirects"] is False


@pytest.mark.parametrize(
    ("response", "kind"),
    [
        (httpx.Response(302, headers={"Location": "http://169.254.169.254/"}), "redirect"),
        (httpx.Response(401), "http_status"),
        (httpx.Response(200, content=b"\xff\xfe\x00bad"), "not_text"),
        (httpx.Response(200, content=b"x" * (5 * 1024 * 1024 + 1)), "too_large"),
    ],
)
async def test_fetch_failures(transport, response: httpx.Response, kind: str) -> None:
    transport["handler"] = lambda request: response
    with pytest.raises(ListFetchError) as exc:
        await fetch_list("https://cmdb.example.com/x", None)
    assert exc.value.kind == kind


async def test_fetch_refuses_private_hosts_unless_allowed(transport, monkeypatch: pytest.MonkeyPatch) -> None:
    transport["handler"] = lambda request: httpx.Response(200, content=b"web-01\n")
    with pytest.raises(ListFetchError) as exc:
        await fetch_list("https://cmdb.internal/x", None)
    assert exc.value.kind == "not_public"
    monkeypatch.setattr(settings, "inventory_list_sources_allow_private_hosts", True)
    assert await fetch_list("https://cmdb.internal/x", None) == "web-01\n"


async def test_fetch_network_error(transport) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    transport["handler"] = handler
    with pytest.raises(ListFetchError) as exc:
        await fetch_list("https://cmdb.example.com/x", None)
    assert exc.value.kind == "network" and "refused" not in exc.value.message


# ---------------------------------------------------------------- managing sources


async def test_create_update_and_never_return_the_credential() -> None:
    svc, *_ = _sources(["web-01"])
    created = await svc.create_source(_create(
        url="https://cmdb.example.com/api/hosts?token=s3cret&site=vie", authHeaderName="X-API-Key", authHeaderValue=" k3y ",
    ))
    dumped = created.model_dump_json(by_alias=True)
    assert "k3y" not in dumped and "s3cret" not in dumped
    assert created.auth_set and created.auth_header_name == "X-API-Key" and "site=vie" in created.url
    doc = await svc.repository.get(created.id)
    assert doc["auth_header_value"] == "k3y" and doc["url"].endswith("token=s3cret&site=vie")

    with pytest.raises(ListSourceTaken):
        await svc.create_source(_create(source="CMDB"))

    # Sending the masked URL back unchanged would be a change; the UI sends url only when edited.
    kept = await svc.update_source(created.id, InventoryListSourceUpdateRequest(mode="replace", intervalMinutes=30))
    assert kept.mode == "replace" and kept.interval_minutes == 30 and kept.auth_set
    assert (await svc.repository.get(created.id))["url"].endswith("token=s3cret&site=vie")

    cleared = await svc.update_source(created.id, InventoryListSourceUpdateRequest(authHeaderValue=""))
    assert not cleared.auth_set and cleared.auth_header_name is None

    with pytest.raises(ValueError, match="https"):
        await svc.update_source(created.id, InventoryListSourceUpdateRequest(url="http://cmdb.example.com/x", authHeaderValue="t"))
    assert await svc.update_source("nope", InventoryListSourceUpdateRequest(enabled=False)) is None


async def test_create_refuses_private_hosts_and_too_many(monkeypatch: pytest.MonkeyPatch) -> None:
    svc, *_ = _sources(["web-01"])
    with pytest.raises(ValueError, match="public address"):
        await svc.create_source(_create(url="https://netbox.internal/api"))
    with pytest.raises(ValueError, match="only sent over https"):
        await svc.create_source(_create(url="http://cmdb.example.com/x", authHeaderValue="Token a"))
    monkeypatch.setattr(settings, "inventory_list_sources_allow_private_hosts", True)
    await svc.create_source(_create(url="http://netbox.internal/api"))
    for i in range(1, MAX_LIST_SOURCES):
        await svc.create_source(_create(source=f"s{i}"))
    with pytest.raises(ValueError, match="At most"):
        await svc.create_source(_create(source="one-more"))


# ---------------------------------------------------------------- fetching and applying


async def test_pull_applies_under_the_source_name_and_keeps_the_state() -> None:
    svc, systems, calls, audit, _ = _sources([INI])
    source = await svc.create_source(_create(authHeaderValue="Token a"))

    preview = await svc.pull(source.id, dry_run=True)
    assert preview.ok and preview.result.created_count == 4 and preview.result.dry_run
    assert (await systems.repo()).collection.docs == [] and (await svc.repository.get(source.id)).get("last_run_at") is None
    assert calls[0] == ("https://cmdb.example.com/hosts.ini", ("Authorization", "Token a"))

    applied = await svc.pull(source.id)
    assert applied.ok and applied.source.last_status == "ok" and applied.source.last_result.created_count == 4
    names = {doc["name"]: doc for doc in (await systems.repo()).collection.docs}
    assert set(names) == {"web-01", "web-02", "web-03", "db-01"}
    assert names["db-01"]["list_sources"] == ["cmdb"] and names["db-01"]["kind"] == "host"
    assert audit.events[-1]["job"] == "inventory_list_pulled" and audit.events[-1]["status"] == "completed"
    assert "Token a" not in repr(audit.events)


async def test_a_broken_answer_applies_nothing() -> None:
    svc, systems, _, audit, _ = _sources([INI])
    source = await svc.create_source(_create(mode="replace"))
    await svc.pull(source.id)

    svc.fetcher = _answer("[web]\nweb-01\n")  # three of four would be retired
    refused = await svc.pull(source.id)
    assert not refused.ok and refused.error_kind == "too_destructive"
    assert refused.source.last_status == "error" and refused.source.last_result.created_count == 4  # last good kept
    assert not any(doc.get("retired_at") for doc in (await systems.repo()).collection.docs)

    forced = await svc.pull(source.id, force=True)
    assert forced.ok and forced.result.retired_count == 3

    svc.fetcher = _answer("kind\nhost\n")  # a CSV without a name column
    await svc.repository.update(source.id, {"format": "csv"})
    bad = await svc.pull(source.id)
    assert not bad.ok and bad.error_kind == "invalid_list"

    svc.fetcher = _answer("")  # an empty export: in replace mode the guard holds
    empty = await svc.pull(source.id)
    assert not empty.ok and empty.error_kind in {"invalid_list", "too_destructive"}

    svc.fetcher = _raise(ListFetchError("http_status", "The server answered HTTP 503."))
    down = await svc.pull(source.id)
    assert down.error == "The server answered HTTP 503." and down.source.last_error_kind == "http_status"


def _answer(text: str):
    async def fetcher(url: str, header: Any) -> str:
        return text

    return fetcher


def _raise(exc: Exception):
    async def fetcher(url: str, header: Any) -> str:
        raise exc

    return fetcher


async def test_scheduled_pulls_audit_changes_and_the_first_failure_only() -> None:
    svc, _, _, audit, failures = _sources([INI])
    source = await svc.create_source(_create())

    await svc.pull(source.id, scheduled=True)
    await svc.pull(source.id, scheduled=True)  # nothing changed: no audit line
    assert [e["status"] for e in audit.events] == ["completed"]

    svc.fetcher = _raise(ListFetchError("network", "The request failed (ConnectError)."))
    await svc.pull(source.id, scheduled=True)
    await svc.pull(source.id, scheduled=True)  # still failing: no second line, no second notification
    assert [e["status"] for e in audit.events] == ["completed", "failed"]
    assert failures == [("cmdb", "The request failed (ConnectError).")]

    await svc.pull(source.id)  # by hand: always audited
    assert len(audit.events) == 3


async def test_pull_due_follows_each_interval() -> None:
    svc, _, calls, _, _ = _sources([INI])
    a = await svc.create_source(_create(source="a", intervalMinutes=60))
    b = await svc.create_source(_create(source="b", intervalMinutes=15))
    off = await svc.create_source(_create(source="off", enabled=False))
    assert (await svc.list_sources()).items[2].next_run_at is None

    now = datetime.now(tz=UTC)
    assert await svc.pull_due(now) == 2  # never fetched: both due, the switched-off one not
    assert await svc.pull_due(now + timedelta(minutes=5)) == 0
    assert await svc.pull_due(now + timedelta(minutes=16)) == 1  # b only
    assert await svc.pull_due(now + timedelta(minutes=61)) == 2
    assert off.id not in {c[0] for c in calls} and a.id != b.id


def test_next_run_at() -> None:
    created = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)
    assert next_run_at({"created_at": created}) == created
    assert next_run_at({"created_at": created, "enabled": False}) is None
    assert next_run_at({"last_run_at": datetime(2026, 11, 26, 10, 0), "interval_minutes": 30}) == datetime(
        2026, 11, 26, 10, 30, tzinfo=UTC
    )


async def test_delete_keeps_the_systems() -> None:
    svc, systems, *_ = _sources([INI])
    source = await svc.create_source(_create(mode="replace"))
    await svc.pull(source.id)
    assert (await svc.delete_source(source.id)).source == "cmdb"
    assert await svc.pull(source.id) is None
    docs = (await systems.repo()).collection.docs
    assert len(docs) == 4 and not any(doc.get("retired_at") for doc in docs)


# ---------------------------------------------------------------- routes and the gate

PASSWORD = "admin-password"


def test_routes_are_admin_only_and_mounted_before_the_systems(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api.v1.routes import api_router
    from app.services.audit_service import get_audit_service

    svc, *_ = _sources([INI])

    async def service() -> InventoryListSourceService:
        return svc

    async def audit() -> FakeAudit:
        return FakeAudit()

    monkeypatch.setattr(settings, "system_password", PASSWORD)
    monkeypatch.setattr(auth_throttle, "_throttle", auth_throttle.AuthThrottle())
    app = FastAPI()
    app.include_router(api_router, prefix=settings.api_prefix)
    app.dependency_overrides[module.get_inventory_list_source_service] = service
    app.dependency_overrides[get_audit_service] = audit
    http = TestClient(app)
    base = f"{settings.api_prefix}/inventory/systems/sources"
    admin = {"X-System-Password": PASSWORD}

    assert http.get(base).status_code == 401
    assert http.post(base, json={"source": "cmdb", "url": "https://cmdb.example.com/x"}).status_code == 401
    listed = http.get(base, headers=admin)
    assert listed.status_code == 200 and listed.json() == {"items": [], "allowPrivateHosts": False}

    created = http.post(base, json={"source": "cmdb", "url": "https://cmdb.example.com/x", "authHeaderValue": "Token a"},
                        headers=admin)
    assert created.status_code == 201 and created.json()["authSet"] and "authHeaderValue" not in created.json()
    source_id = created.json()["id"]
    assert http.post(base, json={"source": "CMDB", "url": "https://cmdb.example.com/y"}, headers=admin).status_code == 409
    assert http.post(base, json={"source": "x", "url": "https://netbox.internal/"}, headers=admin).status_code == 400
    assert http.post(base, json={"source": "x", "url": "https://a.example.com", "authHeaderName": "Host"},
                     headers=admin).status_code == 422

    pulled = http.post(f"{base}/{source_id}/pull", json={"dryRun": True}, headers=admin)
    assert pulled.status_code == 200 and pulled.json()["ok"] and pulled.json()["result"]["createdCount"] == 4
    assert http.post(f"{base}/nope/pull", json={}, headers=admin).status_code == 404
    assert http.put(f"{base}/{source_id}", json={"enabled": False}, headers=admin).json()["nextRunAt"] is None
    assert http.delete(f"{base}/{source_id}", headers=admin).status_code == 204
    assert http.delete(f"{base}/{source_id}", headers=admin).status_code == 404
