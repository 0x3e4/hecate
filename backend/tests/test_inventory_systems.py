"""Inventory systems: hosts and nodes as places, their SBOM pushes as evidence."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import settings
from app.repositories.inventory_repository import InventoryRepository
from app.repositories.inventory_system_repository import InventorySystemRepository, SystemNameTaken
from app.repositories.scan_target_repository import ScanTargetRepository
from app.schemas.inventory_system import InventorySystemCreateRequest, InventorySystemUpdateRequest
from app.services import inventory_system_service as system_module
from app.services.inventory_system_service import InventorySystemService, report_status

from tests.fake_mongo import FakeCollection

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)


def _service(targets: list[dict[str, Any]] | None = None, items: list[dict[str, Any]] | None = None) -> InventorySystemService:
    return InventorySystemService(
        InventorySystemRepository(FakeCollection(unique=("name_key",))),
        ScanTargetRepository(FakeCollection(targets or [])),
        InventoryRepository(FakeCollection(items or [])),
    )


def _target(target_id: str, **fields: Any) -> dict[str, Any]:
    return {"_id": target_id, "type": "sbom-import", "name": target_id.removeprefix("sbom-import-"), **fields}


@pytest.mark.parametrize(
    ("last", "status"),
    [(None, "never"), (NOW - timedelta(days=1), "reporting"), (NOW - timedelta(days=3), "reporting"),
     (NOW - timedelta(days=3, minutes=1), "stale"), (datetime(2026, 11, 26, 11, 0), "reporting")],
)
def test_report_status(last: datetime | None, status: str) -> None:
    assert report_status(last, NOW, 3) == status


async def test_a_push_with_kind_creates_the_system() -> None:
    svc = _service([_target("sbom-import-web-01", kind="host", exposure="internet")])
    system_id = await svc.link_import("sbom-import-web-01", "web-01", "host", "internet")
    system = await (await svc.repo()).get(system_id)
    assert system["name"] == "web-01" and system["source"] == "sbom-import"
    assert (system["kind"], system["exposure"], system["target_id"]) == ("host", "internet", "sbom-import-web-01")
    # The next push links to the same system and creates nothing.
    assert await svc.link_import("sbom-import-web-01", "web-01", None, None) == system_id
    assert len((await svc.repo()).collection.docs) == 1


async def test_an_sbom_without_kind_stays_an_sca_target() -> None:
    svc = _service([_target("sbom-import-shop")])
    assert await svc.link_import("sbom-import-shop", "shop", None, None) is None
    assert (await svc.repo()).collection.docs == []


async def test_a_listed_system_picks_up_its_first_push() -> None:
    svc = _service()
    created = await svc.create_system(InventorySystemCreateRequest(name="DB-01", kind="host", exposure="internal"))
    assert created.target_id is None and created.report_status == "never"

    # The first push creates the target, then links it.
    (await svc.target_repo()).collection.docs.append(_target("sbom-import-db-01"))
    system_id = await svc.link_import("sbom-import-db-01", "db-01", None, None)
    assert system_id == created.id
    # The system's classification reaches the target that had none.
    target = (await svc.target_repo()).collection.docs[0]
    assert (target["kind"], target["exposure"]) == ("host", "internal")


async def test_a_name_held_by_another_target_is_not_taken_over() -> None:
    svc = _service([_target("sbom-import-a", kind="host"), _target("sbom-import-b")])
    first = await svc.link_import("sbom-import-a", "web", "host", None)
    assert first
    assert await svc.link_import("sbom-import-b", "web", "host", None) is None


async def test_names_are_unique_case_insensitively() -> None:
    svc = _service()
    await svc.create_system(InventorySystemCreateRequest(name="web-01"))
    with pytest.raises(SystemNameTaken):
        await svc.create_system(InventorySystemCreateRequest(name="WEB-01 "))


async def test_a_new_system_takes_over_an_unlinked_target_of_its_name() -> None:
    svc = _service([_target("sbom-import-app-01", last_scan_at=NOW, latest_scan_id="s1",
                            latest_summary={"critical": 1, "total": 1})])
    created = await svc.create_system(InventorySystemCreateRequest(name="app-01", kind="host"))
    assert created.target_id == "sbom-import-app-01"
    assert created.latest_scan_id == "s1" and created.latest_summary.critical == 1


async def test_list_reports_status_products_and_a_deleted_target(monkeypatch: pytest.MonkeyPatch) -> None:
    recent = datetime.now(tz=UTC) - timedelta(hours=2)
    old = datetime.now(tz=UTC) - timedelta(days=10)
    svc = _service(
        [_target("sbom-import-a", kind="host", last_scan_at=recent), _target("sbom-import-b", kind="host", last_scan_at=old)],
    )
    a = await svc.link_import("sbom-import-a", "a", "host", None)
    b = await svc.link_import("sbom-import-b", "b", "host", None)
    c = (await svc.create_system(InventorySystemCreateRequest(name="c"))).id
    (await svc.item_repo()).collection.docs.append(
        {"_id": "item-1", "name": "nginx", "version": "1.24", "system_ids": [a, c]},
    )
    # Target b is gone (deleted without the hook): no link, no status.
    (await svc.target_repo()).collection.docs = [d for d in (await svc.target_repo()).collection.docs if d["_id"] != "sbom-import-b"]

    listing = await svc.list_systems()
    by_name = {s.name: s for s in listing.items}
    assert listing.stale_after_days == settings.inventory_system_stale_days
    assert by_name["a"].report_status == "reporting" and by_name["a"].target_id == "sbom-import-a"
    assert by_name["b"].report_status == "never" and by_name["b"].target_id is None
    assert [p.name for p in by_name["a"].products] == ["nginx"] and [p.id for p in by_name["c"].products] == ["item-1"]
    assert by_name["b"].id == b


async def test_kind_and_exposure_stay_the_same_on_both_sides() -> None:
    svc = _service([_target("sbom-import-n1", kind="kubernetes-node")])
    system_id = await svc.link_import("sbom-import-n1", "n1", "kubernetes-node", None)

    await svc.update_system(system_id, InventorySystemUpdateRequest(exposure="internet"))
    target = (await svc.target_repo()).collection.docs[0]
    assert target["exposure"] == "internet"

    await svc.mirror_target_classification("sbom-import-n1", {"exposure": None, "kind": "host"})
    system = await (await svc.repo()).get(system_id)
    assert system["kind"] == "host" and "exposure" not in system

    await svc.update_system(system_id, InventorySystemUpdateRequest.model_validate({"owner": "ops", "notes": None}))
    system = await (await svc.repo()).get(system_id)
    assert system["owner"] == "ops" and "notes" not in system


async def test_deleting_a_system_keeps_its_target_and_unlinks_products() -> None:
    svc = _service([_target("sbom-import-x", kind="host")])
    system_id = await svc.link_import("sbom-import-x", "x", "host", None)
    (await svc.item_repo()).collection.docs.append({"_id": "i", "name": "p", "version": "1", "system_ids": [system_id, "other"]})

    assert await svc.delete_system(system_id)
    assert (await svc.target_repo()).collection.docs[0]["_id"] == "sbom-import-x"
    assert (await svc.item_repo()).collection.docs[0]["system_ids"] == ["other"]


async def test_deleting_the_target_unlinks_the_system() -> None:
    svc = _service([_target("sbom-import-x", kind="host")])
    system_id = await svc.link_import("sbom-import-x", "x", "host", None)
    await svc.target_deleted("sbom-import-x")
    assert "target_id" not in await (await svc.repo()).get(system_id)


async def test_backfill_turns_classified_import_targets_into_systems_once() -> None:
    svc = _service([
        _target("sbom-import-web-01", kind="host", exposure="internet"),
        _target("sbom-import-node-1", kind="kubernetes-node"),
        _target("sbom-import-app"),
        {"_id": "ghcr.io/acme/shop", "type": "container_image", "name": "shop", "kind": "container"},
    ])
    assert await svc.backfill_from_targets() == 2
    assert await svc.backfill_from_targets() == 0
    names = sorted(d["name"] for d in (await svc.repo()).collection.docs)
    assert names == ["node-1", "web-01"]


# ---------------------------------------------------------------- the API


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, InventorySystemService]:
    from app.api.v1 import inventory_systems

    svc = _service([_target("sbom-import-web-01", kind="host")])
    monkeypatch.setattr(inventory_systems, "get_inventory_system_service", lambda: svc)
    app = FastAPI()
    app.include_router(inventory_systems.router, prefix="/inventory/systems")
    return TestClient(app), svc


def test_api_crud(client: tuple[TestClient, InventorySystemService]) -> None:
    http, _ = client
    created = http.post("/inventory/systems", json={"name": "web-01", "kind": "host", "groups": ["dmz", "DMZ", " "]})
    assert created.status_code == 201
    body = created.json()
    assert body["targetId"] == "sbom-import-web-01" and body["groups"] == ["dmz"] and body["reportStatus"] == "never"
    assert http.post("/inventory/systems", json={"name": "Web-01"}).status_code == 409
    assert http.post("/inventory/systems", json={"name": "  "}).status_code == 422
    assert http.post("/inventory/systems", json={"name": "x", "kind": "router"}).status_code == 422

    system_id = body["id"]
    changed = http.put(f"/inventory/systems/{system_id}", json={"exposure": "internet", "environment": "prod"})
    assert changed.status_code == 200 and changed.json()["exposure"] == "internet"
    listing = http.get("/inventory/systems").json()
    assert listing["total"] == 1 and listing["staleAfterDays"] == settings.inventory_system_stale_days
    assert http.delete(f"/inventory/systems/{system_id}").status_code == 204
    assert http.get(f"/inventory/systems/{system_id}").status_code == 404
    assert http.delete(f"/inventory/systems/{system_id}").status_code == 404


async def test_scan_targets_can_leave_out_systems(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.scan_service import ScanService

    svc = _service([_target("sbom-import-web-01", kind="host"), {"_id": "ghcr.io/acme/shop", "type": "container_image", "name": "shop"}])
    system_id = await svc.link_import("sbom-import-web-01", "web-01", "host", None)
    monkeypatch.setattr(system_module, "_service", svc)
    scans = ScanService.__new__(ScanService)
    scans.target_repo = await svc.target_repo()

    total, items = await scans.list_targets(include_systems=True)
    assert {i["_id"] if "_id" in i else i["target_id"]: i["system_id"] for i in items} == {
        "sbom-import-web-01": system_id, "ghcr.io/acme/shop": None,
    } and total == 2
    total, items = await scans.list_targets(include_systems=False)
    assert total == 1 and items[0]["system_id"] is None


# ---------------------------------------------------------------- products and backups


async def test_products_keep_only_systems_that_exist(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.schemas.inventory import InventoryItemCreateRequest, InventoryItemUpdateRequest
    from app.services.inventory_service import InventoryService
    from tests.test_inventory_history import FakeHistoryRepo, FakeInventoryRepo

    svc = _service()
    web = (await svc.create_system(InventorySystemCreateRequest(name="web-01"))).id
    monkeypatch.setattr(system_module, "_service", svc)
    items = InventoryService(FakeInventoryRepo(), FakeHistoryRepo())  # type: ignore[arg-type]

    async def no_eol(*_: Any) -> None:
        return None

    monkeypatch.setattr(items, "_auto_resolve_eol", no_eol)
    created = await items.create_item(InventoryItemCreateRequest(
        name="nginx", vendorSlug="f5", productSlug="nginx", version="1.24", systemIds=[web, "gone", web],
    ))
    assert created.system_ids == [web]
    updated = await items.update_item(created.id, InventoryItemUpdateRequest(systemIds=[]))
    assert updated is not None and updated.system_ids == []
    # Left out of an update, the links stay as they are.
    await items.update_item(created.id, InventoryItemUpdateRequest(systemIds=[web]))
    kept = await items.update_item(created.id, InventoryItemUpdateRequest(version="1.25"))
    assert kept is not None and kept.system_ids == [web]


async def test_backups_carry_systems_and_product_links(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.schemas.backup import InventoryBackupPayload
    from app.services.backup_service import BackupService
    from tests.test_inventory_history import FakeHistoryRepo, FakeInventoryRepo

    svc = _service()
    web = (await svc.create_system(InventorySystemCreateRequest(name="web-01", kind="host", groups=["dmz"]))).id
    monkeypatch.setattr(system_module, "_service", svc)
    inventory = FakeInventoryRepo()
    await inventory.insert("item-1", {"name": "nginx", "vendor_slug": "f5", "product_slug": "nginx",
                                      "version": "1.24", "system_ids": [web]})
    backup = BackupService(None, None, inventory, FakeHistoryRepo())  # type: ignore[arg-type]

    payload = await backup.export_inventory()
    assert [s["name"] for s in payload.systems] == ["web-01"] and payload.systems[0]["groups"] == ["dmz"]
    assert payload.items[0]["system_ids"] == [web]

    # Restore into an empty instance: the system comes back with its id, the link with it.
    fresh = _service()
    monkeypatch.setattr(system_module, "_service", fresh)
    empty = FakeInventoryRepo()
    restore = BackupService(None, None, empty, FakeHistoryRepo())  # type: ignore[arg-type]
    data = payload.model_dump(mode="json")
    data["systems"].append({"name": "  "})  # a broken row is skipped
    summary = await restore.restore_inventory(InventoryBackupPayload.model_validate(data))
    assert summary.inserted == 1
    restored = await (await fresh.repo()).get(web)
    assert restored["name"] == "web-01" and restored["kind"] == "host"
    assert empty.docs["item-1"]["system_ids"] == [web]
    # An older backup without systems still restores.
    old = InventoryBackupPayload.model_validate({"metadata": data["metadata"], "items": data["items"]})
    assert (await restore.restore_inventory(old)).updated == 1
