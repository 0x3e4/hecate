"""Inventory change log and version reports.

The history is what lets an analyst answer "when did we move off the vulnerable
version"; a report must never guess which item a pipeline meant.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.repositories.inventory_history_repository import diff_tracked_fields
from app.schemas.inventory import (
    InventoryItemCreateRequest,
    InventoryItemUpdateRequest,
    InventoryReportEntry,
    InventoryReportRequest,
)
from app.services.inventory_service import InventoryService, match_report_entry


NOW = datetime(2026, 10, 30, tzinfo=UTC)


class FakeInventoryRepo:
    def __init__(self) -> None:
        self.docs: dict[str, dict[str, Any]] = {}

    async def list_all(self) -> list[dict[str, Any]]:
        return [dict(doc) for doc in self.docs.values()]

    async def get(self, item_id: str) -> dict[str, Any] | None:
        doc = self.docs.get(item_id)
        return dict(doc) if doc else None

    async def insert(self, item_id: str, data: dict[str, Any]) -> dict[str, Any]:
        self.docs[item_id] = {"_id": item_id, **data, "created_at": NOW, "updated_at": NOW}
        return dict(self.docs[item_id])

    async def update(self, item_id: str, updates: dict[str, Any]) -> bool:
        self.docs[item_id].update(updates)
        return True

    async def delete(self, item_id: str) -> bool:
        return self.docs.pop(item_id, None) is not None


class FakeHistoryRepo:
    def __init__(self, *, fail: bool = False) -> None:
        self.entries: list[dict[str, Any]] = []
        self.fail = fail

    async def record(self, **entry: Any) -> dict[str, Any]:
        if self.fail:
            raise RuntimeError("history store down")
        self.entries.append(entry)
        return entry


def _item(**overrides: Any) -> dict[str, Any]:
    base = {
        "name": "nginx prod",
        "vendor_slug": "f5",
        "product_slug": "nginx",
        "version": "1.30.0",
        "environment": "prod",
        "deployment": "onprem",
        "instance_count": 1,
        "created_at": NOW,
        "updated_at": NOW,
    }
    return {**base, **overrides}


def _service(*docs: dict[str, Any]) -> tuple[InventoryService, FakeInventoryRepo, FakeHistoryRepo]:
    repo = FakeInventoryRepo()
    for index, doc in enumerate(docs):
        repo.docs[f"id-{index}"] = {"_id": f"id-{index}", **doc}
    history = FakeHistoryRepo()
    return InventoryService(repo, history), repo, history  # type: ignore[arg-type]


def test_diff_ignores_resent_values_and_empty_vs_missing() -> None:
    before = _item(owner=None)
    assert diff_tracked_fields(before, {"name": "nginx prod", "owner": "", "version": "1.30.0"}) == []


def test_diff_reports_old_and_new() -> None:
    assert diff_tracked_fields(_item(), {"version": "1.30.1"}) == [
        {"field": "version", "old": "1.30.0", "new": "1.30.1"}
    ]


async def test_full_form_save_without_a_change_writes_no_history() -> None:
    # The web form always sends every field.
    service, _, history = _service(_item())
    await service.update_item(
        "id-0",
        InventoryItemUpdateRequest(name="nginx prod", version="1.30.0", environment="prod", deployment="onprem"),
    )
    assert history.entries == []


async def test_version_change_is_recorded_with_its_source() -> None:
    service, repo, history = _service(_item())
    await service.update_item(
        "id-0", InventoryItemUpdateRequest(version="1.30.1"), source="mcp", actor="alice"
    )
    assert repo.docs["id-0"]["version"] == "1.30.1"
    entry = history.entries[0]
    assert (entry["action"], entry["source"], entry["actor"]) == ("updated", "mcp", "alice")
    assert entry["changes"] == [{"field": "version", "old": "1.30.0", "new": "1.30.1"}]


async def test_delete_keeps_name_and_last_version_in_history() -> None:
    service, _, history = _service(_item())
    assert await service.delete_item("id-0")
    entry = history.entries[0]
    assert entry["action"] == "deleted"
    assert entry["item_name"] == "nginx prod"
    assert entry["changes"] == [{"field": "version", "old": "1.30.0", "new": None}]


async def test_create_is_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    service, _, history = _service()

    async def no_eol(*_: Any) -> None:
        return None

    monkeypatch.setattr(service, "_auto_resolve_eol", no_eol)
    await service.create_item(
        InventoryItemCreateRequest(name="redis", vendorSlug="redis", productSlug="redis", version="8.4.2")
    )
    assert history.entries[0]["action"] == "created"
    assert history.entries[0]["changes"] == [{"field": "version", "old": None, "new": "8.4.2"}]


async def test_a_failing_history_store_does_not_fail_the_write() -> None:
    service, repo, history = _service(_item())
    history.fail = True
    updated = await service.update_item("id-0", InventoryItemUpdateRequest(version="1.30.1"))
    assert updated is not None and repo.docs["id-0"]["version"] == "1.30.1"


def test_report_needs_something_to_identify_the_item() -> None:
    with pytest.raises(ValueError):
        InventoryReportEntry(version="1.0.0")


def test_report_entries_are_capped() -> None:
    with pytest.raises(ValueError):
        InventoryReportRequest(items=[{"productSlug": "nginx", "version": "1"}] * 201)


def test_match_combines_every_given_field() -> None:
    docs = [
        {"_id": "a", **_item(environment="prod")},
        {"_id": "b", **_item(environment="staging")},
    ]
    entry = InventoryReportEntry(productSlug="NGINX", environment="Staging", version="1")
    assert [doc["_id"] for doc in match_report_entry(entry, docs)] == ["b"]


async def test_report_updates_the_named_item_and_attributes_it() -> None:
    service, repo, history = _service(_item())
    results = await service.report_versions(
        [InventoryReportEntry(productSlug="nginx", version="1.30.1")], reported_by="deploy-prod"
    )
    assert results[0].status == "updated"
    assert results[0].previous_version == "1.30.0"
    assert repo.docs["id-0"]["version"] == "1.30.1"
    assert (history.entries[0]["source"], history.entries[0]["actor"]) == ("report", "deploy-prod")


async def test_report_of_the_running_version_changes_nothing() -> None:
    service, _, history = _service(_item())
    results = await service.report_versions([InventoryReportEntry(productSlug="nginx", version="1.30.0")])
    assert results[0].status == "unchanged"
    assert history.entries == []


async def test_ambiguous_report_touches_no_item() -> None:
    # Two environments, one product: updating both would hide a lagging one.
    service, repo, _ = _service(_item(environment="prod"), _item(environment="staging"))
    results = await service.report_versions([InventoryReportEntry(productSlug="nginx", version="9.9.9")])
    assert (results[0].status, results[0].matches) == ("ambiguous", 2)
    assert {doc["version"] for doc in repo.docs.values()} == {"1.30.0"}


async def test_unknown_product_is_reported_and_the_batch_continues() -> None:
    service, repo, _ = _service(_item())
    results = await service.report_versions(
        [
            InventoryReportEntry(productSlug="ngnix", version="1.0.0"),
            InventoryReportEntry(productSlug="nginx", version="1.30.1"),
        ]
    )
    assert [result.status for result in results] == ["not_found", "updated"]
    assert len(repo.docs) == 1
    assert repo.docs["id-0"]["version"] == "1.30.1"
