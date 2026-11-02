"""Scans that can no longer finish are cancelled instead of staying "running".

Scan tasks live only in the backend process. After a restart, or when a task
was lost, the scan document kept its running or pending status for good, and
the target showed a scan in progress that nothing was working on.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.services import event_bus, scan_service as scan_module
from app.services.scan_service import RESTART_CANCEL_REASON, ScanService


class ScanRepo:
    def __init__(self, scans: list[dict[str, Any]]) -> None:
        self.scans = {s["_id"]: s for s in scans}
        self.updates: dict[str, dict[str, Any]] = {}

    async def list_active(self, limit: int = 500) -> list[dict[str, Any]]:
        return [s for s in self.scans.values() if s["status"] in ("running", "pending")]

    async def update_status(self, scan_id: str, status: str, **fields: Any) -> None:
        self.scans[scan_id]["status"] = status
        self.updates[scan_id] = {"status": status, **fields}

    async def get_running_scan_id(self, target_id: str) -> None:
        return None


class Deleter:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    async def delete_by_scan(self, scan_id: str) -> None:
        self.deleted.append(scan_id)


class TargetRepo:
    def __init__(self) -> None:
        self.cleared: list[str] = []

    async def update_running_state(self, target_id: str, running: bool, *_: Any) -> None:
        if not running:
            self.cleared.append(target_id)


def scan(scan_id: str, status: str, age: timedelta, **extra: Any) -> dict[str, Any]:
    at = datetime.now(UTC) - age
    return {"_id": scan_id, "status": status, "target_id": f"t-{scan_id}", "created_at": at, "started_at": at,
            "scanners": ["trivy"], **extra}


def make_service(scans: list[dict[str, Any]]) -> tuple[ScanService, ScanRepo, TargetRepo]:
    repo, targets = ScanRepo(scans), TargetRepo()
    service = ScanService(targets, repo, Deleter(), Deleter(), None, None)  # type: ignore[arg-type]
    return service, repo, targets


@pytest.fixture(autouse=True)
def quiet_events(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(event_bus, "get_event_bus", lambda: SimpleNamespace(publish=lambda _e: None))
    monkeypatch.setattr(scan_module, "_running_scan_tasks", {})
    monkeypatch.setattr(scan_module, "_cancel_reasons", {})


async def test_scans_left_by_a_restart_are_cancelled_at_startup() -> None:
    service, repo, targets = make_service([
        scan("running", "running", timedelta(minutes=5)),
        scan("queued", "pending", timedelta(seconds=1)),
        scan("done", "completed", timedelta(hours=1)),
    ])

    count = await service.cancel_stale_scans(grace_seconds=0, orphan_reason=RESTART_CANCEL_REASON)

    assert count == 2
    assert {k: v["status"] for k, v in repo.updates.items()} == {"running": "cancelled", "queued": "cancelled"}
    assert repo.updates["running"]["error"] == RESTART_CANCEL_REASON
    assert sorted(targets.cleared) == ["t-queued", "t-running"]
    assert repo.scans["done"]["status"] == "completed"


async def test_a_scan_just_submitted_keeps_its_grace_period() -> None:
    service, repo, _ = make_service([scan("new", "pending", timedelta(seconds=10))])

    assert await service.cancel_stale_scans() == 0
    assert repo.updates == {}


async def test_a_queued_scan_with_a_live_task_is_left_alone() -> None:
    service, repo, _ = make_service([scan("queued", "pending", timedelta(hours=5))])
    task = asyncio.create_task(asyncio.sleep(60))
    scan_module._running_scan_tasks["queued"] = task
    try:
        assert await service.cancel_stale_scans() == 0
        assert not task.cancelled()
    finally:
        task.cancel()


async def test_a_running_scan_past_its_maximum_runtime_is_cancelled_through_its_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scan_module.settings, "sca_scan_max_runtime_seconds", 3600)
    service, _, _ = make_service([
        scan("hung", "running", timedelta(hours=2)),
        scan("busy", "running", timedelta(minutes=30)),
    ])
    hung = asyncio.create_task(asyncio.sleep(60))
    busy = asyncio.create_task(asyncio.sleep(60))
    scan_module._running_scan_tasks.update({"hung": hung, "busy": busy})
    try:
        assert await service.cancel_stale_scans() == 1
        await asyncio.sleep(0)
        assert hung.cancelled()
        assert not busy.cancelled()
        assert "maximum runtime of 60 minutes" in scan_module._cancel_reasons["hung"]
    finally:
        busy.cancel()


def test_the_derived_runtime_covers_the_slowest_scanner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scan_module.settings, "sca_scan_max_runtime_seconds", 0)
    monkeypatch.setenv("GRYPE_TIMEOUT_SECONDS", "5000")
    service, _, _ = make_service([])

    assert service._max_runtime_seconds(["trivy", "grype"]) > 5000 + 60
