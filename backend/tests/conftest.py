"""Shared test setup.

Scan imports, target listings and target deletes call the inventory system
service. Without a database it would try MongoDB and wait out the driver's
30 s server selection; every test gets an in-memory one instead (tests that
need their own set ``inventory_system_service._service`` themselves).
"""
from __future__ import annotations

import pytest

from app.repositories.inventory_repository import InventoryRepository
from app.repositories.inventory_system_repository import InventorySystemRepository
from app.repositories.scan_target_repository import ScanTargetRepository
from app.services import inventory_system_service
from app.services.inventory_system_service import InventorySystemService

from tests.fake_mongo import FakeCollection


@pytest.fixture(autouse=True)
def _in_memory_inventory_systems(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        inventory_system_service,
        "_service",
        InventorySystemService(
            InventorySystemRepository(FakeCollection(unique=("name_key",))),
            ScanTargetRepository(FakeCollection()),
            InventoryRepository(FakeCollection()),
        ),
    )
