"""Authorization boundary of the version report endpoint.

CI holds the SCA API key. That key must open exactly this one route and nothing
else under /inventory, and a wrong key must not slip through to a fail-open gate.
"""
from __future__ import annotations

from typing import Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import inventory
from app.core.config import settings
from app.core.write_auth import require_admin_write, require_inventory_report
from app.services.inventory_service import get_inventory_service

API_KEY = "ci-key"
PASSWORD = "admin-password"
REPORT = {"items": [{"productSlug": "nginx", "version": "1.30.1"}]}


class FakeService:
    def __init__(self) -> None:
        self.report_calls = 0

    async def report_versions(self, entries: list[Any], *, reported_by: str | None = None) -> list[Any]:
        self.report_calls += 1
        return []

    async def list_history(self, **_: Any) -> tuple[int, list[Any]]:
        return 0, []

    async def create_item(self, *_: Any, **__: Any) -> None:
        raise AssertionError("must not reach the service")


@pytest.fixture
def service() -> FakeService:
    return FakeService()


@pytest.fixture
def client(service: FakeService, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(settings, "sca_api_key", API_KEY)
    monkeypatch.setattr(settings, "system_password", PASSWORD)
    app = FastAPI()
    app.include_router(
        inventory.report_router, prefix="/inventory", dependencies=[Depends(require_inventory_report)]
    )
    app.include_router(inventory.router, prefix="/inventory", dependencies=[Depends(require_admin_write)])
    app.dependency_overrides[get_inventory_service] = lambda: service
    return TestClient(app)


def test_ci_key_opens_the_report_route(client: TestClient, service: FakeService) -> None:
    response = client.post("/inventory/report", json=REPORT, headers={"X-API-Key": API_KEY})
    assert response.status_code == 200
    assert service.report_calls == 1


def test_system_password_opens_it_too(client: TestClient) -> None:
    response = client.post("/inventory/report", json=REPORT, headers={"X-System-Password": PASSWORD})
    assert response.status_code == 200


def test_wrong_key_is_rejected(client: TestClient, service: FakeService) -> None:
    response = client.post("/inventory/report", json=REPORT, headers={"X-API-Key": "nope"})
    assert response.status_code == 401
    assert service.report_calls == 0


def test_wrong_key_is_not_rescued_by_a_fail_open_password_gate(
    client: TestClient, service: FakeService, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "system_password", None)
    response = client.post("/inventory/report", json=REPORT, headers={"X-API-Key": "nope"})
    assert response.status_code == 401
    assert service.report_calls == 0


def test_no_credentials_are_rejected(client: TestClient, service: FakeService) -> None:
    assert client.post("/inventory/report", json=REPORT).status_code == 401
    assert service.report_calls == 0


def test_ci_key_opens_nothing_else(client: TestClient) -> None:
    payload = {"name": "x", "vendorSlug": "v", "productSlug": "p", "version": "1"}
    response = client.post("/inventory", json=payload, headers={"X-API-Key": API_KEY})
    assert response.status_code == 401


def test_history_is_a_route_of_its_own_and_readable(client: TestClient) -> None:
    # Declared before /{item_id}, which would otherwise take "history" as an id.
    response = client.get("/inventory/history")
    assert response.status_code == 200
    assert response.json() == {"total": 0, "items": []}
