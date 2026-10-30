"""POST /vulnerabilities/lookup reads in public and writes behind the system password.

The route used to run a refresh for anyone. A lower-cased CVE missed the exact
local lookup, and when EUVD and NVD both answered nothing, the stored record was
replaced by a "reserved" placeholder.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import vulnerabilities
from app.core import auth_throttle
from app.core.config import settings
from app.schemas.vulnerability import VulnerabilityRefreshResponse
from app.services.ingestion.manual_refresher import ManualRefresher
from app.services.vulnerability_service import canonical_vuln_id, get_vulnerability_service

PASSWORD = "admin-password"


class FakeService:
    def __init__(self, found: bool = False) -> None:
        self.found = found
        self.refreshes = 0

    async def get_by_id(self, identifier: str) -> Any:
        return None

    async def trigger_refresh(self, request: Any) -> VulnerabilityRefreshResponse:
        self.refreshes += 1
        return VulnerabilityRefreshResponse(requested=[], results=[])


@pytest.fixture
def service() -> FakeService:
    return FakeService()


@pytest.fixture
def client(service: FakeService, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(settings, "system_password", PASSWORD)
    monkeypatch.setattr(auth_throttle, "_throttle", auth_throttle.AuthThrottle())
    app = FastAPI()
    app.include_router(vulnerabilities.router, prefix="/vulnerabilities")
    app.dependency_overrides[get_vulnerability_service] = lambda: service
    return TestClient(app)


def test_sync_needs_the_system_password(client: TestClient, service: FakeService) -> None:
    response = client.post("/vulnerabilities/lookup", json={"identifier": "cve-2021-44228"})
    assert response.status_code == 401
    assert service.refreshes == 0


def test_sync_runs_with_the_system_password(client: TestClient, service: FakeService) -> None:
    response = client.post(
        "/vulnerabilities/lookup",
        json={"identifier": "CVE-2021-44228"},
        headers={"X-System-Password": PASSWORD},
    )
    assert response.status_code == 200
    assert service.refreshes == 1


def test_read_without_sync_stays_public(client: TestClient, service: FakeService) -> None:
    response = client.post("/vulnerabilities/lookup", json={"identifier": "CVE-2021-44228", "autoSync": False})
    assert response.status_code == 200
    assert response.json()["status"] == "not_found"
    assert service.refreshes == 0


@pytest.mark.parametrize("identifier", ["<script>", "a b", "a" * 129, "", "../x"])
def test_identifier_shape_is_checked(client: TestClient, identifier: str) -> None:
    response = client.post("/vulnerabilities/lookup", json={"identifier": identifier, "autoSync": False})
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("cve-2021-44228", "CVE-2021-44228"),
        ("euvd-2024-12345", "EUVD-2024-12345"),
        ("GHSA-5g2c-h3r8-6w3g", "GHSA-5g2c-h3r8-6w3g"),
        ("RUSTSEC-2024-0001", "RUSTSEC-2024-0001"),
    ],
)
def test_case_of_cve_ids_cannot_miss_the_stored_record(given: str, expected: str) -> None:
    assert canonical_vuln_id(given) == expected


class FakeRepository:
    def __init__(self, existing: bool) -> None:
        self.existing = existing
        self.upserts: list[Any] = []
        self.collection = SimpleNamespace(find_one=self._find_one)

    async def _find_one(self, query: dict[str, Any], projection: dict[str, Any]) -> dict[str, Any] | None:
        return {"_id": query["_id"]} if self.existing else None

    async def upsert(self, document: Any, *, change_context: Any = None) -> Any:
        self.upserts.append(document)
        return SimpleNamespace(inserted=True, changed_fields=1)


async def _nothing(*_: Any, **__: Any) -> None:
    return None


async def _refresh(repository: FakeRepository, identifier: str) -> Any:
    refresher = ManualRefresher.__new__(ManualRefresher)
    refresher._fetch_euvd_record = _nothing  # type: ignore[method-assign]
    refresher._nvd_client = SimpleNamespace(fetch_cve=_nothing, fetch_cpe_matches=_nothing)  # type: ignore[assignment]
    return await refresher._refresh_single(
        original_identifier=identifier.lower(),
        normalized_identifier=identifier,
        repository=repository,  # type: ignore[arg-type]
        asset_catalog=None,  # type: ignore[arg-type]
        kev_metadata={},
        circl_client=None,  # type: ignore[arg-type]
    )


async def test_upstream_miss_never_replaces_a_stored_record() -> None:
    repository = FakeRepository(existing=True)
    status = await _refresh(repository, "CVE-2021-44228")
    assert status.status == "skipped"
    assert repository.upserts == []


async def test_unknown_cve_still_gets_its_reserved_record() -> None:
    repository = FakeRepository(existing=False)
    status = await _refresh(repository, "CVE-2026-99999")
    assert status.status == "inserted"
    assert repository.upserts[0].vuln_id == "CVE-2026-99999"


async def test_arbitrary_strings_are_not_stored() -> None:
    repository = FakeRepository(existing=False)
    status = await _refresh(repository, "anything-at-all")
    assert status.status == "skipped"
    assert repository.upserts == []
