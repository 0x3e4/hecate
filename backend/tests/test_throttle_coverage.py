"""Every route that compares a secret sits behind the failure lockout.

The lockout used to cover the unlock endpoints and the admin gate only, so a
guessed admin password could be tried without limit through any target-scoped
route: 404 for a right guess, 401 for a wrong one.
"""
from __future__ import annotations

from typing import Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.v1.scans import verify_sca_api_key
from app.api.v1.vulnerabilities import _require_ai_analysis_password
from app.core import auth_throttle, write_auth
from app.core.config import settings
from app.core.passwords import hash_password
from app.services.scan_service import get_scan_service

PASSWORD = "admin-password"
TARGET_PASSWORD = "target-password"
ATTEMPTS = auth_throttle._MAX_ATTEMPTS


class FakeRepo:
    def __init__(self, document: dict[str, Any] | None) -> None:
        self.document = document

    async def get(self, _id: str) -> dict[str, Any] | None:
        return self.document


class FakeService:
    def __init__(self) -> None:
        self.scan_repo = FakeRepo({"target_id": "t"})
        self.target_repo = FakeRepo({"write_password_hash": hash_password(TARGET_PASSWORD, iterations=10)})


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(settings, "system_password", PASSWORD)
    monkeypatch.setattr(settings, "ai_analysis_password", "ai-password")
    monkeypatch.setattr(settings, "sca_api_key", "ci-key")
    monkeypatch.setattr(auth_throttle, "_throttle", auth_throttle.AuthThrottle())
    app = FastAPI()
    service = FakeService()
    app.dependency_overrides[get_scan_service] = lambda: service

    @app.delete("/scan/{scan_id}", dependencies=[Depends(write_auth.require_target_write_scan)])
    async def delete_scan(scan_id: str) -> dict[str, str]:
        return {"scan": scan_id}

    @app.post("/scan/{scan_id}/ai", dependencies=[Depends(write_auth.require_ai_target_write_scan)])
    async def scan_ai(scan_id: str) -> dict[str, str]:
        return {"scan": scan_id}

    @app.post("/ci", dependencies=[Depends(verify_sca_api_key)])
    async def ci() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/ai-history", dependencies=[Depends(_require_ai_analysis_password)])
    async def ai_history() -> dict[str, bool]:
        return {"ok": True}

    return TestClient(app)


def _lock(client: TestClient, method: str, path: str, headers: dict[str, str]) -> None:
    for _ in range(ATTEMPTS):
        assert client.request(method, path, headers=headers).status_code == 401
    assert client.request(method, path, headers=headers).status_code == 429


def test_guessing_the_admin_password_through_a_target_route_locks(client: TestClient) -> None:
    _lock(client, "DELETE", "/scan/1", {"X-System-Password": "wrong"})


def test_a_locked_client_gets_429_even_with_the_right_password(client: TestClient) -> None:
    _lock(client, "DELETE", "/scan/1", {"X-System-Password": "wrong"})
    response = client.delete("/scan/1", headers={"X-System-Password": PASSWORD})
    assert response.status_code == 429


def test_guessing_a_target_password_locks(client: TestClient) -> None:
    _lock(client, "DELETE", "/scan/1", {"X-Target-Password": "wrong"})


def test_a_valid_target_password_does_not_reset_the_counter(client: TestClient) -> None:
    for _ in range(ATTEMPTS - 1):
        assert client.delete("/scan/1", headers={"X-System-Password": "wrong"}).status_code == 401
    assert client.delete("/scan/1", headers={"X-Target-Password": TARGET_PASSWORD}).status_code == 200
    assert client.delete("/scan/1", headers={"X-System-Password": "wrong"}).status_code == 401
    assert client.delete("/scan/1", headers={"X-System-Password": "wrong"}).status_code == 429


def test_a_target_password_holder_cannot_probe_the_admin_password(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With a valid target password the request passes whatever admin password is
    # sent, so that header must not be compared at all: a comparison would answer
    # through the response time and never count as a failure.
    compared: list[str | None] = []
    real = write_auth._admin_matches
    monkeypatch.setattr(write_auth, "_admin_matches", lambda value: compared.append(value) or real(value))

    for guess in ("guess-1", "guess-2", PASSWORD):
        headers = {"X-Target-Password": TARGET_PASSWORD, "X-System-Password": guess}
        assert client.delete("/scan/1", headers=headers).status_code == 200

    assert compared == []


def test_admin_guesses_with_a_wrong_target_password_are_counted(client: TestClient) -> None:
    _lock(client, "DELETE", "/scan/1", {"X-Target-Password": "wrong", "X-System-Password": "guess"})


def test_the_admin_password_still_wins_over_a_wrong_target_password(client: TestClient) -> None:
    headers = {"X-Target-Password": "stale", "X-System-Password": PASSWORD}
    assert client.delete("/scan/1", headers=headers).status_code == 200


def test_guessing_the_ai_password_on_a_scan_route_locks(client: TestClient) -> None:
    _lock(client, "POST", "/scan/1/ai", {"X-AI-Analysis-Password": "wrong"})


def test_guessing_the_ai_password_on_a_read_route_locks(client: TestClient) -> None:
    _lock(client, "GET", "/ai-history", {"X-AI-Analysis-Password": "wrong"})


def test_guessing_the_ci_key_locks(client: TestClient) -> None:
    _lock(client, "POST", "/ci", {"X-API-Key": "wrong"})


def test_a_missing_password_is_not_a_guess(client: TestClient) -> None:
    # The findings table sends parallel writes before the UI prompts for a password.
    for _ in range(ATTEMPTS * 2):
        assert client.delete("/scan/1").status_code == 401
        assert client.post("/scan/1/ai").status_code == 401
        assert client.get("/ai-history").status_code == 401
    assert client.delete("/scan/1", headers={"X-System-Password": PASSWORD}).status_code == 200


def test_right_secrets_still_pass(client: TestClient) -> None:
    assert client.delete("/scan/1", headers={"X-System-Password": PASSWORD}).status_code == 200
    assert client.post("/ci", headers={"X-API-Key": "ci-key"}).status_code == 200
    assert client.get("/ai-history", headers={"X-AI-Analysis-Password": "ai-password"}).status_code == 200


def test_one_secret_has_one_counter_across_routes(client: TestClient) -> None:
    # Unlock endpoint, write gate and target routes all compare the system
    # password; a counter per route gave one client ten guesses on each.
    from app.api.v1 import status

    app = FastAPI()
    app.include_router(status.router, prefix="/status")
    other = TestClient(app)
    half = ATTEMPTS // 2
    for _ in range(half):
        assert other.post("/status/system-auth", json={"password": "wrong"}).status_code in (200, 401)
    for _ in range(ATTEMPTS - half):
        assert client.delete("/scan/1", headers={"X-System-Password": "wrong"}).status_code == 401
    assert client.delete("/scan/1", headers={"X-System-Password": PASSWORD}).status_code == 429


@pytest.mark.parametrize(
    ("first", "second", "same"),
    [
        ("2001:db8:1:2::1", "2001:db8:1:2:ffff::9", True),
        ("2001:db8:1:2::1", "2001:db8:1:3::1", False),
        ("203.0.113.5", "203.0.113.6", False),
        ("::ffff:203.0.113.5", "203.0.113.5", True),
        ("unknown", "unknown", True),
    ],
)
def test_ipv6_clients_are_counted_by_their_64(first: str, second: str, same: bool) -> None:
    assert (auth_throttle.client_key(first) == auth_throttle.client_key(second)) is same


def test_the_counter_store_stays_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [1000.0]
    throttle = auth_throttle.AuthThrottle(max_tracked=50)
    monkeypatch.setattr(throttle, "_now", lambda: now[0])
    for n in range(40):
        throttle.record_failure(f"old-{n}")
    now[0] += 120  # past the window
    for n in range(40):
        throttle.record_failure(f"new-{n}")
    assert len(throttle._fails) <= 50
    assert all(key.startswith("new-") for key in throttle._fails)


def test_pruning_keeps_a_running_lockout(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [1000.0]
    throttle = auth_throttle.AuthThrottle(max_attempts=2, max_tracked=3)
    monkeypatch.setattr(throttle, "_now", lambda: now[0])
    throttle.record_failure("attacker")
    throttle.record_failure("attacker")
    now[0] += 120
    for n in range(10):
        throttle.record_failure(f"noise-{n}")
    assert throttle.remaining_lockout("attacker") is not None


class TargetRepo:
    """Targets by id; ``protected`` holds a write password, ``open`` none."""

    def __init__(self, writes: list[tuple[str, Any]]) -> None:
        self.docs = {
            "protected": {"target_id": "protected", "write_password_hash": hash_password(TARGET_PASSWORD, iterations=10)},
            "open": {"target_id": "open"},
            "sbom-import-mine": {"target_id": "sbom-import-mine", "write_password_hash": hash_password(TARGET_PASSWORD, iterations=10)},
        }
        self.writes = writes

    async def get(self, target_id: str) -> dict[str, Any] | None:
        return self.docs.get(target_id)

    async def set_write_password(self, target_id: str, value: str | None) -> None:
        self.writes.append(("password", value is not None))


class TargetService:
    """What the target routes need, recording every write."""

    def __init__(self) -> None:
        self.writes: list[tuple[str, Any]] = []
        self.target_repo = TargetRepo(self.writes)

    async def resolve_target_id(self, target_id: str) -> str:
        return target_id

    async def update_target_auto_scan(self, _target_id: str, value: bool) -> None:
        self.writes.append(("autoScan", value))

    async def update_target_scanners(self, _target_id: str, value: list[str]) -> None:
        self.writes.append(("scanners", value))

    async def update_target_group(self, _target_id: str, value: str | None) -> None:
        self.writes.append(("group", value))

    async def get_target(self, target_id: str) -> dict[str, Any]:
        now = "2026-11-02T00:00:00+00:00"
        return {"target_id": target_id, "type": "source_repo", "name": "t", "created_at": now, "updated_at": now}


@pytest.fixture
def targets(monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, TargetService]:
    from app.api.v1 import scans

    monkeypatch.setattr(settings, "system_password", PASSWORD)
    monkeypatch.setattr(auth_throttle, "_throttle", auth_throttle.AuthThrottle())
    service = TargetService()
    app = FastAPI()
    app.include_router(scans.router, prefix="/scans")
    app.dependency_overrides[get_scan_service] = lambda: service
    return TestClient(app), service


def test_a_target_password_still_changes_auto_scan_and_group(targets: tuple[TestClient, TargetService]) -> None:
    client, service = targets

    response = client.patch(
        "/scans/targets/protected", json={"autoScan": False, "group": "web"}, headers={"X-Target-Password": TARGET_PASSWORD}
    )

    assert response.status_code == 200
    assert service.writes == [("autoScan", False), ("group", "web")]


def test_the_system_password_changes_the_scanners(targets: tuple[TestClient, TargetService]) -> None:
    client, service = targets

    response = client.patch("/scans/targets/protected", json={"scanners": ["trivy"]}, headers={"X-System-Password": PASSWORD})

    assert response.status_code == 200
    assert service.writes == [("scanners", ["trivy"])]


def test_a_target_password_changes_the_scanners_too(targets: tuple[TestClient, TargetService]) -> None:
    client, service = targets

    response = client.patch(
        "/scans/targets/protected", json={"scanners": ["trivy", "grype"]}, headers={"X-Target-Password": TARGET_PASSWORD}
    )

    assert response.status_code == 200
    assert service.writes == [("scanners", ["trivy", "grype"])]


@pytest.mark.parametrize("method", ["PUT", "DELETE"])
def test_the_owner_manages_the_targets_password(targets: tuple[TestClient, TargetService], method: str) -> None:
    client, service = targets

    response = client.request(
        method, "/scans/targets/protected/write-password", json={"password": "new-one"}, headers={"X-Target-Password": TARGET_PASSWORD}
    )

    assert response.status_code == 200
    assert service.writes == [("password", method == "PUT")]


def test_a_wrong_target_password_manages_nothing(targets: tuple[TestClient, TargetService]) -> None:
    client, service = targets

    response = client.delete("/scans/targets/protected/write-password", headers={"X-Target-Password": "wrong"})

    assert response.status_code == 401
    assert response.headers["X-Write-Auth-Required"] == "1"
    assert service.writes == []


def test_the_first_password_needs_the_admin(targets: tuple[TestClient, TargetService]) -> None:
    client, service = targets
    body = {"password": "new-one"}

    assert client.put("/scans/targets/open/write-password", json=body, headers={"X-Target-Password": "guess"}).status_code == 401
    assert client.put("/scans/targets/open/write-password", json=body, headers={"X-System-Password": PASSWORD}).status_code == 200
    assert service.writes == [("password", True)]


def test_without_a_system_password_only_the_owner_manages_a_password(
    targets: tuple[TestClient, TargetService], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, service = targets
    monkeypatch.setattr(settings, "system_password", "")

    assert client.delete("/scans/targets/protected/write-password").status_code == 401
    assert client.put("/scans/targets/open/write-password", json={"password": "x"}).status_code == 403
    headers = {"X-Target-Password": TARGET_PASSWORD}
    assert client.delete("/scans/targets/protected/write-password", headers=headers).status_code == 200
    assert service.writes == [("password", False)]


@pytest.mark.parametrize(
    ("dependency", "kwargs"),
    [
        ("require_target_write_sbom_import", {"json": {"targetId": "sbom-import-mine"}}),
        ("require_target_write_sbom_import", {"json": {"targetName": "Mine"}}),
        ("require_target_write_sbom_upload", {"params": {"targetName": "Mine"}}),
    ],
)
def test_an_sbom_import_into_an_existing_target_takes_its_password(
    targets: tuple[TestClient, TargetService], dependency: str, kwargs: dict[str, Any]
) -> None:
    _, service = targets
    app = FastAPI()
    app.dependency_overrides[get_scan_service] = lambda: service

    @app.post("/import", dependencies=[Depends(getattr(write_auth, dependency))])
    async def imported() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    assert client.post("/import", headers={"X-Target-Password": TARGET_PASSWORD}, **kwargs).status_code == 200
    assert client.post("/import", headers={"X-Target-Password": "wrong"}, **kwargs).status_code == 401


def test_an_sbom_import_into_a_new_target_needs_the_admin(targets: tuple[TestClient, TargetService]) -> None:
    _, service = targets
    app = FastAPI()
    app.dependency_overrides[get_scan_service] = lambda: service

    @app.post("/import", dependencies=[Depends(write_auth.require_target_write_sbom_import)])
    async def imported() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    body = {"targetName": "Somebody else"}
    assert client.post("/import", json=body, headers={"X-Target-Password": TARGET_PASSWORD}).status_code == 401
    assert client.post("/import", json=body, headers={"X-System-Password": PASSWORD}).status_code == 200
