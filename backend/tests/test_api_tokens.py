"""API tokens: each one opens the routes of its scopes and nothing else."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pymongo.errors import PyMongoError

from app.api.v1 import api_tokens, inventory
from app.api.v1.scans import verify_sca_api_key
from app.core import auth_throttle, write_auth
from app.core.config import settings
from app.core.write_auth import require_token_admin
from app.schemas.api_token import ApiTokenCreateRequest
from app.services.api_token_service import ApiTokenService, get_api_token_service
from app.services.audit_service import get_audit_service
from app.services.inventory_service import get_inventory_service

PASSWORD = "admin-password"
ADMIN = {"X-System-Password": PASSWORD}
REPORT = {"items": [{"productSlug": "nginx", "version": "1.30.1"}]}
ATTEMPTS = auth_throttle._MAX_ATTEMPTS


class FakeRepo:
    def __init__(self) -> None:
        self.documents: dict[str, dict[str, Any]] = {}
        self.fail_touch = False

    async def list_all(self) -> list[dict[str, Any]]:
        return [{k: v for k, v in doc.items() if k != "token_hash"} for doc in self.documents.values()]

    async def insert(self, document: dict[str, Any]) -> None:
        self.documents[document["_id"]] = document

    async def get_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        return next((d for d in self.documents.values() if d["token_hash"] == token_hash), None)

    async def any_with_scope(self, scope: str) -> bool:
        return any(scope in d["scopes"] for d in self.documents.values())

    async def touch(self, token_id: str, used_at: datetime) -> None:
        if self.fail_touch:
            raise PyMongoError("down")
        self.documents[token_id]["last_used_at"] = used_at

    async def delete(self, token_id: str) -> dict[str, Any] | None:
        return self.documents.pop(token_id, None)


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def record_event(self, job_name: str, **kwargs: Any) -> None:
        self.events.append((job_name, kwargs))


class FakeInventory:
    def __init__(self) -> None:
        self.reported_by: list[str | None] = []

    async def report_versions(self, entries: list[Any], *, reported_by: str | None = None) -> list[Any]:
        self.reported_by.append(reported_by)
        return []


@pytest.fixture
def repo() -> FakeRepo:
    return FakeRepo()


@pytest.fixture
def service(repo: FakeRepo) -> ApiTokenService:
    return ApiTokenService(repo)  # type: ignore[arg-type]


@pytest.fixture
def audit() -> FakeAudit:
    return FakeAudit()


@pytest.fixture
def reports() -> FakeInventory:
    return FakeInventory()


@pytest.fixture
def client(
    service: ApiTokenService, audit: FakeAudit, reports: FakeInventory, monkeypatch: pytest.MonkeyPatch
) -> TestClient:
    async def get_service() -> ApiTokenService:
        return service

    monkeypatch.setattr(write_auth, "get_api_token_service", get_service)
    monkeypatch.setattr(settings, "system_password", PASSWORD)
    monkeypatch.setattr(settings, "sca_api_key", "ci-key")
    monkeypatch.setattr(auth_throttle, "_throttle", auth_throttle.AuthThrottle())
    app = FastAPI()
    app.include_router(api_tokens.router, prefix="/api-tokens", dependencies=[Depends(require_token_admin)])
    app.include_router(inventory.report_router, prefix="/inventory")
    app.dependency_overrides[get_api_token_service] = get_service
    app.dependency_overrides[get_audit_service] = lambda: audit
    app.dependency_overrides[get_inventory_service] = lambda: reports

    @app.post("/scans", dependencies=[Depends(verify_sca_api_key)])
    async def submit() -> dict[str, bool]:
        return {"ok": True}

    return TestClient(app)


def _create(client: TestClient, *scopes: str, name: str = "deploy", **extra: Any) -> dict[str, Any]:
    response = client.post("/api-tokens", json={"name": name, "scopes": list(scopes), **extra}, headers=ADMIN)
    assert response.status_code == 201, response.text
    return response.json()


def _key(token: dict[str, Any]) -> dict[str, str]:
    return {"X-API-Key": token["token"]}


# --- Storage and display ---


def test_only_a_hash_is_stored(client: TestClient, repo: FakeRepo) -> None:
    token = _create(client, "scan:submit")
    stored = repo.documents[token["id"]]
    assert token["token"].startswith("hct_")
    assert token["token"] not in str(stored)
    assert stored["token_prefix"] == token["token"][:12]
    assert stored["token_hash"] not in str(token)


def test_the_list_never_shows_a_token_or_its_hash(client: TestClient) -> None:
    token = _create(client, "scan:submit")
    listed = client.get("/api-tokens", headers=ADMIN).json()["items"]
    assert len(listed) == 1
    assert listed[0]["tokenPrefix"] == token["tokenPrefix"]
    assert "token" not in listed[0]
    assert "tokenHash" not in listed[0] and "token_hash" not in listed[0]


def test_an_expired_token_is_marked_in_the_list(client: TestClient, repo: FakeRepo) -> None:
    token = _create(client, "scan:submit", expiresInDays=30)
    repo.documents[token["id"]]["expires_at"] = datetime.now(tz=UTC) - timedelta(seconds=1)
    assert client.get("/api-tokens", headers=ADMIN).json()["items"][0]["expired"] is True


@pytest.mark.parametrize(
    "body",
    [
        {"name": "   ", "scopes": ["scan:submit"]},
        {"name": "x", "scopes": []},
        {"name": "x", "scopes": ["admin"]},
        {"name": "x", "scopes": ["scan:submit"], "expiresInDays": 0},
    ],
)
def test_invalid_tokens_cannot_be_created(client: TestClient, body: dict[str, Any]) -> None:
    assert client.post("/api-tokens", json=body, headers=ADMIN).status_code == 422


# --- Who may manage tokens ---


@pytest.mark.parametrize("method", ["get", "post"])
def test_without_a_system_password_nobody_can_manage_tokens(
    client: TestClient, repo: FakeRepo, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    # The other admin routes open when no password is set. Here that would hand out credentials.
    monkeypatch.setattr(settings, "system_password", None)
    response = client.request(method, "/api-tokens", json={"name": "x", "scopes": ["scan:submit"]})
    assert response.status_code == 403
    assert repo.documents == {}


@pytest.mark.parametrize("headers", [{}, {"X-System-Password": "wrong"}])
def test_the_token_list_is_not_public(client: TestClient, headers: dict[str, str]) -> None:
    response = client.get("/api-tokens", headers=headers)
    assert response.status_code == 401
    assert response.headers["X-Write-Auth-Required"] == "1"


def test_a_token_cannot_manage_tokens(client: TestClient) -> None:
    token = _create(client, "scan:submit", "inventory:report")
    assert client.get("/api-tokens", headers=_key(token)).status_code == 401


def test_guessing_the_password_on_the_token_routes_locks(client: TestClient) -> None:
    for _ in range(ATTEMPTS):
        assert client.get("/api-tokens", headers={"X-System-Password": "wrong"}).status_code == 401
    assert client.get("/api-tokens", headers=ADMIN).status_code == 429


def test_creating_and_revoking_leave_an_audit_entry_without_the_token(client: TestClient, audit: FakeAudit) -> None:
    token = _create(client, "scan:submit")
    assert client.delete(f"/api-tokens/{token['id']}", headers=ADMIN).status_code == 204
    assert [name for name, _ in audit.events] == ["api_token_created", "api_token_revoked"]
    assert token["token"] not in str(audit.events)


def test_revoking_an_unknown_token_is_a_404(client: TestClient) -> None:
    assert client.delete("/api-tokens/nope", headers=ADMIN).status_code == 404


# --- What a token opens ---


def test_a_scan_token_submits_scans(client: TestClient) -> None:
    assert client.post("/scans", headers=_key(_create(client, "scan:submit"))).status_code == 200


def test_a_scan_token_cannot_report_versions(client: TestClient, reports: FakeInventory) -> None:
    token = _create(client, "scan:submit")
    assert client.post("/inventory/report", json=REPORT, headers=_key(token)).status_code == 403
    assert reports.reported_by == []


def test_a_report_token_cannot_submit_scans(client: TestClient) -> None:
    assert client.post("/scans", headers=_key(_create(client, "inventory:report"))).status_code == 403


def test_a_report_token_reports_versions(client: TestClient, reports: FakeInventory) -> None:
    token = _create(client, "inventory:report")
    assert client.post("/inventory/report", json=REPORT, headers=_key(token)).status_code == 200
    assert len(reports.reported_by) == 1


def test_a_token_with_both_scopes_opens_both(client: TestClient) -> None:
    token = _create(client, "scan:submit", "inventory:report")
    assert client.post("/scans", headers=_key(token)).status_code == 200
    assert client.post("/inventory/report", json=REPORT, headers=_key(token)).status_code == 200


def test_the_sca_api_key_still_submits_scans(client: TestClient) -> None:
    assert client.post("/scans", headers={"X-API-Key": "ci-key"}).status_code == 200


def test_the_sca_api_key_no_longer_reports_versions(client: TestClient, reports: FakeInventory) -> None:
    response = client.post("/inventory/report", json=REPORT, headers={"X-API-Key": "ci-key"})
    assert response.status_code == 401
    assert reports.reported_by == []


def test_an_expired_token_opens_nothing(client: TestClient, repo: FakeRepo) -> None:
    token = _create(client, "scan:submit", expiresInDays=1)
    repo.documents[token["id"]]["expires_at"] = datetime.now(tz=UTC)
    assert client.post("/scans", headers=_key(token)).status_code == 401


def test_a_revoked_token_opens_nothing(client: TestClient) -> None:
    token = _create(client, "scan:submit")
    client.delete(f"/api-tokens/{token['id']}", headers=ADMIN)
    assert client.post("/scans", headers=_key(token)).status_code == 401


def test_scans_stay_closed_when_the_last_token_is_revoked(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sca_api_key", None)
    token = _create(client, "scan:submit")
    assert client.post("/scans", headers=_key(token)).status_code == 200
    client.delete(f"/api-tokens/{token['id']}", headers=ADMIN)
    assert client.post("/scans", headers=_key(token)).status_code == 503


def test_tokens_alone_are_enough_to_turn_scans_on(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sca_api_key", None)
    assert client.post("/scans", headers={"X-API-Key": "x"}).status_code == 503
    _create(client, "scan:submit")
    assert client.post("/scans", headers={"X-API-Key": "x"}).status_code == 401


# --- Guessing ---


def test_guessing_a_token_locks(client: TestClient) -> None:
    for _ in range(ATTEMPTS):
        assert client.post("/scans", headers={"X-API-Key": "hct_guess"}).status_code == 401
    assert client.post("/scans", headers={"X-API-Key": "hct_guess"}).status_code == 429


def test_a_token_without_the_scope_does_not_reset_the_counter(client: TestClient) -> None:
    # Otherwise its holder could keep guessing at the SCA key without ever locking.
    other = _create(client, "inventory:report")
    for _ in range(ATTEMPTS - 1):
        assert client.post("/scans", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/scans", headers=_key(other)).status_code == 403
    assert client.post("/scans", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/scans", headers={"X-API-Key": "wrong"}).status_code == 429


@pytest.mark.parametrize("key", ["wrong", "hct_" + "a" * 5000])
def test_junk_never_reaches_the_database(
    client: TestClient, repo: FakeRepo, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    async def fail(_: str) -> None:
        raise AssertionError("must not look this up")

    monkeypatch.setattr(repo, "get_by_hash", fail)
    assert client.post("/scans", headers={"X-API-Key": key}).status_code == 401


# --- The report's author ---


def test_the_history_names_the_token_not_the_callers_text(client: TestClient, reports: FakeInventory) -> None:
    token = _create(client, "inventory:report", name="deploy-prod")
    body = {**REPORT, "reportedBy": "someone-else"}
    client.post("/inventory/report", json=body, headers=_key(token))
    assert reports.reported_by == ["deploy-prod (someone-else)"]


def test_the_token_name_stands_alone_without_reported_by(client: TestClient, reports: FakeInventory) -> None:
    token = _create(client, "inventory:report", name="deploy-prod")
    client.post("/inventory/report", json=REPORT, headers=_key(token))
    assert reports.reported_by == ["deploy-prod"]


def test_a_person_keeps_their_own_text(client: TestClient, reports: FakeInventory) -> None:
    client.post("/inventory/report", json={**REPORT, "reportedBy": "me"}, headers=ADMIN)
    assert reports.reported_by == ["me"]


# --- Service details ---


async def test_use_is_recorded(service: ApiTokenService, repo: FakeRepo) -> None:
    created = await service.create_token(ApiTokenCreateRequest(name="x", scopes=["scan:submit"]))
    assert await service.authenticate(created.token) is not None
    assert repo.documents[created.id]["last_used_at"] is not None


async def test_a_failed_timestamp_does_not_fail_the_request(service: ApiTokenService, repo: FakeRepo) -> None:
    created = await service.create_token(ApiTokenCreateRequest(name="x", scopes=["scan:submit"]))
    repo.fail_touch = True
    assert await service.authenticate(created.token) is not None


async def test_repeated_scopes_collapse(service: ApiTokenService) -> None:
    created = await service.create_token(ApiTokenCreateRequest(name="x", scopes=["scan:submit", "scan:submit"]))
    assert created.scopes == ["scan:submit"]
