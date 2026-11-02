"""Client registration is open by design, so what it stores has to stay bounded."""
from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.core.config import settings
from app.mcp import auth as mcp_auth
from app.mcp import oauth
from app.mcp.security import RateLimiter

REDIRECT = {"redirect_uris": ["http://localhost:1234/callback"]}


@pytest.fixture(autouse=True)
def clean_store(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(oauth, "_registration_limiter", RateLimiter(10_000))
    monkeypatch.setattr(settings, "mcp_allowed_redirect_hosts", "localhost")
    oauth._registered_clients.clear()
    yield
    oauth._registered_clients.clear()


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(oauth.router)
    return TestClient(app)


def test_client_name_is_cut(client: TestClient) -> None:
    response = client.post("/mcp/oauth/register", json={**REDIRECT, "client_name": "x" * 100_000})
    assert response.status_code == 201
    assert len(response.json()["client_name"]) == oauth._MAX_CLIENT_NAME_LENGTH


def test_oversized_redirect_lists_are_refused(client: TestClient) -> None:
    many = {"redirect_uris": ["http://localhost/cb"] * (oauth._MAX_REDIRECT_URIS + 1)}
    long = {"redirect_uris": ["http://localhost/" + "a" * oauth._MAX_REDIRECT_URI_LENGTH]}
    assert client.post("/mcp/oauth/register", json=many).status_code == 400
    assert client.post("/mcp/oauth/register", json=long).status_code == 400
    assert not oauth._registered_clients


def test_a_body_that_is_not_an_object_is_refused(client: TestClient) -> None:
    assert client.post("/mcp/oauth/register", json=["x"]).status_code == 400


def test_the_store_has_a_ceiling(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oauth, "_MAX_REGISTERED_CLIENTS", 3)
    for _ in range(5):
        assert client.post("/mcp/oauth/register", json=REDIRECT).status_code == 201
    assert len(oauth._registered_clients) == 3


def test_registrations_are_rate_limited(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oauth, "_registration_limiter", RateLimiter(2))
    statuses = [client.post("/mcp/oauth/register", json=REDIRECT).status_code for _ in range(4)]
    assert statuses[:2] == [201, 201]
    assert statuses[-1] == 429


def test_unused_clients_expire(client: TestClient) -> None:
    client_id = client.post("/mcp/oauth/register", json=REDIRECT).json()["client_id"]
    oauth._registered_clients[client_id]["expires"] = time.time() - 1
    oauth._cleanup_expired()
    assert client_id not in oauth._registered_clients


def _scope(peer: str, forwarded: str) -> dict:
    return {
        "type": "http",
        "client": (peer, 1),
        "headers": [(b"x-forwarded-for", forwarded.encode())],
        "path": "/mcp",
        "method": "POST",
        "query_string": b"",
    }


def test_audit_ip_cannot_be_forged_by_a_direct_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "trusted_proxy_ips_raw", None)
    scope = _scope("203.0.113.9", "10.0.0.5")
    assert mcp_auth.MCPAuthMiddleware._get_client_ip(scope, scope["headers"]) == "203.0.113.9"
    assert Request(scope).client.host == "203.0.113.9"


CHALLENGE = "a" * 43


@pytest.fixture
def registered(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> str:
    class Provider:
        name = "test"

    async def resolve(_state: str, _callback: str) -> str:
        return "https://idp.example/authorize"

    async def no_audit(**_kwargs: object) -> None:
        return None

    monkeypatch.setattr(oauth, "_authorize_limiter", RateLimiter(10_000))
    monkeypatch.setattr(oauth.oauth_providers, "get_provider", lambda: Provider())
    monkeypatch.setattr(oauth.oauth_providers, "resolve_authorize_url", resolve)
    monkeypatch.setattr(oauth, "log_oauth_event", no_audit)
    oauth._pending_auths.clear()
    return client.post("/mcp/oauth/register", json=REDIRECT).json()["client_id"]


def _authorize(client: TestClient, client_id: str, **overrides: str):
    params = {
        "client_id": client_id,
        "redirect_uri": REDIRECT["redirect_uris"][0],
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        "state": "s",
        **overrides,
    }
    return client.get("/mcp/oauth/authorize", params=params, follow_redirects=False)


def test_a_valid_authorize_request_still_redirects(client: TestClient, registered: str) -> None:
    assert _authorize(client, registered).status_code == 302
    assert len(oauth._pending_auths) == 1


@pytest.mark.parametrize("challenge", ["short", "a" * 44, "a" * 8000, "a" * 42 + "!"])
def test_a_malformed_code_challenge_is_refused(client: TestClient, registered: str, challenge: str) -> None:
    assert _authorize(client, registered, code_challenge=challenge).status_code == 400
    assert not oauth._pending_auths


def test_an_oversized_state_is_refused(client: TestClient, registered: str) -> None:
    assert _authorize(client, registered, state="s" * 8000).status_code == 400
    assert not oauth._pending_auths


def test_pending_sign_ins_have_a_ceiling(client: TestClient, registered: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oauth, "_MAX_PENDING_AUTHS", 3)
    statuses = [_authorize(client, registered).status_code for _ in range(5)]
    assert statuses == [302, 302, 302, 503, 503]
    assert len(oauth._pending_auths) == 3


def test_authorize_is_rate_limited_per_client(client: TestClient, registered: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oauth, "_authorize_limiter", RateLimiter(2))
    statuses = [_authorize(client, registered).status_code for _ in range(4)]
    assert statuses[:2] == [302, 302]
    assert statuses[2:] == [429, 429]
