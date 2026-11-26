"""OIDC sign-in, sessions, roles at every gate, read gating and the request audit trail.

The identity provider is an httpx.MockTransport serving discovery, JWKS, token
and userinfo endpoints with a locally generated RSA key.
"""
from __future__ import annotations

import base64
import hashlib
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.testclient import TestClient

from app.api.v1 import auth as auth_api
from app.api.v1 import status as status_api
from app.core import auth_throttle, request_audit
from app.core.auth_context import require_read_access
from app.core.config import settings
from app.core.passwords import hash_password
from app.core.request_audit import RequestAuditMiddleware
from app.core.write_auth import (
    require_admin_read,
    require_admin_write,
    require_ai_write,
    require_editor_write,
    require_target_password_change,
    require_target_write_path,
    require_token_admin,
)
from app.services import api_token_service, auth_session_service, oidc_client
from app.services.auth_session_service import AuthSessionService
from app.services.scan_service import get_scan_service

ISSUER = "https://idp.test/realms/hecate"
CLIENT_ID = "hecate-web"
SECRET = "client-secret"
BASE = "https://hecate.test"
SYSTEM_PASSWORD = "system-pw"
TARGET_PASSWORD = "target-pw"


def _rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return {**jwk, "kid": kid, "use": "sig", "alg": "RS256"}


class FakeIdp:
    """Discovery, JWKS, token and userinfo endpoints of a tiny OIDC provider."""

    def __init__(self) -> None:
        self.key = _rsa_key()
        self.kid = "k1"
        self.jwks = [_jwk(self.key, self.kid)]
        self.codes: dict[str, dict[str, Any]] = {}
        self.claims: dict[str, Any] = {"sub": "u-1", "name": "Ada Admin", "email": "ada@example.com",
                                       "groups": ["hecate-admins"]}
        self.userinfo_claims: dict[str, Any] = {}
        self.id_token_override: Any = None
        self.token_requests: list[dict[str, Any]] = []

    def discovery(self) -> dict[str, Any]:
        return {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
            "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
            "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
            "userinfo_endpoint": f"{ISSUER}/protocol/openid-connect/userinfo",
            "end_session_endpoint": f"{ISSUER}/protocol/openid-connect/logout",
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        }

    def sign(self, claims: dict[str, Any], *, key: Any = None, kid: str | None = None, alg: str = "RS256") -> str:
        return jwt.encode(claims, key or self.key, algorithm=alg, headers={"kid": kid or self.kid})

    def id_token(self, nonce: str, **overrides: Any) -> str:
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "iat": now, "exp": now + 300, "nonce": nonce, **self.claims}
        claims.update(overrides)
        return self.sign({k: v for k, v in claims.items() if v is not None})

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=self.discovery())
        if path.endswith("/certs"):
            return httpx.Response(200, json={"keys": self.jwks})
        if path.endswith("/token"):
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append({"form": form, "auth": request.headers.get("authorization")})
            pending = self.codes.pop(form.get("code", ""), None)
            if pending is None:
                return httpx.Response(400, json={"error": "invalid_grant"})
            verifier = form.get("code_verifier", "")
            digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            if digest != pending["challenge"] or form.get("redirect_uri") != pending["redirect_uri"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            token = self.id_token_override(pending["nonce"]) if self.id_token_override else self.id_token(pending["nonce"])
            return httpx.Response(200, json={"id_token": token, "access_token": "at-1", "token_type": "Bearer"})
        if path.endswith("/userinfo"):
            assert request.headers.get("authorization") == "Bearer at-1"
            return httpx.Response(200, json={"sub": self.claims["sub"], **self.userinfo_claims})
        return httpx.Response(404)


class FakeSessionRepo:
    def __init__(self) -> None:
        self.docs: dict[str, dict[str, Any]] = {}

    async def insert(self, document: dict[str, Any]) -> None:
        self.docs[document["_id"]] = dict(document)

    async def get(self, document_id: str) -> dict[str, Any] | None:
        return self.docs.get(document_id)

    async def pop(self, document_id: str) -> dict[str, Any] | None:
        return self.docs.pop(document_id, None)

    async def touch(self, document_id: str, seen_at: Any) -> None:
        if document_id in self.docs:
            self.docs[document_id]["last_seen_at"] = seen_at


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def record_event(self, job_name: str, **kwargs: Any) -> None:
        self.events.append((job_name, kwargs))


class FakeTargetRepo:
    def __init__(self) -> None:
        self.targets = {"repo-1": {"_id": "repo-1", "write_password_hash": hash_password(TARGET_PASSWORD)}}

    async def get(self, target_id: str) -> dict[str, Any] | None:
        return self.targets.get(target_id)


class FakeScanService:
    def __init__(self) -> None:
        self.target_repo = FakeTargetRepo()

    async def resolve_target_id(self, target_id: str) -> str | None:
        return target_id


class FakeTokenService:
    async def authenticate(self, token: str) -> dict[str, Any] | None:
        return {"name": "ci", "scopes": ["scan:submit"]} if token == "hct_" + "a" * 43 else None


@pytest.fixture
def idp(monkeypatch: pytest.MonkeyPatch) -> FakeIdp:
    fake = FakeIdp()
    monkeypatch.setattr(settings, "oidc_issuer", ISSUER)
    monkeypatch.setattr(settings, "oidc_client_id", CLIENT_ID)
    monkeypatch.setattr(settings, "oidc_client_secret", SECRET)
    monkeypatch.setattr(settings, "oidc_roles_claim", "groups")
    monkeypatch.setattr(settings, "oidc_admin_groups", "hecate-admins")
    monkeypatch.setattr(settings, "oidc_editor_groups", "hecate-editors")
    monkeypatch.setattr(settings, "oidc_viewer_groups", "")
    monkeypatch.setattr(settings, "auth_public_url", BASE)
    monkeypatch.setattr(settings, "auth_require_login", None)
    monkeypatch.setattr(settings, "system_password", None)
    monkeypatch.setattr(settings, "ai_analysis_password", None)
    monkeypatch.setattr(settings, "sca_api_key", "ci-key")
    monkeypatch.setattr(oidc_client, "_transport", httpx.MockTransport(fake.handler))
    monkeypatch.setattr(oidc_client, "_JWKS_MIN_REFRESH_SECONDS", 0.0)
    oidc_client.reset_oidc_client()
    monkeypatch.setattr(auth_session_service, "_service", AuthSessionService(FakeSessionRepo()))  # type: ignore[arg-type]
    monkeypatch.setattr(auth_throttle, "_throttle", auth_throttle.AuthThrottle())
    yield fake
    oidc_client.reset_oidc_client()


@pytest.fixture
def audit(monkeypatch: pytest.MonkeyPatch) -> FakeAudit:
    fake = FakeAudit()

    async def get_audit() -> FakeAudit:
        return fake

    monkeypatch.setattr(auth_api, "get_audit_service", get_audit)
    monkeypatch.setattr(request_audit, "audit_sink", fake.record_event)
    monkeypatch.setattr(request_audit, "write_inline", True)
    return fake


def _build_app() -> FastAPI:
    app = FastAPI()
    api = APIRouter(dependencies=[Depends(require_read_access)])
    api.include_router(auth_api.router, prefix="/auth")
    api.include_router(status_api.router, prefix="/status")

    @api.get("/things")
    async def things() -> dict[str, bool]:
        return {"ok": True}

    @api.get("/config")
    async def config() -> dict[str, bool]:
        return {"ok": True}

    @api.get("/scans/{scan_id}/shield")
    async def shield(scan_id: str) -> dict[str, str]:
        return {"scan": scan_id}

    @api.post("/vulnerabilities/search")
    async def search() -> list[str]:
        return []

    @api.post("/admin-write", dependencies=[Depends(require_admin_write)])
    async def admin_write() -> dict[str, bool]:
        return {"ok": True}

    @api.post("/editor-write", dependencies=[Depends(require_editor_write)])
    async def editor_write() -> dict[str, bool]:
        return {"ok": True}

    @api.post("/ai-write", dependencies=[Depends(require_ai_write)])
    async def ai_write() -> dict[str, bool]:
        return {"ok": True}

    @api.get("/settings", dependencies=[Depends(require_admin_read)])
    async def settings_read() -> dict[str, bool]:
        return {"ok": True}

    @api.get("/tokens", dependencies=[Depends(require_token_admin)])
    async def tokens() -> list[str]:
        return []

    @api.patch("/scans/targets/{target_id:path}", dependencies=[Depends(require_target_write_path)])
    async def patch_target(target_id: str) -> dict[str, str]:
        return {"target": target_id}

    @api.put("/scans/targets/{target_id:path}/write-password", dependencies=[Depends(require_target_password_change)])
    async def set_password(target_id: str) -> dict[str, str]:
        return {"target": target_id}

    @api.post("/explicit", dependencies=[Depends(require_editor_write)])
    async def explicit() -> dict[str, bool]:
        from app.services.audit_service import AuditService

        class Repo:
            async def insert_event(self, **kwargs: Any) -> None:
                explicit_events.append(kwargs)

        await AuditService(Repo()).record_event("saved_search_created", metadata={"label": "x"})  # type: ignore[arg-type]
        return {"ok": True}

    app.include_router(api, prefix=settings.api_prefix)
    app.dependency_overrides[get_scan_service] = lambda: FakeScanService()
    app.add_middleware(RequestAuditMiddleware)
    return app


explicit_events: list[dict[str, Any]] = []


@pytest.fixture
def client(idp: FakeIdp, audit: FakeAudit) -> TestClient:
    explicit_events.clear()
    return TestClient(_build_app(), base_url=BASE, follow_redirects=False)


CSRF = {"X-Hecate-Request": "1"}


def _login(client: TestClient, idp: FakeIdp, return_to: str = "/scans") -> httpx.Response:
    start = client.get("/api/v1/auth/login", params={"returnTo": return_to})
    assert start.status_code == 302, start.text
    query = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
    idp.codes["code-1"] = {
        "challenge": query["code_challenge"],
        "nonce": query["nonce"],
        "redirect_uri": query["redirect_uri"],
    }
    return client.get("/api/v1/auth/callback", params={"code": "code-1", "state": query["state"]})


def _login_as(client: TestClient, idp: FakeIdp, groups: list[str]) -> None:
    idp.claims["groups"] = groups
    response = _login(client, idp)
    assert response.status_code == 302 and "authError" not in response.headers["location"], response.headers


# --- Sign-in flow ---------------------------------------------------------------


def test_login_redirects_with_pkce_state_and_nonce(client: TestClient) -> None:
    response = client.get("/api/v1/auth/login")
    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    query = parse_qs(location.query)
    assert location.netloc == "idp.test"
    assert query["code_challenge_method"] == ["S256"]
    assert query["response_type"] == ["code"]
    assert query["client_id"] == [CLIENT_ID]
    assert query["redirect_uri"] == [f"{BASE}/api/v1/auth/callback"]
    assert len(query["state"][0]) >= 32 and len(query["nonce"][0]) >= 32
    cookie = response.headers["set-cookie"]
    assert "hecate_login=" in cookie and "HttpOnly" in cookie and "Path=/api/v1/auth" in cookie


def test_full_login_sets_a_session_cookie_and_returns(client: TestClient, idp: FakeIdp, audit: FakeAudit) -> None:
    response = _login(client, idp, "/scans?tab=findings")
    assert response.status_code == 302
    assert response.headers["location"] == "/scans?tab=findings"
    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(c for c in cookies if c.startswith("hecate_session="))
    assert "HttpOnly" in session_cookie
    assert "Secure" in session_cookie
    assert "SameSite=lax" in session_cookie or "samesite=lax" in session_cookie.lower()
    assert "Path=/" in session_cookie
    # The client authenticates with HTTP Basic (confidential client) and sends the PKCE verifier.
    request = idp.token_requests[-1]
    assert request["auth"].startswith("Basic ")
    assert "code_verifier" in request["form"]
    me = client.get("/api/v1/auth/me").json()
    assert me["authenticated"] is True
    assert me["user"] == {"name": "Ada Admin", "email": "ada@example.com", "role": "admin"}
    login_events = [e for e in audit.events if e[0] == "auth_login"]
    assert login_events and login_events[-1][1]["status"] == "completed"


def test_the_session_store_never_holds_the_cookie_value(client: TestClient, idp: FakeIdp) -> None:
    response = _login(client, idp)
    token = client.cookies.get("hecate_session")
    assert token
    repo = auth_session_service._service.repository  # type: ignore[union-attr]
    assert all(token not in key for key in repo.docs)
    assert all(doc.get("kind") == "session" for doc in repo.docs.values())
    assert response.status_code == 302


def test_a_replayed_callback_is_refused(client: TestClient, idp: FakeIdp) -> None:
    start = client.get("/api/v1/auth/login")
    query = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
    idp.codes["c"] = {"challenge": query["code_challenge"], "nonce": query["nonce"], "redirect_uri": query["redirect_uri"]}
    login_cookie = client.cookies.get("hecate_login")
    first = client.get("/api/v1/auth/callback", params={"code": "c", "state": query["state"]})
    assert "authError" not in first.headers["location"]
    client.cookies.set("hecate_login", login_cookie, domain="hecate.test", path="/api/v1/auth")
    second = client.get("/api/v1/auth/callback", params={"code": "c", "state": query["state"]})
    assert second.headers["location"] == "/?authError=invalid_state"


def test_a_wrong_state_is_refused(client: TestClient, idp: FakeIdp, audit: FakeAudit) -> None:
    client.get("/api/v1/auth/login")
    response = client.get("/api/v1/auth/callback", params={"code": "x", "state": "forged"})
    assert response.headers["location"] == "/?authError=invalid_state"
    assert audit.events[-1][0] == "auth_login" and audit.events[-1][1]["status"] == "failed"


def test_a_callback_without_the_login_cookie_is_refused(client: TestClient, idp: FakeIdp) -> None:
    start = client.get("/api/v1/auth/login")
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    client.cookies.clear()
    response = client.get("/api/v1/auth/callback", params={"code": "x", "state": state})
    assert response.headers["location"] == "/?authError=invalid_state"


def test_an_idp_error_is_reported_without_its_description(client: TestClient, audit: FakeAudit) -> None:
    client.get("/api/v1/auth/login")
    response = client.get("/api/v1/auth/callback", params={"error": "access_denied", "error_description": "<b>x</b>"})
    assert response.headers["location"] == "/?authError=idp_error"
    assert "<b>" not in str(audit.events[-1])


@pytest.mark.parametrize(
    "token_factory",
    [
        pytest.param(lambda idp, nonce: idp.sign(
            {"iss": ISSUER, "aud": CLIENT_ID, "iat": int(time.time()), "exp": int(time.time()) + 300,
             "nonce": nonce, "sub": "u-1"}, key=_rsa_key()), id="bad-signature"),
        pytest.param(lambda idp, nonce: idp.id_token(nonce, iss="https://evil.test"), id="wrong-issuer"),
        pytest.param(lambda idp, nonce: idp.id_token(nonce, aud="someone-else"), id="wrong-audience"),
        pytest.param(lambda idp, nonce: idp.id_token(nonce, exp=int(time.time()) - 3600,
                                                     iat=int(time.time()) - 7200), id="expired"),
        pytest.param(lambda idp, nonce: idp.id_token("another-nonce"), id="wrong-nonce"),
        pytest.param(lambda idp, nonce: idp.id_token(nonce, aud=[CLIENT_ID, "other"], azp="other"), id="wrong-azp"),
        pytest.param(lambda idp, nonce: jwt.encode(
            {"iss": ISSUER, "aud": CLIENT_ID, "iat": int(time.time()), "exp": int(time.time()) + 300,
             "nonce": nonce, "sub": "u-1"}, "secret", algorithm="HS256", headers={"kid": "k1"}), id="hs256"),
        pytest.param(lambda idp, nonce: jwt.encode(
            {"iss": ISSUER, "aud": CLIENT_ID, "iat": int(time.time()), "exp": int(time.time()) + 300,
             "nonce": nonce, "sub": "u-1"}, None, algorithm="none"), id="alg-none"),
        pytest.param(lambda idp, nonce: idp.id_token(nonce, sub=None), id="no-subject"),
    ],
)
def test_invalid_id_tokens_are_refused(client: TestClient, idp: FakeIdp, token_factory: Any) -> None:
    idp.id_token_override = lambda nonce: token_factory(idp, nonce)
    response = _login(client, idp)
    assert response.headers["location"] == "/?authError=invalid_token"
    assert client.cookies.get("hecate_session") is None


def test_a_rotated_signing_key_is_fetched(client: TestClient, idp: FakeIdp) -> None:
    _login(client, idp)  # caches the first key set
    new_key = _rsa_key()
    idp.key, idp.kid = new_key, "k2"
    idp.jwks = [_jwk(new_key, "k2")]
    client.cookies.clear()
    response = _login(client, idp)
    assert "authError" not in response.headers["location"]


def test_an_account_without_a_hecate_group_is_denied(
    client: TestClient, idp: FakeIdp, audit: FakeAudit, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "oidc_viewer_groups", "hecate-viewers")
    idp.claims["groups"] = ["marketing"]
    response = _login(client, idp)
    assert response.headers["location"] == "/?authError=no_role"
    assert client.cookies.get("hecate_session") is None
    job, event = audit.events[-1]
    assert job == "auth_login" and event["metadata"]["reason"] == "no_role"
    assert event["metadata"]["user"]["email"] == "ada@example.com"


def test_open_redirects_land_on_the_start_page(client: TestClient, idp: FakeIdp) -> None:
    for target in ("//evil.test/x", "https://evil.test", "/\\evil.test", "/api/v1/things"):
        client.cookies.clear()
        assert _login(client, idp, target).headers["location"] == "/"


def test_logout_ends_the_session_and_offers_rp_logout(client: TestClient, idp: FakeIdp) -> None:
    _login(client, idp)
    refused = client.post("/api/v1/auth/logout")
    assert refused.status_code == 403
    response = client.post("/api/v1/auth/logout", headers=CSRF)
    assert response.status_code == 200
    logout_url = response.json()["logoutUrl"]
    assert logout_url.startswith(f"{ISSUER}/protocol/openid-connect/logout?")
    assert "id_token_hint=" in logout_url and "post_logout_redirect_uri=" in logout_url
    assert client.get("/api/v1/auth/me").json()["authenticated"] is False


def test_an_idle_session_expires(client: TestClient, idp: FakeIdp) -> None:
    from datetime import UTC, datetime, timedelta

    _login(client, idp)
    repo = auth_session_service._service.repository  # type: ignore[union-attr]
    for doc in repo.docs.values():
        doc["last_seen_at"] = datetime.now(UTC) - timedelta(minutes=settings.auth_session_idle_minutes + 1)
    assert client.get("/api/v1/auth/me").json()["authenticated"] is False


# --- Role mapping -----------------------------------------------------------------


def test_roles_from_a_nested_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "oidc_roles_claim", "realm_access.roles")
    monkeypatch.setattr(settings, "oidc_admin_groups", "admin")
    monkeypatch.setattr(settings, "oidc_editor_groups", "editor")
    monkeypatch.setattr(settings, "oidc_viewer_groups", "viewer")
    assert oidc_client.resolve_role({"realm_access": {"roles": ["offline_access", "editor"]}}) == "editor"
    assert oidc_client.resolve_role({"realm_access": {"roles": ["admin", "editor"]}}) == "admin"
    assert oidc_client.resolve_role({"realm_access": {"roles": ["other"]}}) is None
    assert oidc_client.resolve_role({}) is None


def test_role_names_tolerate_keycloak_paths_case_and_dict_claims(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "oidc_roles_claim", "urn:zitadel:iam:org:project:roles")
    monkeypatch.setattr(settings, "oidc_admin_groups", "Hecate-Admins")
    monkeypatch.setattr(settings, "oidc_editor_groups", "")
    monkeypatch.setattr(settings, "oidc_viewer_groups", "")
    claims = {"urn:zitadel:iam:org:project:roles": {"hecate-admins": {"123": "org"}}}
    assert oidc_client.resolve_role(claims) == "admin"
    monkeypatch.setattr(settings, "oidc_roles_claim", "groups")
    assert oidc_client.resolve_role({"groups": ["/hecate-admins"]}) == "admin"
    # Empty viewer list: any signed-in user can read.
    assert oidc_client.resolve_role({"groups": []}) == "viewer"


def test_roles_can_come_from_userinfo(client: TestClient, idp: FakeIdp) -> None:
    idp.claims.pop("groups")
    idp.userinfo_claims = {"groups": ["hecate-editors"]}
    _login(client, idp)
    assert client.get("/api/v1/auth/me").json()["user"]["role"] == "editor"


def test_symmetric_algorithms_cannot_be_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "oidc_allowed_algs", "RS256,HS256,none,hs512,ES256")
    assert oidc_client.allowed_algorithms() == ["RS256", "ES256"]


# --- Gates by role ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("groups", "admin", "editor", "target", "password_change", "tokens"),
    [
        (["hecate-admins"], 200, 200, 200, 200, 200),
        (["hecate-editors"], 403, 200, 200, 403, 403),
        ([], 403, 403, 403, 403, 403),
    ],
    ids=["admin", "editor", "viewer"],
)
def test_gate_by_role(
    client: TestClient, idp: FakeIdp, groups: list[str], admin: int, editor: int, target: int,
    password_change: int, tokens: int,
) -> None:
    _login_as(client, idp, groups)
    assert client.post("/api/v1/admin-write", headers=CSRF).status_code == admin
    assert client.post("/api/v1/editor-write", headers=CSRF).status_code == editor
    assert client.patch("/api/v1/scans/targets/repo-1", headers=CSRF).status_code == target
    assert client.put("/api/v1/scans/targets/repo-1/write-password", headers=CSRF).status_code == password_change
    assert client.get("/api/v1/tokens").status_code == tokens
    denied = client.post("/api/v1/admin-write", headers=CSRF)
    if denied.status_code == 403:
        # A signed-in user is told which role is missing, never asked for a password.
        assert denied.headers["x-auth-role-required"] == "admin"
        assert "x-write-auth-required" not in denied.headers


def test_a_viewer_with_the_target_password_may_still_write(client: TestClient, idp: FakeIdp) -> None:
    _login_as(client, idp, [])
    headers = {**CSRF, "X-Target-Password": TARGET_PASSWORD}
    assert client.patch("/api/v1/scans/targets/repo-1", headers=headers).status_code == 200


def test_an_editor_owning_the_target_may_change_its_password(client: TestClient, idp: FakeIdp) -> None:
    _login_as(client, idp, ["hecate-editors"])
    headers = {**CSRF, "X-Target-Password": TARGET_PASSWORD}
    assert client.put("/api/v1/scans/targets/repo-1/write-password", headers=headers).status_code == 200


def test_an_editor_with_the_system_password_passes_the_admin_gate(
    client: TestClient, idp: FakeIdp, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "system_password", SYSTEM_PASSWORD)
    _login_as(client, idp, ["hecate-editors"])
    headers = {**CSRF, "X-System-Password": SYSTEM_PASSWORD}
    assert client.post("/api/v1/admin-write", headers=headers).status_code == 200


def test_anonymous_writes_need_a_sign_in_once_oidc_is_on(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "auth_require_login", False)
    response = client.post("/api/v1/admin-write")
    assert response.status_code == 401
    assert response.headers["x-auth-required"] == "login"
    monkeypatch.setattr(settings, "system_password", SYSTEM_PASSWORD)
    response = client.post("/api/v1/admin-write")
    assert response.status_code == 401
    assert response.headers["x-write-auth-required"] == "admin"
    assert response.headers["x-auth-required"] == "login"
    ok = client.post("/api/v1/admin-write", headers={"X-System-Password": SYSTEM_PASSWORD})
    assert ok.status_code == 200


def test_the_ai_password_stays_a_lock_for_everyone(
    client: TestClient, idp: FakeIdp, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "ai_analysis_password", "ai-pw")
    _login_as(client, idp, ["hecate-admins"])
    assert client.post("/api/v1/ai-write", headers=CSRF).status_code == 401
    assert client.post("/api/v1/ai-write", headers={**CSRF, "X-AI-Analysis-Password": "ai-pw"}).status_code == 200


def test_viewers_cannot_run_ai_even_with_the_ai_password(
    client: TestClient, idp: FakeIdp, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "ai_analysis_password", "ai-pw")
    _login_as(client, idp, [])
    response = client.post("/api/v1/ai-write", headers={**CSRF, "X-AI-Analysis-Password": "ai-pw"})
    assert response.status_code == 403


def test_without_an_ai_password_an_editor_runs_ai(client: TestClient, idp: FakeIdp) -> None:
    _login_as(client, idp, ["hecate-editors"])
    assert client.post("/api/v1/ai-write", headers=CSRF).status_code == 200


def test_a_signed_in_admin_skips_the_system_password_dialog(
    client: TestClient, idp: FakeIdp, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "system_password", SYSTEM_PASSWORD)
    assert client.get("/api/v1/status/system-auth").status_code == 401  # login required, nobody signed in
    _login_as(client, idp, ["hecate-admins"])
    assert client.get("/api/v1/status/system-auth").json() == {
        "required": False, "authenticated": True, "adminRequired": False, "passwordAccepted": False,
    }


# --- System settings reads -----------------------------------------------------------


def test_settings_reads_need_the_admin_even_when_login_is_optional(
    client: TestClient, idp: FakeIdp, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "auth_require_login", False)
    assert client.get("/api/v1/things").status_code == 200  # data stays public
    anonymous = client.get("/api/v1/settings")
    assert anonymous.status_code == 401
    assert anonymous.headers["x-auth-required"] == "login"
    status = client.get("/api/v1/status/system-auth").json()
    assert status["adminRequired"] is True and status["passwordAccepted"] is False
    _login_as(client, idp, [])  # viewer
    refused = client.get("/api/v1/settings")
    assert refused.status_code == 403
    assert refused.headers["x-auth-role-required"] == "admin"
    _login_as(client, idp, ["hecate-admins"])
    assert client.get("/api/v1/settings").status_code == 200


def test_the_system_password_opens_settings_reads_without_counting_bare_visits(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "auth_require_login", False)
    monkeypatch.setattr(settings, "system_password", SYSTEM_PASSWORD)
    # Opening the page without a password is no guess: it never locks the client out.
    for _ in range(15):
        assert client.get("/api/v1/settings").status_code == 401
    assert client.get("/api/v1/settings", headers={"X-System-Password": SYSTEM_PASSWORD}).status_code == 200
    assert client.get("/api/v1/settings", headers={"X-System-Password": "wrong"}).status_code == 401


def test_settings_reads_without_oidc_follow_the_system_password(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "oidc_issuer", "")
    assert client.get("/api/v1/settings").status_code == 200  # fail-open, as every admin gate
    monkeypatch.setattr(settings, "system_password", SYSTEM_PASSWORD)
    assert client.get("/api/v1/settings").status_code == 401
    assert client.get("/api/v1/settings", headers={"X-System-Password": SYSTEM_PASSWORD}).status_code == 200


# --- CSRF -----------------------------------------------------------------------------


def test_cookie_writes_need_the_csrf_header(client: TestClient, idp: FakeIdp) -> None:
    _login_as(client, idp, ["hecate-admins"])
    assert client.post("/api/v1/admin-write").status_code == 403
    cross_site = {**CSRF, "Sec-Fetch-Site": "cross-site"}
    assert client.post("/api/v1/admin-write", headers=cross_site).status_code == 403
    assert client.post("/api/v1/admin-write", headers={**CSRF, "Sec-Fetch-Site": "same-origin"}).status_code == 200


def test_reads_with_a_session_need_no_csrf_header(client: TestClient, idp: FakeIdp) -> None:
    _login_as(client, idp, [])
    assert client.get("/api/v1/things").status_code == 200


# --- Read gating -------------------------------------------------------------------------


def test_reads_need_a_caller_when_login_is_required(client: TestClient) -> None:
    response = client.get("/api/v1/things")
    assert response.status_code == 401
    assert response.headers["x-auth-required"] == "login"


@pytest.mark.parametrize("path", ["/api/v1/status/health", "/api/v1/config", "/api/v1/scans/s-1/shield",
                                  "/api/v1/auth/me"])
def test_public_routes_stay_open(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 200


def test_scripts_read_with_their_credentials(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    async def tokens() -> FakeTokenService:
        return FakeTokenService()

    monkeypatch.setattr(api_token_service, "get_api_token_service", tokens)
    monkeypatch.setattr(settings, "system_password", SYSTEM_PASSWORD)
    assert client.get("/api/v1/things", headers={"X-API-Key": "ci-key"}).status_code == 200
    assert client.get("/api/v1/things", headers={"X-API-Key": "hct_" + "a" * 43}).status_code == 200
    assert client.get("/api/v1/things", headers={"X-System-Password": SYSTEM_PASSWORD}).status_code == 200
    assert client.get("/api/v1/things", headers={"X-API-Key": "hct_" + "b" * 43}).status_code == 401
    assert client.get("/api/v1/things", headers={"X-System-Password": "wrong"}).status_code == 401


def test_read_routes_do_not_accept_a_target_password(client: TestClient) -> None:
    response = client.post("/api/v1/vulnerabilities/search", headers={"X-Target-Password": "anything"})
    assert response.status_code == 401


def test_reads_stay_public_when_login_is_optional(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "auth_require_login", False)
    assert client.get("/api/v1/things").status_code == 200


def test_without_oidc_nothing_changes(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "oidc_issuer", "")
    monkeypatch.setattr(settings, "auth_require_login", True)
    assert settings.auth_login_required is False
    assert client.get("/api/v1/things").status_code == 200
    # Fail-open admin gate exactly as before.
    assert client.post("/api/v1/admin-write").status_code == 200
    assert client.get("/api/v1/auth/login").status_code == 404


# --- Audit trail ----------------------------------------------------------------------------


def _api_events(audit: FakeAudit) -> list[dict[str, Any]]:
    return [kwargs for job, kwargs in audit.events if job == "api_request"]


def test_writes_are_recorded_with_actor_route_and_status(client: TestClient, idp: FakeIdp, audit: FakeAudit) -> None:
    _login_as(client, idp, ["hecate-editors"])
    client.patch("/api/v1/scans/targets/https://user:tok@git.test/repo.git", headers=CSRF)
    event = _api_events(audit)[-1]
    meta = event["metadata"]
    assert meta["method"] == "PATCH"
    assert meta["route"] == "/scans/targets/{target_id:path}"
    assert meta["statusCode"] == 200 and meta["outcome"] == "success"
    assert meta["actor"]["type"] == "user" and meta["actor"]["role"] == "editor"
    assert meta["actor"]["email"] == "ada@example.com"
    assert "tok" not in meta["pathParams"]["target_id"]
    assert meta["clientIp"]


def test_refused_writes_are_recorded(client: TestClient, idp: FakeIdp, audit: FakeAudit) -> None:
    _login_as(client, idp, [])
    client.post("/api/v1/admin-write", headers=CSRF)
    event = _api_events(audit)[-1]
    assert event["status"] == "failed"
    assert event["metadata"]["outcome"] == "denied" and event["metadata"]["statusCode"] == 403
    assert "admin role" in event["error"]


def test_refused_cross_site_write_names_the_session_owner(client: TestClient, idp: FakeIdp, audit: FakeAudit) -> None:
    _login_as(client, idp, ["hecate-admins"])
    assert client.post("/api/v1/admin-write").status_code == 403  # cookie, no X-Hecate-Request
    actor = _api_events(audit)[-1]["metadata"]["actor"]
    assert actor["type"] == "session_refused" and actor["reason"] == "csrf"
    assert actor["email"] == "ada@example.com"
    assert "session refused" in actor["label"]


def test_read_posts_are_not_recorded(client: TestClient, idp: FakeIdp, audit: FakeAudit) -> None:
    _login_as(client, idp, [])
    client.post("/api/v1/vulnerabilities/search", headers=CSRF)
    assert _api_events(audit) == []


def test_password_checks_are_recorded_as_auth_events(
    client: TestClient, audit: FakeAudit, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "auth_require_login", False)
    monkeypatch.setattr(settings, "system_password", SYSTEM_PASSWORD)
    client.post("/api/v1/status/system-auth", json={"password": "wrong"})
    job, event = audit.events[-1]
    assert job == "auth_password_check" and event["status"] == "failed"
    assert "wrong" not in str(event)


def test_a_richer_explicit_event_is_not_repeated(client: TestClient, idp: FakeIdp, audit: FakeAudit) -> None:
    _login_as(client, idp, ["hecate-editors"])
    assert client.post("/api/v1/explicit", headers=CSRF).status_code == 200
    assert _api_events(audit) == []
    assert explicit_events[-1]["metadata"]["actor"]["name"] == "Ada Admin"


def test_an_audit_failure_does_not_fail_the_request(
    client: TestClient, idp: FakeIdp, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("mongo down")

    _login_as(client, idp, ["hecate-admins"])
    monkeypatch.setattr(request_audit, "audit_sink", broken)
    assert client.post("/api/v1/admin-write", headers=CSRF).status_code == 200


def test_password_actors_without_oidc(client: TestClient, audit: FakeAudit, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "oidc_issuer", "")
    client.post("/api/v1/admin-write")
    assert _api_events(audit)[-1]["metadata"]["actor"] == {"type": "anonymous", "label": "Anonymous"}
    monkeypatch.setattr(settings, "system_password", SYSTEM_PASSWORD)
    client.post("/api/v1/admin-write", headers={"X-System-Password": SYSTEM_PASSWORD})
    assert _api_events(audit)[-1]["metadata"]["actor"]["type"] == "system_password"
    client.patch("/api/v1/scans/targets/repo-1", headers={"X-Target-Password": TARGET_PASSWORD})
    actor = _api_events(audit)[-1]["metadata"]["actor"]
    assert actor == {"type": "target_password", "target": "repo-1", "label": "Target password (repo-1)"}


@pytest.mark.parametrize(
    "path",
    ["/api/v1/audit/ingestion", "/api/v1/notifications/channels", "/api/v1/notifications/rules",
     "/api/v1/sync/states", "/api/v1/advisory-feeds", "/api/v1/backup/inventory/export"],
)
def test_settings_and_audit_reads_are_admin_only_on_the_real_router(
    idp: FakeIdp, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    """The production routers, not a test route: the gate answers before any handler runs."""
    from app.api.v1.routes import api_router

    monkeypatch.setattr(settings, "auth_require_login", False)
    app = FastAPI()
    app.include_router(api_router, prefix=settings.api_prefix)
    response = TestClient(app, base_url=BASE).get(path)
    assert response.status_code == 401, response.text
    assert response.headers["x-auth-required"] == "login"


def test_public_base_url_trusts_forwarded_headers_only_from_proxies(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.auth_context import public_base_url

    monkeypatch.setattr(settings, "auth_public_url", "")
    scope = {
        "type": "http", "scheme": "http", "server": ("backend", 8000), "path": "/", "query_string": b"",
        "client": ("10.0.0.5", 1234),
        "headers": [(b"host", b"backend:8000"), (b"x-forwarded-proto", b"https"), (b"x-forwarded-host", b"evil.test")],
    }
    monkeypatch.setattr(settings, "trusted_proxy_ips_raw", None)
    assert public_base_url(Request(scope)) == "http://backend:8000"
    monkeypatch.setattr(settings, "trusted_proxy_ips_raw", "10.0.0.5")
    assert public_base_url(Request(scope)) == "https://evil.test"
    monkeypatch.setattr(settings, "auth_public_url", "https://hecate.example/")
    assert public_base_url(Request(scope)) == "https://hecate.example"


def test_signing_in_again_replaces_the_old_session(client: TestClient, idp: FakeIdp) -> None:
    _login(client, idp)
    first = client.cookies.get("hecate_session")
    _login(client, idp)
    repo = auth_session_service._service.repository  # type: ignore[union-attr]
    sessions = [doc for doc in repo.docs.values() if doc.get("kind") == "session"]
    assert len(sessions) == 1
    assert client.cookies.get("hecate_session") != first


# --- Personal preferences -------------------------------------------------------


class FakePreferencesRepo:
    def __init__(self) -> None:
        self.docs: dict[str, dict[str, Any]] = {}

    async def get(self, key: str) -> dict[str, Any] | None:
        return self.docs.get(key)

    async def save(self, key: str, preferences: dict[str, Any]) -> Any:
        from datetime import UTC, datetime

        now = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)
        self.docs[key] = {"_id": key, "preferences": preferences, "updated_at": now}
        return now


@pytest.fixture
def prefs_repo(monkeypatch: pytest.MonkeyPatch) -> FakePreferencesRepo:
    repo = FakePreferencesRepo()

    async def get_repo() -> FakePreferencesRepo:
        return repo

    monkeypatch.setattr(auth_api, "get_user_preferences_repository", get_repo)
    return repo


def test_preferences_need_a_sign_in(client: TestClient, prefs_repo: FakePreferencesRepo) -> None:
    response = client.get("/api/v1/auth/me/preferences")
    assert response.status_code == 401
    assert response.headers["X-Auth-Required"] == "login"
    assert client.put("/api/v1/auth/me/preferences", json={}, headers=CSRF).status_code == 401


def test_preferences_are_kept_per_account(
    client: TestClient, idp: FakeIdp, audit: FakeAudit, prefs_repo: FakePreferencesRepo
) -> None:
    _login_as(client, idp, ["hecate-viewers-none"])
    assert client.get("/api/v1/auth/me/preferences").json() == {
        "language": None, "timezone": None, "dashboardOnlyMyStack": False, "updatedAt": None,
    }
    body = {"language": "de", "timezone": "Europe/Vienna", "dashboardOnlyMyStack": True}
    assert client.put("/api/v1/auth/me/preferences", json=body).status_code == 403  # no CSRF header
    saved = client.put("/api/v1/auth/me/preferences", json=body, headers=CSRF)
    assert saved.status_code == 200, saved.text
    assert client.get("/api/v1/auth/me/preferences").json() == {**body, "updatedAt": "2026-11-26T09:00:00Z"}
    (key,) = prefs_repo.docs
    assert key == f"{ISSUER}|{idp.claims['sub']}"
    written = [e for e in _api_events(audit) if e["metadata"]["route"] == "/auth/me/preferences"]
    assert [e["metadata"]["outcome"] for e in written] == ["denied", "success"]


def test_preferences_refuse_unknown_values(client: TestClient, idp: FakeIdp, prefs_repo: FakePreferencesRepo) -> None:
    _login_as(client, idp, ["hecate-viewers-none"])
    for body in ({"timezone": "Mars/Olympus"}, {"language": "fr"}, {"theme": "light"}):
        assert client.put("/api/v1/auth/me/preferences", json=body, headers=CSRF).status_code == 422
    assert prefs_repo.docs == {}
