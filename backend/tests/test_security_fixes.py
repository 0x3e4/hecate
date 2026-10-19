"""Regression tests for the security-audit remediations.

Each test here fails against the pre-fix code and passes with the fix:
  * spoofable X-Forwarded-For no longer grants a safelisted/authoritative IP,
  * user search input is escaped before reaching a MongoDB ``$regex``,
  * notification channel URLs are redacted on the read path,
  * the MCP no-auth bypass is inert in a production-like environment.
"""
from __future__ import annotations

from types import SimpleNamespace

from starlette.datastructures import Headers

from app.api.v1.notifications import _redact_channel_url
from app.core.config import Settings
from app.utils.request import get_security_client_ip
from app.utils.strings import contains_regex


def _req(host: str, headers: dict[str, str] | None = None):
    return SimpleNamespace(client=SimpleNamespace(host=host), headers=Headers(headers or {}))


# --------------------------------------------------------------------------
# get_security_client_ip — spoof-resistant client IP for security decisions
# --------------------------------------------------------------------------

def test_xff_ignored_when_no_trusted_proxy(monkeypatch):
    # Default deployment (no TRUSTED_PROXY_IPS): a client-supplied XFF must be
    # ignored entirely — the direct peer is authoritative.
    monkeypatch.setattr("app.utils.request.settings", Settings(environment="production"))
    req = _req("203.0.113.9", {"x-forwarded-for": "10.0.0.5"})
    assert get_security_client_ip(req) == "203.0.113.9"


def test_spoofed_leftmost_xff_not_trusted_behind_proxy(monkeypatch):
    # Behind a trusted proxy, nginx appends the real peer to the RIGHT of any
    # client-supplied value. The attacker prepends a safelisted IP on the left;
    # we must return the right-most (proxy-observed) hop, not the spoofed one.
    monkeypatch.setattr(
        "app.utils.request.settings",
        Settings(environment="production", trusted_proxy_ips="172.18.0.2"),
    )
    req = _req("172.18.0.2", {"x-forwarded-for": "10.0.0.5, 203.0.113.9"})
    assert get_security_client_ip(req) == "203.0.113.9"


def test_untrusted_peer_cannot_claim_forwarded_header(monkeypatch):
    # A direct connection from a non-proxy source can't use XFF to impersonate.
    monkeypatch.setattr(
        "app.utils.request.settings",
        Settings(environment="production", trusted_proxy_ips="172.18.0.2"),
    )
    req = _req("198.51.100.7", {"x-forwarded-for": "10.0.0.5"})
    assert get_security_client_ip(req) == "198.51.100.7"


# --------------------------------------------------------------------------
# contains_regex — literal, length-capped MongoDB $regex clause
# --------------------------------------------------------------------------

def test_contains_regex_escapes_metacharacters():
    clause = contains_regex("(a+)+$")
    # The ReDoS payload must be neutralised to a literal (every metachar escaped).
    assert clause["$options"] == "i"
    assert "(a+)+" not in clause["$regex"]
    assert clause["$regex"] == r"\(a\+\)\+\$"


def test_contains_regex_caps_length():
    clause = contains_regex("a" * 5000, max_length=200)
    assert len(clause["$regex"]) <= 200


def test_contains_regex_handles_empty_and_none():
    assert contains_regex("")["$regex"] == ""
    assert contains_regex(None)["$regex"] == ""  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# _redact_channel_url — never leak embedded credentials on the read path
# --------------------------------------------------------------------------

def test_redact_channel_url_masks_secret():
    assert _redact_channel_url("slack://TokenA/TokenB/TokenC") == "slack://***"
    assert _redact_channel_url("mailtos://user:pass@smtp.example.com") == "mailtos://***"
    assert "pass" not in _redact_channel_url("mailtos://user:pass@smtp.example.com")
    assert _redact_channel_url("") == ""


# --------------------------------------------------------------------------
# mcp_auth_bypass_active — dev-only no-auth bypass is inert in production
# --------------------------------------------------------------------------

def test_mcp_auth_bypass_refused_in_production():
    s = Settings(environment="production", mcp_auth_disabled=True)
    assert s.mcp_auth_bypass_active is False


def test_mcp_auth_bypass_allowed_in_development():
    s = Settings(environment="development", mcp_auth_disabled=True)
    assert s.mcp_auth_bypass_active is True


# --------------------------------------------------------------------------
# MCP OAuth authorize — strict redirect_uri + mandatory PKCE (Finding 3)
# These rejection paths return before any IdP/DB call, so they test in isolation.
# --------------------------------------------------------------------------

def _oauth_client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.mcp import oauth

    app = FastAPI()
    app.include_router(oauth.router)
    return TestClient(app)


def test_authorize_rejects_unknown_client_id():
    c = _oauth_client()
    r = c.get(
        "/mcp/oauth/authorize",
        params={"client_id": "not-registered", "redirect_uri": "https://x/cb", "code_challenge": "abc"},
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_authorize_rejects_unregistered_redirect_uri():
    c = _oauth_client()
    reg = c.post("/mcp/oauth/register", json={"redirect_uris": ["https://good/cb"], "client_name": "t"})
    cid = reg.json()["client_id"]
    r = c.get(
        "/mcp/oauth/authorize",
        params={"client_id": cid, "redirect_uri": "https://evil/", "code_challenge": "abc"},
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_authorize_requires_pkce_challenge():
    c = _oauth_client()
    reg = c.post("/mcp/oauth/register", json={"redirect_uris": ["https://good/cb"]})
    cid = reg.json()["client_id"]
    r = c.get(
        "/mcp/oauth/authorize",
        params={"client_id": cid, "redirect_uri": "https://good/cb"},  # no code_challenge
        follow_redirects=False,
    )
    assert r.status_code == 400
