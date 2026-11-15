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
import pytest

from app.utils.request import get_security_client_ip, is_trusted_proxy
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


@pytest.mark.parametrize(
    ("entries", "peer", "trusted"),
    [
        ("172.16.0.0/12", "172.18.0.7", True),          # Docker network, any container address
        ("172.16.0.0/12", "172.32.0.1", False),
        ("10.0.0.0/8,192.168.0.0/16", "192.168.1.20", True),
        ("fd00::/8", "fd12:3456::9", True),
        ("172.16.0.0/12", "::ffff:172.18.0.7", True),   # IPv4-mapped peer
        ("172.18.0.2", "172.18.0.2", True),             # exact address, as before
        ("172.18.0.2", "172.18.0.3", False),
        ("*", "203.0.113.1", True),
        ("unresolvable.invalid", "203.0.113.1", False),
        ("", "172.18.0.7", False),
    ],
)
def test_trusted_proxies_accept_cidr_ranges(monkeypatch, entries, peer, trusted):
    monkeypatch.setattr("app.utils.request.settings", Settings(environment="production", trusted_proxy_ips=entries or None))
    assert is_trusted_proxy(peer) is trusted


def test_trusted_proxy_by_host_name_follows_the_container(monkeypatch):
    import app.utils.request as request_utils

    monkeypatch.setattr(request_utils, "settings", Settings(environment="production", trusted_proxy_ips="frontend"))
    monkeypatch.setattr(request_utils, "_resolved_hosts", {})
    answers = {"frontend": ["172.18.0.4"]}
    calls = []

    def fake_getaddrinfo(host, *_args, **_kwargs):
        calls.append(host)
        return [(2, 1, 6, "", (ip, 0)) for ip in answers[host]]

    monkeypatch.setattr(request_utils.socket, "getaddrinfo", fake_getaddrinfo)
    assert is_trusted_proxy("172.18.0.4") is True
    assert is_trusted_proxy("172.18.0.9") is False  # a neighbour on the same network
    assert calls == ["frontend"]  # cached between requests

    # Recreated container, new address: picked up once the cache expires.
    answers["frontend"] = ["172.18.0.7"]
    monkeypatch.setattr(request_utils, "_resolved_hosts", {"frontend": (-1e9, frozenset({"172.18.0.4"}))})
    assert is_trusted_proxy("172.18.0.7") is True

    # A failed lookup keeps the last answer instead of trusting nobody.
    def broken(*_args, **_kwargs):
        raise OSError("dns down")

    monkeypatch.setattr(request_utils.socket, "getaddrinfo", broken)
    monkeypatch.setattr(request_utils, "_resolved_hosts", {"frontend": (-1e9, frozenset({"172.18.0.7"}))})
    assert is_trusted_proxy("172.18.0.7") is True


def test_forwarded_ip_is_read_from_a_proxy_inside_a_trusted_range(monkeypatch):
    # The frontend gateway is recreated with a new address from its network's subnet.
    monkeypatch.setattr(
        "app.utils.request.settings",
        Settings(environment="production", trusted_proxy_ips="172.16.0.0/12"),
    )
    req = _req("172.19.0.5", {"x-forwarded-for": "203.0.113.9"})
    assert get_security_client_ip(req) == "203.0.113.9"


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
    reg = c.post("/mcp/oauth/register", json={"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"], "client_name": "t"})
    cid = reg.json()["client_id"]
    r = c.get(
        "/mcp/oauth/authorize",
        params={"client_id": cid, "redirect_uri": "https://evil/", "code_challenge": "abc"},
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_authorize_requires_pkce_challenge():
    c = _oauth_client()
    reg = c.post("/mcp/oauth/register", json={"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]})
    cid = reg.json()["client_id"]
    r = c.get(
        "/mcp/oauth/authorize",
        params={"client_id": cid, "redirect_uri": "https://claude.ai/api/mcp/auth_callback"},  # no code_challenge
        follow_redirects=False,
    )
    assert r.status_code == 400


# --------------------------------------------------------------------------
# MCP_ALLOWED_REDIRECT_HOSTS — DCR can't register an attacker redirect_uri
# --------------------------------------------------------------------------

def _redirect_allowed(monkeypatch, uri: str, hosts: str | None = None) -> bool:
    from app.mcp import oauth

    if hosts is not None:
        monkeypatch.setattr(oauth.settings, "mcp_allowed_redirect_hosts", hosts)
    return oauth._redirect_uri_allowed(uri)


def test_default_redirect_hosts_accept_known_clients(monkeypatch):
    assert _redirect_allowed(monkeypatch, "https://claude.ai/api/mcp/auth_callback")
    assert _redirect_allowed(monkeypatch, "http://localhost:33418/callback")
    assert _redirect_allowed(monkeypatch, "http://127.0.0.1:5173/oauth")
    assert _redirect_allowed(monkeypatch, "http://[::1]:8080/cb")


def test_redirect_hosts_reject_attacker_and_tricks(monkeypatch):
    assert not _redirect_allowed(monkeypatch, "https://evil.example/cb")
    assert not _redirect_allowed(monkeypatch, "https://claude.ai.evil.example/cb")
    assert not _redirect_allowed(monkeypatch, "https://claude.ai@evil.example/cb")
    assert not _redirect_allowed(monkeypatch, "http://claude.ai/cb")  # plain http off-loopback
    assert not _redirect_allowed(monkeypatch, "https://claude.ai/cb#frag")
    assert not _redirect_allowed(monkeypatch, "javascript:alert(1)")


def test_redirect_hosts_wildcard_and_custom_scheme(monkeypatch):
    hosts = "*.example.org,anysphere.cursor-mcp"
    assert _redirect_allowed(monkeypatch, "https://mcp.example.org/cb", hosts)
    assert not _redirect_allowed(monkeypatch, "https://example.org.evil/cb", hosts)
    assert _redirect_allowed(monkeypatch, "cursor://anysphere.cursor-mcp/oauth/callback", hosts)


def test_register_rejects_disallowed_redirect_uri():
    c = _oauth_client()
    r = c.post("/mcp/oauth/register", json={"redirect_uris": ["https://evil.example/cb"]})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_redirect_uri"
