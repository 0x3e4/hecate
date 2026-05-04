"""OAuth 2.0 Authorization Server for MCP that delegates user authentication to an upstream IdP.

Hecate exposes the AS endpoints required by the MCP spec (DCR + Auth Code + PKCE)
so that Claude Desktop / mcp-remote / Cursor / VS Code can self-register and run
the standard OAuth flow against /mcp. The actual human-facing consent step is
delegated to the configured IdP (GitHub / Microsoft Entra / generic OIDC) via a
nested OAuth flow:

  MCP client -> Hecate /authorize -> IdP authorize -> IdP callback -> Hecate /idp/callback
              -> Hecate mints auth code -> redirect back to MCP client -> /token (PKCE)
              -> Hecate access token bound to {identity, email, scope, ip}

Tokens carry the resolved upstream identity and a scope string. Read tools accept
any valid token; write tools additionally require the `mcp:write` scope which is
granted only when the user's source IP matches MCP_WRITE_IP_SAFELIST at
authorization time (and is re-checked at request time in `require_write_scope`).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from app.core.config import settings
from app.mcp import oauth_providers
from app.mcp.audit import log_oauth_event

log = structlog.get_logger()

router = APIRouter()

# In-memory stores (cleared on restart — acceptable for short-lived OAuth state).
_pending_auths: dict[str, dict[str, Any]] = {}  # idp_state -> pending MCP authorize request
_auth_codes: dict[str, dict[str, Any]] = {}  # MCP auth code -> {client_id, redirect_uri, code_challenge, scope, identity, email, ip, expires}
_registered_clients: dict[str, dict[str, Any]] = {}  # client_id -> DCR record
_access_tokens: dict[str, dict[str, Any]] = {}  # access_token -> {client_id, scope, identity, email, ip, expires}

_PENDING_TTL = 600  # 10 minutes for the entire IdP round-trip
_AUTH_CODE_TTL = 300
_ACCESS_TOKEN_TTL = 86400


@dataclass
class TokenInfo:
    identity: str
    email: str
    scope: str
    client_id: str
    issued_at_ip: str


def _base_url(request: Request) -> str:
    if settings.mcp_public_url:
        return settings.mcp_public_url.rstrip("/")
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", request.url.netloc)
    return f"{proto}://{host}"


def _client_ip(request: Request) -> str:
    """Resolve client IP, honouring X-Forwarded-For if present."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


def _cleanup_expired() -> None:
    now = time.time()
    for store in (_pending_auths, _auth_codes, _access_tokens):
        expired = [k for k, v in store.items() if v.get("expires", 0) < now]
        for k in expired:
            del store[k]


def _ip_in_safelist(ip_str: str, safelist_csv: str) -> bool:
    """Check if an IP is in a CSV of IPs/CIDRs. Returns False on parse error or empty list."""
    import ipaddress

    if not ip_str or not safelist_csv:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for entry in safelist_csv.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if ip == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            log.warning("mcp.oauth.bad_safelist_entry", entry=entry)
            continue
    return False


def _user_allowed(identity: str, email: str) -> bool:
    """Check identity/email against MCP_ALLOWED_USERS. Empty list = allow all."""
    raw = (settings.mcp_allowed_users or "").strip()
    if not raw:
        return True
    allowed = {item.strip().lower() for item in raw.split(",") if item.strip()}
    return identity.lower() in allowed or (email and email.lower() in allowed)


# ---------- OAuth Metadata (RFC 8414) ----------

def _as_metadata(request: Request) -> dict[str, Any]:
    base = _base_url(request)
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/mcp/oauth/authorize",
        "token_endpoint": f"{base}/mcp/oauth/token",
        "registration_endpoint": f"{base}/mcp/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["mcp:read", "mcp:write"],
    }


@router.get("/.well-known/oauth-authorization-server")
async def oauth_metadata(request: Request) -> JSONResponse:
    return JSONResponse(_as_metadata(request))


# Path-suffixed variant per RFC 8414 §3 / RFC 9728 §3.1 — clients that resolve
# the AS via the resource URL will append the resource path.
@router.get("/.well-known/oauth-authorization-server/mcp")
async def oauth_metadata_suffixed(request: Request) -> JSONResponse:
    return JSONResponse(_as_metadata(request))


# ---------- Protected Resource Metadata (RFC 9728) ----------

def _prm_metadata(request: Request) -> dict[str, Any]:
    base = _base_url(request)
    return {
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp:read", "mcp:write"],
    }


@router.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata(request: Request) -> JSONResponse:
    return JSONResponse(_prm_metadata(request))


# Path-suffixed variant per RFC 9728 §3.1 — for resource https://host/mcp the
# canonical metadata URL is https://host/.well-known/oauth-protected-resource/mcp.
# Latest Anthropic / Claude MCP clients fetch this form.
@router.get("/.well-known/oauth-protected-resource/mcp")
async def protected_resource_metadata_suffixed(request: Request) -> JSONResponse:
    return JSONResponse(_prm_metadata(request))


# ---------- Dynamic Client Registration (RFC 7591) ----------

@router.post("/mcp/oauth/register")
async def register_client(request: Request) -> JSONResponse:
    _cleanup_expired()
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    redirect_uris = body.get("redirect_uris", [])
    if not redirect_uris or not isinstance(redirect_uris, list):
        return JSONResponse(
            {"error": "invalid_request", "error_description": "redirect_uris required"},
            status_code=400,
        )

    client_id = secrets.token_urlsafe(24)
    client_secret = secrets.token_urlsafe(32)
    _registered_clients[client_id] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uris": redirect_uris,
        "client_name": body.get("client_name", "MCP Client"),
        "created_at": time.time(),
    }
    log.info("mcp.oauth.client_registered", client_id=client_id, name=body.get("client_name"))
    return JSONResponse(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": body.get("client_name", "MCP Client"),
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        },
        status_code=201,
    )


# ---------- Authorization Endpoint ----------

@router.get("/mcp/oauth/authorize")
async def authorize(request: Request) -> Any:
    """Stash the MCP client request and redirect the user to the IdP."""
    _cleanup_expired()
    params = request.query_params
    client_id = params.get("client_id", "")
    redirect_uri = params.get("redirect_uri", "")
    state = params.get("state", "")
    code_challenge = params.get("code_challenge", "")
    code_challenge_method = params.get("code_challenge_method", "")

    if client_id and client_id in _registered_clients:
        client = _registered_clients[client_id]
        if redirect_uri and redirect_uri not in client["redirect_uris"]:
            return HTMLResponse("<h1>Error: Invalid redirect_uri</h1>", status_code=400)

    if code_challenge_method and code_challenge_method != "S256":
        return HTMLResponse("<h1>Error: Only S256 code challenge method is supported</h1>", status_code=400)

    try:
        provider = oauth_providers.get_provider()
    except oauth_providers.ProviderError as exc:
        log.error("mcp.oauth.provider_unavailable", error=str(exc))
        return HTMLResponse(f"<h1>MCP OAuth not configured: {exc}</h1>", status_code=500)

    idp_state = secrets.token_urlsafe(32)
    callback_url = f"{_base_url(request)}/mcp/oauth/idp/callback"
    _pending_auths[idp_state] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "mcp_state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires": time.time() + _PENDING_TTL,
    }

    client_ip = _client_ip(request)
    await log_oauth_event(
        event="authorize_initiated",
        provider=provider.name,
        client_ip=client_ip,
        mcp_client_id=client_id,
    )

    try:
        idp_url = await oauth_providers.resolve_authorize_url(idp_state, callback_url)
    except Exception as exc:
        log.error("mcp.oauth.authorize_url_failed", error=str(exc))
        del _pending_auths[idp_state]
        return HTMLResponse(f"<h1>OAuth provider error: {exc}</h1>", status_code=502)

    return RedirectResponse(url=idp_url, status_code=302)


# ---------- IdP Callback ----------

@router.get("/mcp/oauth/idp/callback")
async def idp_callback(request: Request) -> Any:
    """Receive the IdP redirect, exchange code, fetch user, mint MCP auth code."""
    _cleanup_expired()
    params = request.query_params
    idp_state = params.get("state", "")
    idp_code = params.get("code", "")
    idp_error = params.get("error", "")

    pending = _pending_auths.pop(idp_state, None)
    if pending is None:
        log.warning("mcp.oauth.callback_unknown_state")
        return HTMLResponse("<h1>Error: Unknown or expired authorization state</h1>", status_code=400)

    client_ip = _client_ip(request)
    provider = oauth_providers.get_provider()

    if idp_error or not idp_code:
        await log_oauth_event(
            event="authorize_denied",
            provider=provider.name,
            client_ip=client_ip,
            reason=f"idp_error:{idp_error or 'no_code'}",
            mcp_client_id=pending["client_id"],
        )
        return _redirect_with_error(pending, "access_denied", idp_error or "no_code")

    callback_url = f"{_base_url(request)}/mcp/oauth/idp/callback"
    try:
        idp_token = await provider.exchange_code(idp_code, callback_url)
        user = await provider.fetch_user(idp_token)
    except oauth_providers.ProviderError as exc:
        log.warning("mcp.oauth.callback_provider_error", error=str(exc))
        await log_oauth_event(
            event="authorize_denied",
            provider=provider.name,
            client_ip=client_ip,
            reason=f"provider_error:{exc}",
            mcp_client_id=pending["client_id"],
        )
        return _redirect_with_error(pending, "server_error", "idp_exchange_failed")

    if not _user_allowed(user.identity, user.email):
        await log_oauth_event(
            event="authorize_denied",
            provider=provider.name,
            identity=user.identity,
            email=user.email,
            client_ip=client_ip,
            reason="user_not_allowlisted",
            mcp_client_id=pending["client_id"],
        )
        return _redirect_with_error(pending, "access_denied", "user_not_allowlisted")

    scope = "mcp:read"
    if _ip_in_safelist(client_ip, settings.mcp_write_ip_safelist):
        scope = "mcp:read mcp:write"

    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "client_id": pending["client_id"],
        "redirect_uri": pending["redirect_uri"],
        "code_challenge": pending["code_challenge"],
        "code_challenge_method": pending["code_challenge_method"],
        "scope": scope,
        "identity": user.identity,
        "email": user.email,
        "ip": client_ip,
        "expires": time.time() + _AUTH_CODE_TTL,
    }

    await log_oauth_event(
        event="authorize_success",
        provider=provider.name,
        identity=user.identity,
        email=user.email,
        client_ip=client_ip,
        granted_scope=scope,
        mcp_client_id=pending["client_id"],
    )

    redirect_uri = pending["redirect_uri"]
    redirect_params = {"code": code}
    if pending["mcp_state"]:
        redirect_params["state"] = pending["mcp_state"]
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(
        url=f"{redirect_uri}{separator}{urlencode(redirect_params)}",
        status_code=302,
    )


def _redirect_with_error(pending: dict[str, Any], error: str, description: str) -> RedirectResponse:
    redirect_uri = pending["redirect_uri"]
    if not redirect_uri:
        return HTMLResponse(  # type: ignore[return-value]
            f"<h1>Authorization failed: {error}</h1><p>{description}</p>",
            status_code=400,
        )
    params = {"error": error, "error_description": description}
    if pending.get("mcp_state"):
        params["state"] = pending["mcp_state"]
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(url=f"{redirect_uri}{separator}{urlencode(params)}", status_code=302)


# ---------- Token Endpoint ----------

@router.post("/mcp/oauth/token")
async def token_exchange(request: Request) -> JSONResponse:
    _cleanup_expired()
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
    else:
        form = await request.form()
        body = dict(form)

    grant_type = body.get("grant_type", "")
    code = body.get("code", "")
    redirect_uri = body.get("redirect_uri", "")
    code_verifier = body.get("code_verifier", "")
    client_id = body.get("client_id", "")

    if grant_type != "authorization_code":
        return JSONResponse(
            {"error": "unsupported_grant_type", "error_description": "Only authorization_code is supported"},
            status_code=400,
        )

    if not code or code not in _auth_codes:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Invalid or expired authorization code"},
            status_code=400,
        )

    auth_code = _auth_codes.pop(code)

    if auth_code["expires"] < time.time():
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Authorization code expired"},
            status_code=400,
        )

    if client_id and auth_code["client_id"] and client_id != auth_code["client_id"]:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Client ID mismatch"},
            status_code=400,
        )

    if redirect_uri and auth_code["redirect_uri"] and redirect_uri != auth_code["redirect_uri"]:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Redirect URI mismatch"},
            status_code=400,
        )

    if auth_code.get("code_challenge"):
        if not code_verifier:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "code_verifier required for PKCE"},
                status_code=400,
            )
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(expected, auth_code["code_challenge"]):
            log.warning("mcp.oauth.pkce_failed", client_id=client_id)
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "PKCE verification failed"},
                status_code=400,
            )

    access_token = secrets.token_urlsafe(48)
    _access_tokens[access_token] = {
        "client_id": client_id or auth_code["client_id"],
        "scope": auth_code["scope"],
        "identity": auth_code["identity"],
        "email": auth_code["email"],
        "ip": auth_code["ip"],
        "expires": time.time() + _ACCESS_TOKEN_TTL,
    }

    await log_oauth_event(
        event="token_issued",
        provider=oauth_providers.get_provider().name,
        identity=auth_code["identity"],
        email=auth_code["email"],
        client_ip=auth_code["ip"],
        granted_scope=auth_code["scope"],
        mcp_client_id=client_id or auth_code["client_id"],
    )

    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": _ACCESS_TOKEN_TTL,
        "scope": auth_code["scope"],
    })


# ---------- Token Validation (used by auth middleware) ----------

def get_oauth_token_info(token: str) -> TokenInfo | None:
    """Look up an OAuth access token. Returns None if missing or expired."""
    data = _access_tokens.get(token)
    if not data:
        return None
    if data["expires"] < time.time():
        del _access_tokens[token]
        return None
    return TokenInfo(
        identity=data["identity"],
        email=data["email"],
        scope=data["scope"],
        client_id=data["client_id"],
        issued_at_ip=data["ip"],
    )


def get_dcr_client_name(client_id: str | None) -> str | None:
    """Return the registered `client_name` for a DCR client, or None."""
    if not client_id:
        return None
    record = _registered_clients.get(client_id)
    if not record:
        return None
    name = record.get("client_name")
    return str(name) if name else None
