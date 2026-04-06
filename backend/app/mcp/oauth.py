"""OAuth 2.0 Authorization Server for MCP (RFC 6749 + PKCE + Dynamic Client Registration).

Implements the OAuth flow required by the MCP spec for remote HTTP servers.
Claude Desktop discovers endpoints via /.well-known/oauth-authorization-server,
then uses Authorization Code + PKCE to obtain a Bearer token.

The "authorization" step is a simple HTML page where the user enters their
MCP API key. This keeps the flow compatible with Hecate's existing API-key-based
security model while satisfying the OAuth requirement.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs

import structlog
from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from app.core.config import settings

log = structlog.get_logger()

router = APIRouter()

# In-memory stores (cleared on restart — acceptable for MCP auth codes which are short-lived).
_auth_codes: dict[str, dict[str, Any]] = {}  # code -> {client_id, redirect_uri, code_challenge, expires, api_key}
_registered_clients: dict[str, dict[str, Any]] = {}  # client_id -> {redirect_uris, client_secret, ...}
_access_tokens: dict[str, dict[str, Any]] = {}  # token -> {client_id, expires}

# Expiry times
_AUTH_CODE_TTL = 300  # 5 minutes
_ACCESS_TOKEN_TTL = 86400  # 24 hours


def _base_url(request: Request) -> str:
    """Derive the external base URL from the request."""
    # Use X-Forwarded-Proto/Host if behind reverse proxy
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", request.url.netloc)
    return f"{proto}://{host}"


def _cleanup_expired() -> None:
    """Remove expired codes and tokens."""
    now = time.time()
    for store in (_auth_codes, _access_tokens):
        expired = [k for k, v in store.items() if v.get("expires", 0) < now]
        for k in expired:
            del store[k]


# ---------- OAuth Metadata (RFC 8414) ----------

@router.get("/.well-known/oauth-authorization-server")
async def oauth_metadata(request: Request) -> JSONResponse:
    """OAuth 2.0 Authorization Server Metadata (RFC 8414)."""
    base = _base_url(request)
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/mcp/oauth/authorize",
        "token_endpoint": f"{base}/mcp/oauth/token",
        "registration_endpoint": f"{base}/mcp/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["mcp:read", "mcp:write"],
    })


# ---------- Protected Resource Metadata (RFC 9728) ----------

@router.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata(request: Request) -> JSONResponse:
    """OAuth 2.0 Protected Resource Metadata (RFC 9728).

    Returned URL in WWW-Authenticate header tells the client where to find
    the authorization server metadata.
    """
    base = _base_url(request)
    return JSONResponse({
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp:read", "mcp:write"],
    })


# ---------- Dynamic Client Registration (RFC 7591) ----------

@router.post("/mcp/oauth/register")
async def register_client(request: Request) -> JSONResponse:
    """Dynamic Client Registration endpoint (RFC 7591).

    Claude Desktop calls this to register itself as an OAuth client before
    starting the authorization flow.
    """
    _cleanup_expired()

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    client_id = secrets.token_urlsafe(24)
    client_secret = secrets.token_urlsafe(32)

    redirect_uris = body.get("redirect_uris", [])
    if not redirect_uris or not isinstance(redirect_uris, list):
        return JSONResponse(
            {"error": "invalid_request", "error_description": "redirect_uris required"},
            status_code=400,
        )

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
async def authorize(request: Request) -> HTMLResponse:
    """Authorization endpoint — shows a simple form for the user to enter their API key."""
    params = request.query_params
    client_id = params.get("client_id", "")
    redirect_uri = params.get("redirect_uri", "")
    state = params.get("state", "")
    code_challenge = params.get("code_challenge", "")
    code_challenge_method = params.get("code_challenge_method", "")
    scope = params.get("scope", "")

    # Validate client
    if client_id and client_id in _registered_clients:
        client = _registered_clients[client_id]
        if redirect_uri and redirect_uri not in client["redirect_uris"]:
            return HTMLResponse("<h1>Error: Invalid redirect_uri</h1>", status_code=400)

    if code_challenge_method and code_challenge_method != "S256":
        return HTMLResponse("<h1>Error: Only S256 code challenge method is supported</h1>", status_code=400)

    # Render authorization page styled to match Hecate UI
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hecate Cyber Defense - MCP Authorize</title>
    <link rel="icon" href="/logo.png" type="image/png">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            background: #080a12; color: #f5f7fa;
            display: flex; justify-content: center; align-items: center;
            min-height: 100vh; padding: 20px;
        }}
        .card {{
            background: #05070d; border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px; padding: 48px; max-width: 440px; width: 100%;
        }}
        .branding {{
            display: flex; align-items: center; gap: 14px; margin-bottom: 8px;
        }}
        .branding img {{
            height: 48px; width: 48px;
        }}
        .branding h1 {{
            font-size: 1.45rem; margin: 0; color: #f5f7fa;
        }}
        .subtitle {{
            color: rgba(255, 255, 255, 0.55); margin-bottom: 28px; font-size: 14px;
        }}
        label {{
            display: block; margin-bottom: 6px; font-size: 14px; color: rgba(255, 255, 255, 0.75);
        }}
        input[type="password"] {{
            width: 100%; padding: 10px 14px;
            background: rgba(255, 255, 255, 0.04); border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 6px; color: #f5f7fa; font-size: 16px; margin-bottom: 20px;
            font-family: inherit;
        }}
        input[type="password"]:focus {{
            border-color: #ffd43b; outline: none;
            box-shadow: 0 0 0 2px rgba(255, 212, 59, 0.15);
        }}
        input[type="password"]::placeholder {{ color: rgba(255, 255, 255, 0.3); }}
        button {{
            width: 100%; padding: 12px; border: none; border-radius: 6px;
            font-size: 16px; font-weight: 600; cursor: pointer;
            background: rgba(255, 212, 59, 0.35); color: #ffd43b;
            font-family: inherit; transition: background 0.15s;
        }}
        button:hover {{ background: rgba(255, 212, 59, 0.5); }}
        .scope-info {{
            color: rgba(255, 255, 255, 0.4); font-size: 13px; margin-bottom: 20px;
        }}
        .error-msg {{
            background: rgba(248, 81, 73, 0.1); border: 1px solid rgba(248, 81, 73, 0.3);
            border-radius: 6px; padding: 10px 14px; margin-bottom: 16px;
            color: #f85149; font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="branding">
            <img src="/logo.png" alt="Hecate">
            <h1>Hecate MCP</h1>
        </div>
        <p class="subtitle">Authorize access to the vulnerability database</p>
        {"<div class='error-msg'>Invalid API key. Please try again.</div>" if request.query_params.get("error") else ""}
        <form method="POST" action="/mcp/oauth/authorize">
            <input type="hidden" name="client_id" value="{html.escape(client_id)}">
            <input type="hidden" name="redirect_uri" value="{html.escape(redirect_uri)}">
            <input type="hidden" name="state" value="{html.escape(state)}">
            <input type="hidden" name="code_challenge" value="{html.escape(code_challenge)}">
            <input type="hidden" name="code_challenge_method" value="{html.escape(code_challenge_method)}">
            <input type="hidden" name="scope" value="{html.escape(scope)}">
            <label for="api_key">MCP API Key</label>
            <input type="password" id="api_key" name="api_key" placeholder="Enter your MCP API key" required autofocus>
            <p class="scope-info">This will grant read access to the Hecate vulnerability database.</p>
            <button type="submit">Authorize</button>
        </form>
    </div>
</body>
</html>"""
    return HTMLResponse(page)


@router.post("/mcp/oauth/authorize")
async def authorize_submit(request: Request) -> Response:
    """Handle the authorization form submission."""
    form = await request.form()
    api_key = str(form.get("api_key", ""))
    client_id = str(form.get("client_id", ""))
    redirect_uri = str(form.get("redirect_uri", ""))
    state = str(form.get("state", ""))
    code_challenge = str(form.get("code_challenge", ""))
    code_challenge_method = str(form.get("code_challenge_method", ""))

    # Validate the API key against configured MCP API key
    configured_key = settings.mcp_api_key or ""
    if not hmac.compare_digest(api_key.encode(), configured_key.encode()):
        log.warning("mcp.oauth.authorize_failed", reason="invalid_api_key", client_id=client_id)
        # Re-show form with error
        return HTMLResponse(
            """<!DOCTYPE html><html><head><meta charset="UTF-8">
            <meta http-equiv="refresh" content="0;url=/mcp/oauth/authorize?"""
            + urlencode({
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "error": "invalid_key",
            })
            + """"></head><body>Redirecting...</body></html>""",
            status_code=200,
        )

    # Generate authorization code
    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires": time.time() + _AUTH_CODE_TTL,
        "api_key": api_key,
    }

    log.info("mcp.oauth.code_issued", client_id=client_id)

    # Redirect back to client with auth code
    params = {"code": code}
    if state:
        params["state"] = state

    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(
        url=f"{redirect_uri}{separator}{urlencode(params)}",
        status_code=302,
    )


# ---------- Token Endpoint ----------

@router.post("/mcp/oauth/token")
async def token_exchange(request: Request) -> JSONResponse:
    """Token endpoint — exchanges authorization code for access token (with PKCE verification)."""
    _cleanup_expired()

    # Accept both JSON and form-encoded bodies
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

    # Check expiry
    if auth_code["expires"] < time.time():
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Authorization code expired"},
            status_code=400,
        )

    # Verify client_id
    if client_id and auth_code["client_id"] and client_id != auth_code["client_id"]:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Client ID mismatch"},
            status_code=400,
        )

    # Verify redirect_uri
    if redirect_uri and auth_code["redirect_uri"] and redirect_uri != auth_code["redirect_uri"]:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Redirect URI mismatch"},
            status_code=400,
        )

    # PKCE verification (S256)
    if auth_code.get("code_challenge"):
        if not code_verifier:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "code_verifier required for PKCE"},
                status_code=400,
            )
        # S256: BASE64URL(SHA256(code_verifier)) == code_challenge
        import base64
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(expected, auth_code["code_challenge"]):
            log.warning("mcp.oauth.pkce_failed", client_id=client_id)
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "PKCE verification failed"},
                status_code=400,
            )

    # Issue access token
    access_token = secrets.token_urlsafe(48)
    _access_tokens[access_token] = {
        "client_id": client_id or auth_code["client_id"],
        "expires": time.time() + _ACCESS_TOKEN_TTL,
        "api_key": auth_code["api_key"],
    }

    log.info("mcp.oauth.token_issued", client_id=client_id)

    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": _ACCESS_TOKEN_TTL,
        "scope": "mcp:read",
    })


# ---------- Token Validation (used by auth middleware) ----------

def validate_oauth_token(token: str) -> bool:
    """Check if a Bearer token is a valid OAuth access token."""
    token_data = _access_tokens.get(token)
    if not token_data:
        return False
    if token_data["expires"] < time.time():
        del _access_tokens[token]
        return False
    return True
