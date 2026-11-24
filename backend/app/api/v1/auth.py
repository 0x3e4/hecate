"""Web app sign-in through an OIDC identity provider (backend-for-frontend).

``GET /auth/login`` starts the Authorization Code + PKCE flow, ``GET
/auth/callback`` finishes it and sets the session cookie, ``GET /auth/me``
says who is signed in, ``POST /auth/logout`` ends the session. All four stay
reachable when login is required. See docs/admin/authentication.md.
"""
from __future__ import annotations

import hmac
import secrets
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import structlog
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from app.core.auth_context import CSRF_HEADER, get_auth_context, public_base_url
from app.core.config import settings
from app.services.audit_service import get_audit_service
from app.services.auth_session_service import get_auth_session_service
from app.services.oidc_client import (
    OidcError,
    claim_values,
    display_name,
    email_of,
    get_oidc_client,
    pkce_pair,
    resolve_role,
)
from app.utils.request import get_security_client_ip

router = APIRouter()
log = structlog.get_logger()

LOGIN_COOKIE = "hecate_login"
_MAX_RETURN_TO = 2000


class AuthUser(BaseModel):
    name: str
    email: str | None = None
    role: str


class AuthMeResponse(BaseModel):
    authenticated: bool
    user: AuthUser | None = None
    auth_enabled: bool = Field(alias="authEnabled", serialization_alias="authEnabled")
    auth_required: bool = Field(alias="authRequired", serialization_alias="authRequired")
    provider_label: str = Field(alias="providerLabel", serialization_alias="providerLabel")
    model_config = {"populate_by_name": True}


class LogoutResponse(BaseModel):
    logout_url: str | None = Field(default=None, alias="logoutUrl", serialization_alias="logoutUrl")
    model_config = {"populate_by_name": True}


def safe_return_to(value: str | None) -> str:
    """A same-site path to land on after sign-in, or ``/``.

    Only plain absolute paths: ``//host`` and ``/\\host`` are protocol-relative
    URLs to browsers, and the API itself is no place to land.
    """
    if not value or len(value) > _MAX_RETURN_TO:
        return "/"
    if not value.startswith("/") or value.startswith("//") or value.startswith("/\\"):
        return "/"
    if any(ord(ch) < 32 or ch == "\\" for ch in value):
        return "/"
    if value == settings.api_prefix or value.startswith("/api/") or value == "/api":
        return "/"
    return value


def _redirect_uri(request: Request) -> str:
    return f"{public_base_url(request)}{settings.api_prefix}/auth/callback"


def _secure_cookie(request: Request) -> bool:
    return public_base_url(request).startswith("https://")


def _fail(request: Request, reason: str) -> RedirectResponse:
    response = RedirectResponse(f"/?authError={quote(reason)}", status_code=302)
    response.delete_cookie(LOGIN_COOKIE, path=f"{settings.api_prefix}/auth")
    return response


async def _audit(job_name: str, *, status: str, request: Request, metadata: dict[str, Any], error: str | None = None) -> None:
    try:
        service = await get_audit_service()
        await service.record_event(
            job_name,
            status=status,
            metadata={"clientIp": get_security_client_ip(request) or None, **metadata},
            error=error,
        )
    except Exception as exc:  # noqa: BLE001 - auditing never blocks a sign-in
        log.warning("auth.audit_failed", job=job_name, error=repr(exc))


@router.get("/me")
async def me(request: Request) -> AuthMeResponse:
    ctx = await get_auth_context(request)
    user = ctx.user
    return AuthMeResponse(
        authenticated=user is not None,
        user=AuthUser(name=user.name, email=user.email, role=user.role) if user else None,
        auth_enabled=settings.oidc_enabled,
        auth_required=settings.auth_login_required,
        provider_label=settings.oidc_provider_label,
    )


@router.get(
    "/login",
    response_class=RedirectResponse,
    status_code=302,
    responses={302: {"description": "Redirect to the identity provider (or back with `?authError=` when sign-in is off)."}},
)
async def login(request: Request, returnTo: str | None = None) -> RedirectResponse:  # noqa: N803 - query name
    if not settings.oidc_enabled:
        raise HTTPException(status_code=404, detail="Sign-in is not configured.")
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = pkce_pair()
    try:
        url = await get_oidc_client().authorization_url(
            state=state, nonce=nonce, code_challenge=challenge, redirect_uri=_redirect_uri(request)
        )
    except OidcError as exc:
        log.warning("auth.login_unavailable", code=exc.code, error=exc.message)
        await _audit(
            "auth_login", status="failed", request=request, metadata={"label": "Sign-in", "reason": exc.code}, error=exc.message
        )
        return _fail(request, exc.code)
    sessions = await get_auth_session_service()
    browser_token = await sessions.create_login_state(
        state=state, nonce=nonce, code_verifier=verifier, return_to=safe_return_to(returnTo)
    )
    response = RedirectResponse(url, status_code=302)
    response.set_cookie(
        LOGIN_COOKIE,
        browser_token,
        max_age=600,
        httponly=True,
        secure=_secure_cookie(request),
        samesite="lax",
        path=f"{settings.api_prefix}/auth",
    )
    return response


@router.get(
    "/callback",
    response_class=RedirectResponse,
    status_code=302,
    responses={302: {"description": "Back into Hecate after sign-in, or to `/?authError=<code>`."}},
)
async def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    if not settings.oidc_enabled:
        raise HTTPException(status_code=404, detail="Sign-in is not configured.")
    sessions = await get_auth_session_service()
    browser_token = request.cookies.get(LOGIN_COOKIE)
    pending = await sessions.consume_login_state(browser_token) if browser_token else None
    base_meta: dict[str, Any] = {"label": "Sign-in", "provider": settings.oidc_provider_label}

    async def fail(reason: str, message: str, extra: dict[str, Any] | None = None) -> RedirectResponse:
        log.warning("auth.login_failed", reason=reason, error=message)
        await _audit(
            "auth_login", status="failed", request=request, metadata={**base_meta, "reason": reason, **(extra or {})},
            error=message,
        )
        return _fail(request, reason)

    if error:
        # The IdP's own error code (access_denied, …), never its free-text description.
        return await fail("idp_error", f"The identity provider returned {error[:60]!r}.")
    if pending is None:
        return await fail("invalid_state", "No pending sign-in for this browser (expired, replayed or cookie missing).")
    if not state or not hmac.compare_digest(state, str(pending.get("state", ""))):
        return await fail("invalid_state", "The state parameter does not match this sign-in.")
    if not code:
        return await fail("invalid_state", "The callback carries no authorization code.")

    client = get_oidc_client()
    try:
        tokens = await client.exchange_code(
            code=code, code_verifier=str(pending["code_verifier"]), redirect_uri=_redirect_uri(request)
        )
        claims = await client.validate_id_token(tokens["id_token"], nonce=str(pending["nonce"]))
    except OidcError as exc:
        return await fail(exc.code, exc.message)

    merged = dict(claims)
    access_token = tokens.get("access_token")
    if settings.oidc_use_userinfo and isinstance(access_token, str):
        # Authelia and others put groups only into userinfo; the ID token wins where both have a claim.
        missing = (
            not claim_values(claims, settings.oidc_roles_claim)
            or not claims.get("email")
            or not (claims.get("name") or claims.get("preferred_username"))
        )
        if missing:
            info = await client.userinfo(access_token, subject=str(claims["sub"]))
            for key, value in info.items():
                merged.setdefault(key, value)

    name = display_name(merged)
    email = email_of(merged)
    who = {"name": name, "email": email, "sub": str(claims["sub"])}
    role = resolve_role(merged)
    if role is None:
        return await fail(
            "no_role", "The account is in none of the groups configured for Hecate.", {"user": who}
        )

    # A fresh session on every sign-in; a session cookie the browser still had is dropped.
    previous = request.cookies.get(settings.auth_cookie_name)
    if previous:
        try:
            await sessions.delete_session(previous)
        except Exception as exc:  # noqa: BLE001 - it expires on its own
            log.warning("auth.previous_session_cleanup_failed", error=repr(exc))
    token, expires = await sessions.create_session(
        sub=str(claims["sub"]),
        issuer=str(claims.get("iss", "")),
        name=name,
        email=email,
        role=role,
        id_token=tokens["id_token"],
    )
    await _audit(
        "auth_login",
        status="completed",
        request=request,
        metadata={**base_meta, "actor": {"type": "user", **{k: v for k, v in who.items() if v}, "role": role,
                                         "label": f"{name} ({role})"}},
    )
    response = RedirectResponse(safe_return_to(str(pending.get("return_to") or "/")), status_code=302)
    response.delete_cookie(LOGIN_COOKIE, path=f"{settings.api_prefix}/auth")
    response.set_cookie(
        settings.auth_cookie_name,
        token,
        max_age=max(60, int((expires - datetime.now(UTC)).total_seconds())),
        httponly=True,
        secure=_secure_cookie(request),
        samesite="lax",
        path="/",
    )
    return response


@router.post("/logout", response_model=LogoutResponse)
async def logout(request: Request) -> JSONResponse:
    if not request.headers.get(CSRF_HEADER):
        raise HTTPException(status_code=403, detail=f"Cross-site request refused: missing {CSRF_HEADER} header.")
    token = request.cookies.get(settings.auth_cookie_name)
    document = None
    if token and settings.oidc_enabled:
        try:
            document = await (await get_auth_session_service()).delete_session(token)
        except Exception as exc:  # noqa: BLE001 - the cookie is cleared regardless
            log.warning("auth.logout_failed", error=repr(exc))
    logout_url: str | None = None
    if document is not None:
        name = str(document.get("name") or "")
        role = str(document.get("role") or "")
        actor = {"type": "user", "name": name, "email": document.get("email"), "sub": document.get("sub"),
                 "role": role, "label": f"{name} ({role})"}
        await _audit(
            "auth_logout", status="completed", request=request,
            metadata={"label": "Sign-out", "actor": {k: v for k, v in actor.items() if v}},
        )
        if settings.oidc_rp_initiated_logout:
            logout_url = await get_oidc_client().end_session_url(
                id_token_hint=document.get("id_token"),
                post_logout_redirect_uri=f"{public_base_url(request)}/",
            )
    response = JSONResponse(LogoutResponse(logout_url=logout_url).model_dump(by_alias=True))
    response.delete_cookie(settings.auth_cookie_name, path="/")
    return response
