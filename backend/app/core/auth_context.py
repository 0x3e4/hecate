"""Who is calling: the OIDC session (if any) and the credential that authorized a request.

Resolved once per request and kept on ``request.state`` (the gates in
``write_auth`` read it) and in a context variable (``AuditService.record_event``
and the request audit middleware read it to name the actor).

Roles: ``viewer`` < ``editor`` < ``admin``. A session satisfies a gate whose
role it reaches before any password header is looked at; the password headers
keep working on top (scripts, installs without OIDC, an editor holding the
system password).

Without OIDC configured nothing here changes behaviour: there is no session,
and the gates fall back to the passwords exactly as before.
"""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

import structlog
from fastapi import Header, HTTPException, Request

from app.core.auth_throttle import API_KEY_SECRET, SYSTEM_SECRET, enforce_auth_throttle, record_auth_result
from app.core.config import settings
from app.core.passwords import secret_equals
from app.utils.request import is_trusted_proxy

log = structlog.get_logger()

MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
ROLE_RANK = {"viewer": 1, "editor": 2, "admin": 3}

# The SPA sends this on every request. A cross-site page cannot add it without
# a CORS preflight, which credentialed cross-origin requests do not pass.
CSRF_HEADER = "X-Hecate-Request"
# On a 401 that only a sign-in can fix (distinct from X-Write-Auth-Required,
# which asks for a password).
AUTH_REQUIRED_HEADER = "X-Auth-Required"
# On a 403 for a signed-in user whose role is too low; the value names the role.
ROLE_REQUIRED_HEADER = "X-Auth-Role-Required"

# Routes (relative to the API prefix) that stay open when login is required.
PUBLIC_ROUTES = frozenset(
    {
        "/status/health",
        "/config",
        "/scans/{scan_id}/shield",
        "/scans/targets/{target_id:path}/shield",
    }
)
PUBLIC_ROUTE_PREFIXES = ("/auth/",)

# POST routes that only read. The read gate treats them as reads, the audit
# middleware does not record them (lookup is recorded once it fetches upstream).
READ_POST_ROUTES = frozenset(
    {
        "/vulnerabilities/search",
        "/vulnerabilities/lookup",
        "/cwe/bulk",
        "/capec/bulk",
        "/capec/from-cwes",
    }
)
# Password probes of the unlock dialogs: recorded as auth events, not as writes.
PASSWORD_CHECK_ROUTES = {
    "/status/system-auth": "system password",
    "/status/ai-auth": "AI password",
}


@dataclass
class SessionUser:
    session_id: str
    sub: str
    issuer: str
    name: str
    email: str | None
    role: str

    def has_role(self, role: str) -> bool:
        return ROLE_RANK.get(self.role, 0) >= ROLE_RANK[role]

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> SessionUser:
        return cls(
            session_id=str(document.get("_id", "")),
            sub=str(document.get("sub", "")),
            issuer=str(document.get("issuer", "")),
            name=str(document.get("name") or document.get("sub") or "unknown"),
            email=document.get("email") if isinstance(document.get("email"), str) else None,
            role=str(document.get("role", "")),
        )


_CREDENTIAL_LABELS = {
    "system_password": "System password",
    "target_password": "Target password",
    "api_token": "API token",
    "sca_api_key": "SCA API key",
    "ai_password": "AI password",
}


@dataclass
class AuthContext:
    resolved: bool = False
    user: SessionUser | None = None
    csrf_failed: bool = False
    # Whose session cookie a refused cross-site write carried. Not signed in for
    # this request; the audit names them so a forged request is attributable.
    csrf_user: SessionUser | None = None
    # What authorized the request when it was not (only) the session.
    credential: dict[str, Any] | None = None
    # An explicit, richer audit event was written while the request ran.
    explicit_audit: bool = False
    # Record this request even though its route is a read (lookup that fetched).
    force_audit: bool = False
    # Matched route template without the API prefix (set while the request runs).
    route: str | None = None

    def actor(self) -> dict[str, Any]:
        """The audit actor: the signed-in user, else the credential, else anonymous."""
        credential = self.credential or {}
        if self.user is not None:
            actor: dict[str, Any] = {
                "type": "user",
                "name": self.user.name,
                "email": self.user.email,
                "sub": self.user.sub,
                "role": self.user.role,
                "label": f"{self.user.name} ({self.user.role})",
            }
            if credential and credential.get("type") not in (None, "session"):
                actor["via"] = credential.get("type")
            return {k: v for k, v in actor.items() if v is not None}
        if self.csrf_user is not None:
            refused = {
                "type": "session_refused",
                "name": self.csrf_user.name,
                "email": self.csrf_user.email,
                "sub": self.csrf_user.sub,
                "role": self.csrf_user.role,
                "reason": "csrf",
                "label": f"{self.csrf_user.name} (session refused: cross-site request)",
            }
            return {k: v for k, v in refused.items() if v is not None}
        if credential:
            kind = credential.get("type", "")
            label = _CREDENTIAL_LABELS.get(kind, kind)
            if kind == "target_password" and credential.get("target"):
                label = f"{label} ({credential['target']})"
            elif kind == "api_token" and credential.get("name"):
                label = f"{label} {credential['name']}"
            return {**credential, "label": label}
        return {"type": "anonymous", "label": "Anonymous"}


_current: ContextVar[AuthContext | None] = ContextVar("hecate_auth_context", default=None)


def current_auth_context() -> AuthContext | None:
    """The context of the request this code runs for (also in tasks it started)."""
    return _current.get()


def bind_auth_context(ctx: AuthContext):
    return _current.set(ctx)


def unbind_auth_context(token) -> None:
    _current.reset(token)


def _state_context(request: Request) -> AuthContext:
    ctx = getattr(request.state, "hecate_auth", None)
    if ctx is None:
        ctx = current_auth_context() or AuthContext()
        request.state.hecate_auth = ctx
    return ctx


def csrf_ok(request: Request) -> bool:
    """Whether a cookie-authenticated write comes from Hecate's own pages."""
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        return False
    return bool(request.headers.get(CSRF_HEADER))


async def get_auth_context(request: Request) -> AuthContext:
    ctx = _state_context(request)
    if ctx.resolved:
        return ctx
    ctx.resolved = True
    if not settings.oidc_enabled:
        return ctx
    token = request.cookies.get(settings.auth_cookie_name)
    if not token:
        return ctx
    try:
        from app.services.auth_session_service import get_auth_session_service

        document = await (await get_auth_session_service()).get_session(token)
    except Exception as exc:  # noqa: BLE001 - a session store outage reads as "not signed in"
        log.warning("auth.session_lookup_failed", error=repr(exc))
        document = None
    if document is None:
        return ctx
    user = SessionUser.from_document(document)
    if request.method in MUTATING_METHODS and not csrf_ok(request):
        ctx.csrf_failed = True
        ctx.csrf_user = user
        return ctx
    ctx.user = user
    return ctx


async def current_user(request: Request) -> SessionUser | None:
    """The signed-in user, or ``None``. A cookie-borne write without the CSRF header is refused."""
    ctx = await get_auth_context(request)
    if ctx.csrf_failed:
        raise HTTPException(status_code=403, detail=f"Cross-site request refused: missing {CSRF_HEADER} header.")
    return ctx.user


def note_credential(request: Request, kind: str, **details: Any) -> None:
    """Record what authorized this request, for the audit trail. Never a secret."""
    ctx = _state_context(request)
    if kind == "session" and ctx.user is not None:
        return
    ctx.credential = {"type": kind, **{k: v for k, v in details.items() if v is not None}}


def login_required_error(detail: str = "Sign-in required.") -> HTTPException:
    return HTTPException(status_code=401, detail=detail, headers={AUTH_REQUIRED_HEADER: "login"})


def role_error(role: str) -> HTTPException:
    return HTTPException(
        status_code=403,
        detail=f"This action requires the {role} role.",
        headers={ROLE_REQUIRED_HEADER: role},
    )


def with_login_hint(headers: dict[str, str]) -> dict[str, str]:
    """Add the sign-in marker to a password-prompt 401 when signing in would also help."""
    if settings.oidc_enabled:
        return {**headers, AUTH_REQUIRED_HEADER: "login"}
    return headers


def route_template(scope: dict[str, Any]) -> str | None:
    """The full template of the matched route (``/api/v1/scans/{scan_id}``), or ``None``.

    FastAPI 0.139 keeps included routers nested, so ``scope["route"].path`` is the
    template relative to its own router; the full one lives in the effective
    route context, which exists only while the request is being handled.
    """
    try:
        from fastapi.routing import _get_scope_effective_route_context

        effective = _get_scope_effective_route_context(scope)
    except Exception:  # noqa: BLE001 - private API; fall back below
        effective = None
    path = getattr(effective, "path", None) if effective is not None else None
    if not isinstance(path, str) or not path:
        path = getattr(scope.get("route"), "path", None)
    return path if isinstance(path, str) else None


def strip_api_prefix(path: str) -> str:
    prefix = settings.api_prefix
    return path[len(prefix):] if prefix and path.startswith(prefix) else path


def relative_route(request: Request) -> str | None:
    """The matched route template without the API prefix, or ``None`` before routing.

    Remembered on the request's context for the audit middleware, which runs
    after FastAPI has dropped the effective route context again.
    """
    ctx = _state_context(request)
    if ctx.route is None:
        path = route_template(request.scope)
        if path is not None:
            ctx.route = strip_api_prefix(path)
    return ctx.route


def is_public_route(relative: str | None) -> bool:
    if relative is None:
        return False
    return relative in PUBLIC_ROUTES or relative.startswith(PUBLIC_ROUTE_PREFIXES)


async def require_read_access(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_system_password: str | None = Header(default=None, alias="X-System-Password"),
    x_target_password: str | None = Header(default=None, alias="X-Target-Password"),
    x_ai_analysis_password: str | None = Header(default=None, alias="X-AI-Analysis-Password"),
) -> None:
    """With ``AUTH_REQUIRE_LOGIN``, every API route needs a caller Hecate can name.

    Accepted: a session (any role), the system password, ``SCA_API_KEY``, or an
    API token of any scope, so CI pipelines that poll scan results keep working.
    A write that carries a target or AI password is left to its own gate, which
    verifies it; read routes never accept those two. Attached to the API router,
    so a new route is covered by default; the exceptions are ``PUBLIC_ROUTES``.
    """
    if not settings.auth_login_required:
        return
    relative = relative_route(request)
    if is_public_route(relative):
        return
    if await current_user(request) is not None:
        return
    is_write = request.method in MUTATING_METHODS and relative not in READ_POST_ROUTES
    if is_write and (x_target_password or x_ai_analysis_password):
        return
    if x_system_password and settings.system_password:
        key = enforce_auth_throttle(request, SYSTEM_SECRET)
        if secret_equals(x_system_password, settings.system_password):
            record_auth_result(key, True)
            note_credential(request, "system_password")
            return
        record_auth_result(key, False)
    elif x_api_key:
        key = enforce_auth_throttle(request, API_KEY_SECRET)
        if secret_equals(x_api_key, settings.sca_api_key):
            record_auth_result(key, True)
            note_credential(request, "sca_api_key")
            return
        from app.services.api_token_service import get_api_token_service, looks_like_token

        if looks_like_token(x_api_key):
            token = await (await get_api_token_service()).authenticate(x_api_key)
            if token is not None:
                note_credential(request, "api_token", name=token.get("name"))
                return
        record_auth_result(key, False)
    raise login_required_error("Sign-in required: send a session, the system password or an API key.")


def public_base_url(request: Request) -> str:
    """The web app's public origin, for the OIDC redirect URI and the cookie flags.

    ``AUTH_PUBLIC_URL`` wins. Otherwise the forwarded scheme and host are only
    believed when the direct peer is a trusted proxy (``TRUSTED_PROXY_IPS``).
    """
    if settings.auth_public_url.strip():
        return settings.auth_public_url.strip().rstrip("/")
    client = request.client
    peer = client.host if client else ""
    scheme = request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    if is_trusted_proxy(peer):
        scheme = (request.headers.get("x-forwarded-proto") or scheme).split(",")[0].strip()
        host = (request.headers.get("x-forwarded-host") or host).split(",")[0].strip()
    if scheme not in ("http", "https"):
        scheme = "https"
    return f"{scheme}://{host}"
