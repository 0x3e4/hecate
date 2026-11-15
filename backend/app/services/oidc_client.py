"""OpenID Connect relying party for the web app login.

The backend runs the Authorization Code flow with PKCE (S256), ``state`` and
``nonce`` as a confidential client (or a public one when no secret is set) and
hands the browser nothing but an opaque session cookie (backend-for-frontend).
Everything vendor-specific comes from the issuer's discovery document, so
Keycloak, Authelia, Authentik, Zitadel, Pocket ID and Entra ID go through the
same code. See docs/admin/authentication.md.

ID tokens are checked here, not trusted because they came over TLS from the
token endpoint: signature against the issuer's JWKS (refetched once when an
unknown ``kid`` shows up, so key rotation works without a restart), ``iss``,
``aud`` (+ ``azp``), ``exp`` / ``iat`` with a small leeway, ``nonce``, and an
algorithm allow-list that never contains ``none`` or an HMAC algorithm (a public
key used as an HMAC secret would let anyone mint tokens).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import httpx
import jwt
import structlog

from app.core.config import settings
from app.services.http.ssl import get_http_verify

log = structlog.get_logger()

ROLE_ORDER = ("admin", "editor", "viewer")
_NEVER_ALLOWED = {"none", "HS256", "HS384", "HS512"}
_DISCOVERY_TTL_SECONDS = 3600.0
_JWKS_TTL_SECONDS = 3600.0
# An unknown kid refetches the key set, but not more often than this, so a
# stream of tokens with made-up kids cannot turn us into a JWKS hammer.
_JWKS_MIN_REFRESH_SECONDS = 60.0


class OidcError(Exception):
    """A failed login step. ``code`` is safe to show and to log; ``message`` too
    (it never contains a token, a code or a secret)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def allowed_algorithms() -> list[str]:
    """The configured signature algorithms, minus anything symmetric or ``none``."""
    algorithms = []
    for raw in settings.oidc_allowed_algs.split(","):
        name = raw.strip()
        if not name or name in _NEVER_ALLOWED or name.lower() == "none" or name.upper().startswith("HS"):
            continue
        algorithms.append(name)
    return algorithms


def pkce_pair() -> tuple[str, str]:
    """A PKCE code verifier and its S256 challenge (RFC 7636)."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


# --- Role mapping ------------------------------------------------------------


def claim_values(claims: dict[str, Any], path: str) -> list[str]:
    """The string values of a claim, looked up literally first, then as a dotted path.

    Literal first because claim names may contain dots themselves
    (``https://example.com/roles``). A dict value contributes its keys (Zitadel's
    ``urn:zitadel:iam:org:project:roles`` maps role names to organisations), a
    string is one value.
    """
    path = (path or "").strip()
    if not path:
        return []
    if path in claims:
        value: Any = claims[path]
    else:
        value = claims
        for part in path.split("."):
            if not isinstance(value, dict) or part not in value:
                return []
            value = value[part]
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [str(key) for key in value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _normalize_group(value: str) -> str:
    # Keycloak's group mapper sends full paths ("/hecate-admins") unless told
    # otherwise; names are compared case-insensitively.
    return value.strip().lstrip("/").casefold()


def _configured(csv: str) -> set[str]:
    return {_normalize_group(item) for item in csv.split(",") if item.strip()}


def resolve_role(claims: dict[str, Any]) -> str | None:
    """The highest Hecate role the claims grant, or ``None`` for no access.

    An empty viewer list makes every authenticated user a viewer.
    """
    values = {_normalize_group(v) for v in claim_values(claims, settings.oidc_roles_claim)}
    if values & _configured(settings.oidc_admin_groups):
        return "admin"
    if values & _configured(settings.oidc_editor_groups):
        return "editor"
    viewers = _configured(settings.oidc_viewer_groups)
    if not viewers or values & viewers:
        return "viewer"
    return None


def display_name(claims: dict[str, Any]) -> str:
    for key in ("name", "preferred_username", "email", "upn", "sub"):
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:200]
    return "unknown"


def email_of(claims: dict[str, Any]) -> str | None:
    for key in ("email", "upn", "preferred_username"):
        value = claims.get(key)
        if isinstance(value, str) and "@" in value:
            return value.strip()[:320]
    return None


# --- Client ------------------------------------------------------------------


class OidcClient:
    def __init__(
        self,
        issuer: str,
        client_id: str,
        client_secret: str = "",
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.issuer = issuer.strip().rstrip("/")
        self.client_id = client_id.strip()
        self.client_secret = client_secret
        self._transport = transport
        self._discovery: dict[str, Any] | None = None
        self._discovery_at = 0.0
        self._jwks: list[dict[str, Any]] = []
        self._jwks_at = 0.0

    def _http(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=settings.oidc_timeout_seconds,
            verify=get_http_verify(),
            follow_redirects=False,
            transport=self._transport,
            headers={"User-Agent": "hecate-oidc/1.0", "Accept": "application/json"},
        )

    async def discovery(self) -> dict[str, Any]:
        now = time.monotonic()
        if self._discovery is not None and now - self._discovery_at < _DISCOVERY_TTL_SECONDS:
            return self._discovery
        url = f"{self.issuer}/.well-known/openid-configuration"
        try:
            async with self._http() as client:
                response = await client.get(url)
        except httpx.HTTPError as exc:
            raise OidcError("provider_unavailable", f"Discovery failed: {type(exc).__name__}") from exc
        if response.status_code != 200:
            raise OidcError("provider_unavailable", f"Discovery answered HTTP {response.status_code}")
        try:
            document = response.json()
        except ValueError as exc:
            raise OidcError("provider_unavailable", "Discovery document is not JSON") from exc
        if not isinstance(document, dict):
            raise OidcError("provider_unavailable", "Discovery document is not an object")
        # OIDC Discovery 1.0 §4.3: the issuer in the document must be the one we asked.
        if str(document.get("issuer", "")).rstrip("/") != self.issuer:
            raise OidcError(
                "provider_misconfigured",
                "The discovery document names a different issuer than OIDC_ISSUER.",
            )
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            value = document.get(key)
            if not isinstance(value, str) or urlsplit(value).scheme not in ("https", "http"):
                raise OidcError("provider_misconfigured", f"Discovery document lacks {key}.")
        self._discovery = document
        self._discovery_at = now
        return document

    async def authorization_url(self, *, state: str, nonce: str, code_challenge: str, redirect_uri: str) -> str:
        document = await self.discovery()
        endpoint = document["authorization_endpoint"]
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": settings.oidc_scopes.strip() or "openid",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        separator = "&" if "?" in endpoint else "?"
        return f"{endpoint}{separator}{urlencode(params)}"

    async def exchange_code(self, *, code: str, code_verifier: str, redirect_uri: str) -> dict[str, Any]:
        document = await self.discovery()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        headers: dict[str, str] = {}
        methods = document.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
        if self.client_secret and "client_secret_basic" in methods:
            # RFC 6749 §2.3.1: id and secret are form-encoded before base64.
            raw = f"{quote(self.client_id, safe='')}:{quote(self.client_secret, safe='')}"
            headers["Authorization"] = "Basic " + base64.b64encode(raw.encode()).decode()
        elif self.client_secret:
            data["client_id"] = self.client_id
            data["client_secret"] = self.client_secret
        else:
            data["client_id"] = self.client_id
        try:
            async with self._http() as client:
                response = await client.post(document["token_endpoint"], data=data, headers=headers)
        except httpx.HTTPError as exc:
            raise OidcError("token_exchange_failed", f"Token endpoint unreachable: {type(exc).__name__}") from exc
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        if response.status_code != 200 or not isinstance(payload, dict):
            error = payload.get("error") if isinstance(payload, dict) else None
            # Only the OAuth error code: descriptions may echo request values.
            raise OidcError(
                "token_exchange_failed",
                f"Token endpoint answered HTTP {response.status_code}" + (f" ({str(error)[:60]})" if error else ""),
            )
        if not isinstance(payload.get("id_token"), str):
            raise OidcError("token_exchange_failed", "Token response carries no id_token (is the openid scope set?).")
        return payload

    async def _load_jwks(self, *, force: bool = False) -> list[dict[str, Any]]:
        now = time.monotonic()
        fresh = self._jwks and now - self._jwks_at < _JWKS_TTL_SECONDS
        if fresh and not force:
            return self._jwks
        if force and self._jwks and now - self._jwks_at < _JWKS_MIN_REFRESH_SECONDS:
            return self._jwks
        document = await self.discovery()
        try:
            async with self._http() as client:
                response = await client.get(document["jwks_uri"])
            keys = response.json().get("keys") if response.status_code == 200 else None
        except (httpx.HTTPError, ValueError, AttributeError) as exc:
            raise OidcError("provider_unavailable", f"JWKS fetch failed: {type(exc).__name__}") from exc
        if not isinstance(keys, list):
            raise OidcError("provider_unavailable", "JWKS document has no keys.")
        self._jwks = [key for key in keys if isinstance(key, dict) and key.get("use", "sig") == "sig"]
        self._jwks_at = now
        return self._jwks

    async def _signing_key(self, kid: str | None, algorithm: str) -> Any:
        for attempt in (False, True):
            keys = await self._load_jwks(force=attempt)
            if kid:
                candidates = [key for key in keys if key.get("kid") == kid]
            else:
                candidates = keys if len(keys) == 1 else [key for key in keys if key.get("alg") == algorithm]
            if len(candidates) == 1:
                try:
                    return jwt.PyJWK(candidates[0], algorithm=algorithm).key
                except jwt.PyJWTError as exc:
                    raise OidcError("invalid_token", f"Unusable signing key: {type(exc).__name__}") from exc
        raise OidcError("invalid_token", "ID token is signed with a key the issuer does not publish.")

    async def validate_id_token(self, id_token: str, *, nonce: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise OidcError("invalid_token", "ID token is not a JWT.") from exc
        algorithm = header.get("alg")
        if not isinstance(algorithm, str) or algorithm not in allowed_algorithms():
            raise OidcError("invalid_token", f"ID token algorithm {str(algorithm)[:20]!r} is not allowed.")
        document = await self.discovery()
        key = await self._signing_key(header.get("kid") if isinstance(header.get("kid"), str) else None, algorithm)
        try:
            claims = jwt.decode(
                id_token,
                key=key,
                algorithms=[algorithm],
                audience=self.client_id,
                issuer=document["issuer"],
                leeway=max(0, settings.oidc_clock_skew_seconds),
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise OidcError("invalid_token", "ID token has expired.") from exc
        except jwt.InvalidAudienceError as exc:
            raise OidcError("invalid_token", "ID token was issued for another client.") from exc
        except jwt.InvalidIssuerError as exc:
            raise OidcError("invalid_token", "ID token comes from another issuer.") from exc
        except jwt.PyJWTError as exc:
            raise OidcError("invalid_token", f"ID token rejected: {type(exc).__name__}") from exc
        audience = claims.get("aud")
        azp = claims.get("azp")
        if azp is not None and azp != self.client_id:
            raise OidcError("invalid_token", "ID token's authorized party is another client.")
        if isinstance(audience, list) and len(audience) > 1 and azp is None:
            raise OidcError("invalid_token", "ID token has several audiences but no authorized party.")
        token_nonce = claims.get("nonce")
        if not isinstance(token_nonce, str) or not hmac.compare_digest(token_nonce, nonce):
            raise OidcError("invalid_token", "ID token nonce does not match this login.")
        return claims

    async def userinfo(self, access_token: str, *, subject: str) -> dict[str, Any]:
        """Claims from the userinfo endpoint, ``{}`` when there is none or it fails.

        Only taken when its ``sub`` is the ID token's (OIDC Core §5.3.2).
        """
        document = await self.discovery()
        endpoint = document.get("userinfo_endpoint")
        if not isinstance(endpoint, str) or not access_token:
            return {}
        try:
            async with self._http() as client:
                response = await client.get(endpoint, headers={"Authorization": f"Bearer {access_token}"})
            payload = response.json() if response.status_code == 200 else None
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("auth.userinfo_failed", error=type(exc).__name__)
            return {}
        if not isinstance(payload, dict) or payload.get("sub") != subject:
            return {}
        return payload

    async def end_session_url(self, *, id_token_hint: str | None, post_logout_redirect_uri: str) -> str | None:
        try:
            document = await self.discovery()
        except OidcError:
            return None
        endpoint = document.get("end_session_endpoint")
        if not isinstance(endpoint, str) or urlsplit(endpoint).scheme not in ("https", "http"):
            return None
        params = {"client_id": self.client_id, "post_logout_redirect_uri": post_logout_redirect_uri}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        separator = "&" if "?" in endpoint else "?"
        return f"{endpoint}{separator}{urlencode(params)}"


_client: OidcClient | None = None
_client_key: tuple[str, str, str] | None = None
# Tests point this at an httpx.MockTransport.
_transport: httpx.AsyncBaseTransport | None = None


def get_oidc_client() -> OidcClient:
    """The process-wide client, rebuilt when the OIDC settings change."""
    global _client, _client_key
    key = (settings.oidc_issuer, settings.oidc_client_id, settings.oidc_client_secret)
    if _client is None or _client_key != key:
        _client = OidcClient(*key, transport=_transport)
        _client_key = key
    return _client


def reset_oidc_client() -> None:
    global _client, _client_key
    _client = None
    _client_key = None
