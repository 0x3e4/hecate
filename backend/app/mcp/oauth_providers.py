"""Pluggable OAuth identity provider abstraction for MCP delegated authentication.

Hecate acts as the OAuth 2.0 Authorization Server for the MCP client (so DCR + PKCE
work with Claude Desktop / mcp-remote etc), but delegates the human authentication
step to a real upstream IdP. This module wraps the IdP-side OAuth dance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import structlog

from app.core.config import settings
from app.services.http.ssl import get_http_verify

log = structlog.get_logger()


@dataclass
class UserInfo:
    identity: str
    email: str
    name: str


class ProviderError(Exception):
    """Raised when the upstream IdP exchange or userinfo call fails."""


class OAuthProvider:
    name: str = ""
    default_scopes: str = ""

    def __init__(self) -> None:
        self.client_id = settings.mcp_oauth_client_id
        self.client_secret = settings.mcp_oauth_client_secret
        self.scopes = (settings.mcp_oauth_scopes or self.default_scopes).strip()

    def authorize_url(self, state: str, redirect_uri: str) -> str:
        raise NotImplementedError

    async def exchange_code(self, code: str, redirect_uri: str) -> str:
        raise NotImplementedError

    async def fetch_user(self, access_token: str) -> UserInfo:
        raise NotImplementedError


class GitHubProvider(OAuthProvider):
    name = "github"
    default_scopes = "read:user user:email"

    AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USER_URL = "https://api.github.com/user"
    EMAILS_URL = "https://api.github.com/user/emails"

    def authorize_url(self, state: str, redirect_uri: str) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": self.scopes,
            "state": state,
            "allow_signup": "false",
        }
        return f"{self.AUTHORIZE_URL}?{urlencode(params)}"

    async def exchange_code(self, code: str, redirect_uri: str) -> str:
        async with httpx.AsyncClient(timeout=10.0, verify=get_http_verify()) as client:
            resp = await client.post(
                self.TOKEN_URL,
                headers={"Accept": "application/json"},
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
            )
            if resp.status_code != 200:
                raise ProviderError(f"GitHub token exchange failed: {resp.status_code}")
            data = resp.json()
            token = data.get("access_token")
            if not token:
                raise ProviderError(f"GitHub token exchange returned no token: {data.get('error')}")
            return token

    async def fetch_user(self, access_token: str) -> UserInfo:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {access_token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        async with httpx.AsyncClient(timeout=10.0, verify=get_http_verify()) as client:
            user_resp = await client.get(self.USER_URL, headers=headers)
            if user_resp.status_code != 200:
                raise ProviderError(f"GitHub /user failed: {user_resp.status_code}")
            user = user_resp.json()
            login = user.get("login") or ""
            name = user.get("name") or login
            email = user.get("email") or ""

            if not email:
                emails_resp = await client.get(self.EMAILS_URL, headers=headers)
                if emails_resp.status_code == 200:
                    for entry in emails_resp.json():
                        if entry.get("primary") and entry.get("verified"):
                            email = entry.get("email") or ""
                            break

        if not login:
            raise ProviderError("GitHub user has no login")
        return UserInfo(identity=login, email=email, name=name)


class MicrosoftProvider(OAuthProvider):
    name = "microsoft"
    default_scopes = "openid email profile User.Read"

    USER_URL = "https://graph.microsoft.com/v1.0/me"

    def __init__(self) -> None:
        super().__init__()
        issuer = (settings.mcp_oauth_issuer or "https://login.microsoftonline.com/common/v2.0").rstrip("/")
        # Strip trailing /v2.0 to get the tenant base
        if issuer.endswith("/v2.0"):
            tenant_base = issuer[: -len("/v2.0")]
        else:
            tenant_base = issuer
        self._authorize_url = f"{tenant_base}/oauth2/v2.0/authorize"
        self._token_url = f"{tenant_base}/oauth2/v2.0/token"

    def authorize_url(self, state: str, redirect_uri: str) -> str:
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": self.scopes,
            "state": state,
        }
        return f"{self._authorize_url}?{urlencode(params)}"

    async def exchange_code(self, code: str, redirect_uri: str) -> str:
        async with httpx.AsyncClient(timeout=10.0, verify=get_http_verify()) as client:
            resp = await client.post(
                self._token_url,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "scope": self.scopes,
                },
            )
            if resp.status_code != 200:
                raise ProviderError(f"Microsoft token exchange failed: {resp.status_code} {resp.text[:200]}")
            data = resp.json()
            token = data.get("access_token")
            if not token:
                raise ProviderError(f"Microsoft token exchange returned no token: {data.get('error')}")
            return token

    async def fetch_user(self, access_token: str) -> UserInfo:
        async with httpx.AsyncClient(timeout=10.0, verify=get_http_verify()) as client:
            resp = await client.get(
                self.USER_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if resp.status_code != 200:
                raise ProviderError(f"Microsoft Graph /me failed: {resp.status_code}")
            data = resp.json()
        identity = data.get("userPrincipalName") or data.get("id") or ""
        email = data.get("mail") or data.get("userPrincipalName") or ""
        name = data.get("displayName") or identity
        if not identity:
            raise ProviderError("Microsoft user has no userPrincipalName")
        return UserInfo(identity=identity, email=email, name=name)


class OIDCProvider(OAuthProvider):
    name = "oidc"
    default_scopes = "openid email profile"

    def __init__(self) -> None:
        super().__init__()
        if not settings.mcp_oauth_issuer:
            raise ProviderError("MCP_OAUTH_ISSUER is required for the oidc provider")
        self._issuer = settings.mcp_oauth_issuer.rstrip("/")
        self._discovery: dict[str, Any] | None = None

    async def _discover(self) -> dict[str, Any]:
        if self._discovery is not None:
            return self._discovery
        url = f"{self._issuer}/.well-known/openid-configuration"
        async with httpx.AsyncClient(timeout=10.0, verify=get_http_verify()) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                raise ProviderError(f"OIDC discovery failed: {url} {resp.status_code}")
            self._discovery = resp.json()
        return self._discovery

    async def authorize_url_async(self, state: str, redirect_uri: str) -> str:
        meta = await self._discover()
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": self.scopes,
            "state": state,
        }
        return f"{meta['authorization_endpoint']}?{urlencode(params)}"

    def authorize_url(self, state: str, redirect_uri: str) -> str:  # pragma: no cover - sync shim
        raise RuntimeError("Use authorize_url_async() for OIDCProvider")

    async def exchange_code(self, code: str, redirect_uri: str) -> str:
        meta = await self._discover()
        async with httpx.AsyncClient(timeout=10.0, verify=get_http_verify()) as client:
            resp = await client.post(
                meta["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
            )
            if resp.status_code != 200:
                raise ProviderError(f"OIDC token exchange failed: {resp.status_code} {resp.text[:200]}")
            data = resp.json()
            token = data.get("access_token")
            if not token:
                raise ProviderError("OIDC token exchange returned no access_token")
            return token

    async def fetch_user(self, access_token: str) -> UserInfo:
        meta = await self._discover()
        userinfo_url = meta.get("userinfo_endpoint")
        if not userinfo_url:
            raise ProviderError("OIDC discovery missing userinfo_endpoint")
        async with httpx.AsyncClient(timeout=10.0, verify=get_http_verify()) as client:
            resp = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if resp.status_code != 200:
                raise ProviderError(f"OIDC userinfo failed: {resp.status_code}")
            data = resp.json()
        identity = data.get("preferred_username") or data.get("sub") or ""
        email = data.get("email") or ""
        name = data.get("name") or identity
        if not identity:
            raise ProviderError("OIDC userinfo missing sub/preferred_username")
        return UserInfo(identity=identity, email=email, name=name)


_provider_instance: OAuthProvider | None = None


def get_provider() -> OAuthProvider:
    global _provider_instance
    if _provider_instance is not None:
        return _provider_instance
    name = (settings.mcp_oauth_provider or "").lower()
    if name == "github":
        _provider_instance = GitHubProvider()
    elif name == "microsoft":
        _provider_instance = MicrosoftProvider()
    elif name == "oidc":
        _provider_instance = OIDCProvider()
    else:
        raise ProviderError(f"Unknown MCP_OAUTH_PROVIDER: {name!r}")
    return _provider_instance


async def resolve_authorize_url(state: str, redirect_uri: str) -> str:
    """Resolve the IdP authorize URL, handling async OIDC discovery."""
    provider = get_provider()
    if isinstance(provider, OIDCProvider):
        return await provider.authorize_url_async(state, redirect_uri)
    return provider.authorize_url(state, redirect_uri)
