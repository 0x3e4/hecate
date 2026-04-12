"""ASGI middleware for MCP OAuth authentication and connection limiting."""

from __future__ import annotations

import asyncio
import json
from contextvars import ContextVar
from typing import Any

import structlog

from app.core.config import settings

log = structlog.get_logger()

# Contextvars set by auth middleware, readable by tool handlers and audit.
mcp_client_id: ContextVar[str] = ContextVar("mcp_client_id", default="anonymous")
mcp_client_ip: ContextVar[str] = ContextVar("mcp_client_ip", default="")
mcp_token_scope: ContextVar[str] = ContextVar("mcp_token_scope", default="")
mcp_token_email: ContextVar[str] = ContextVar("mcp_token_email", default="")
mcp_token_issued_ip: ContextVar[str] = ContextVar("mcp_token_issued_ip", default="")
mcp_dcr_client_id: ContextVar[str] = ContextVar("mcp_dcr_client_id", default="")


class MCPAuthMiddleware:
    """ASGI middleware that validates an OAuth Bearer token before forwarding to MCP server."""

    def __init__(self, app: Any) -> None:
        self._app = app
        self._semaphore = asyncio.Semaphore(settings.mcp_max_concurrent_connections)

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self._app(scope, receive, send)
            return

        headers_list = scope.get("headers", [])
        headers = dict(headers_list)
        proto = "https"
        host = ""
        for k, v in headers_list:
            if k == b"x-forwarded-proto":
                proto = v.decode()
            elif k == b"x-forwarded-host":
                host = v.decode()
        if not host:
            host = headers.get(b"host", b"localhost").decode()
        resource_metadata_url = f"{proto}://{host}/.well-known/oauth-protected-resource/mcp"

        auth_header = headers.get(b"authorization", b"").decode()

        if not auth_header.startswith("Bearer "):
            await self._send_401(send, resource_metadata_url)
            log.warning("mcp.auth_failed", reason="missing_bearer")
            return

        token = auth_header[7:]

        from app.mcp.oauth import get_oauth_token_info

        info = get_oauth_token_info(token)
        if info is None:
            await self._send_401(send, resource_metadata_url)
            log.warning(
                "mcp.auth_failed",
                reason="invalid_token",
                client_ip=self._get_client_ip(scope, headers_list),
            )
            return

        if self._semaphore.locked():
            await self._send_error(send, 503, "Too many concurrent connections")
            log.warning("mcp.connection_limit_reached")
            return

        async with self._semaphore:
            client_ip = self._get_client_ip(scope, headers_list) or ""
            tokens = [
                mcp_client_id.set(info.identity or "mcp-oauth-client"),
                mcp_client_ip.set(client_ip),
                mcp_token_scope.set(info.scope or ""),
                mcp_token_email.set(info.email or ""),
                mcp_token_issued_ip.set(info.issued_at_ip or ""),
                mcp_dcr_client_id.set(info.client_id or ""),
            ]
            try:
                await self._app(scope, receive, send)
            finally:
                mcp_dcr_client_id.reset(tokens[5])
                mcp_token_issued_ip.reset(tokens[4])
                mcp_token_email.reset(tokens[3])
                mcp_token_scope.reset(tokens[2])
                mcp_client_ip.reset(tokens[1])
                mcp_client_id.reset(tokens[0])

    @staticmethod
    async def _send_401(send: Any, resource_metadata_url: str) -> None:
        body = json.dumps({"error": "Unauthorized"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(body)).encode()],
                    [b"www-authenticate", f'Bearer resource_metadata="{resource_metadata_url}"'.encode()],
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    async def _send_error(send: Any, status: int, message: str) -> None:
        body = json.dumps({"error": message}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(body)).encode()],
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    def _get_client_ip(scope: dict, headers_list: list) -> str | None:
        for k, v in headers_list:
            if k == b"x-forwarded-for":
                return v.decode().split(",")[0].strip()
        client = scope.get("client")
        return client[0] if client else None


def require_write_scope() -> tuple[bool, str | None]:
    """Check if the current MCP request is allowed to call write tools.

    Both checks must pass:
      1. The OAuth token must carry the `mcp:write` scope (granted at authorize
         time when the user's IP was in MCP_WRITE_IP_SAFELIST).
      2. The CURRENT request's source IP must still be in MCP_WRITE_IP_SAFELIST
         (defence-in-depth in case the user's IP changed after token issue).

    Returns (allowed, deny_reason).
    """
    scope = mcp_token_scope.get("")
    if "mcp:write" not in scope.split():
        return False, "Token was not issued with mcp:write scope (source IP was not in MCP_WRITE_IP_SAFELIST at authorization time)."
    ip_str = mcp_client_ip.get()
    from app.mcp.oauth import _ip_in_safelist

    if not ip_str or not _ip_in_safelist(ip_str, settings.mcp_write_ip_safelist):
        return False, "Current source IP is not in MCP_WRITE_IP_SAFELIST."
    return True, None
