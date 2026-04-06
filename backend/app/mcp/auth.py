"""ASGI middleware for MCP API key authentication and connection limiting."""

from __future__ import annotations

import asyncio
import hmac
import json
from contextvars import ContextVar
from typing import Any

import structlog

from app.core.config import settings

log = structlog.get_logger()

# Contextvar set by auth middleware, readable by tool handlers.
mcp_client_id: ContextVar[str] = ContextVar("mcp_client_id", default="anonymous")


class MCPAuthMiddleware:
    """ASGI middleware that validates Bearer token (API key or OAuth) before forwarding to MCP server."""

    def __init__(self, app: Any) -> None:
        self._app = app
        self._semaphore = asyncio.Semaphore(settings.mcp_max_concurrent_connections)
        self._api_key = (settings.mcp_api_key or "").encode()

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self._app(scope, receive, send)
            return

        # Extract Authorization header
        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode()

        if not auth_header.startswith("Bearer "):
            await self._send_error(send, 401, "Missing or invalid Authorization header")
            log.warning("mcp.auth_failed", reason="missing_bearer")
            return

        token = auth_header[7:]

        # Check 1: Direct API key match (timing-safe)
        is_api_key = hmac.compare_digest(token.encode(), self._api_key)

        # Check 2: OAuth access token
        is_oauth = False
        if not is_api_key:
            from app.mcp.oauth import validate_oauth_token
            is_oauth = validate_oauth_token(token)

        if not is_api_key and not is_oauth:
            await self._send_error(send, 401, "Invalid API key or token")
            log.warning(
                "mcp.auth_failed",
                reason="invalid_key",
                client_ip=self._get_client_ip(scope),
            )
            return

        # Connection limiting
        if self._semaphore.locked():
            await self._send_error(send, 503, "Too many concurrent connections")
            log.warning("mcp.connection_limit_reached")
            return

        async with self._semaphore:
            client_label = "mcp-oauth-client" if is_oauth else "mcp-apikey-client"
            token_client = mcp_client_id.set(client_label)
            try:
                await self._app(scope, receive, send)
            finally:
                mcp_client_id.reset(token_client)

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
    def _get_client_ip(scope: dict) -> str | None:
        client = scope.get("client")
        return client[0] if client else None


def require_write_key() -> bool:
    """Check if the write API key is configured and valid.

    Call this inside write-gated tool handlers.  Returns True when
    write access is allowed, False otherwise.
    """
    return bool(settings.mcp_write_api_key)
