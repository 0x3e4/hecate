"""MCP server factory for Hecate vulnerability management platform."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

from app.core.config import settings
from app.mcp.auth import MCPAuthMiddleware
from app.mcp.security import RateLimiter

# Singleton rate limiter shared across all tool handlers.
_rate_limiter = RateLimiter(settings.mcp_rate_limit_per_minute)

# Module-level reference so startup/shutdown can access the session manager.
_mcp_instance: FastMCP | None = None


def get_rate_limiter() -> RateLimiter:
    return _rate_limiter


def create_mcp_server() -> FastMCP:
    """Create and configure the MCP server with all tool registrations."""
    mcp = FastMCP("hecate-vuln-db", stateless_http=True, streamable_http_path="/")

    # Register tools from each module
    from app.mcp.tools.vulnerabilities import register as register_vulnerabilities
    from app.mcp.tools.cpe import register as register_cpe
    from app.mcp.tools.assets import register as register_assets
    from app.mcp.tools.stats import register as register_stats
    from app.mcp.tools.cwe_capec import register as register_cwe_capec
    from app.mcp.tools.scans import register as register_scans

    register_vulnerabilities(mcp)
    register_cpe(mcp)
    register_assets(mcp)
    register_stats(mcp)
    register_cwe_capec(mcp)
    register_scans(mcp)

    return mcp


def create_mcp_app() -> tuple[Any, FastMCP]:
    """Create the MCP ASGI application wrapped with auth middleware.

    Returns (asgi_app, mcp_instance) so the caller can manage the
    session manager lifecycle.
    """
    global _mcp_instance
    mcp = create_mcp_server()
    _mcp_instance = mcp
    asgi_app = mcp.streamable_http_app()
    return MCPAuthMiddleware(asgi_app), mcp


def get_mcp_instance() -> FastMCP | None:
    return _mcp_instance
