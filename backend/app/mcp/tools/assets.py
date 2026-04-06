"""MCP tools for asset catalog (vendors, products, versions) queries."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.core.config import settings
from app.mcp.audit import log_tool_invocation
from app.mcp.auth import mcp_client_id
from app.mcp.security import sanitize_search_input
from app.mcp.server import get_rate_limiter


def register(mcp: FastMCP) -> None:
    """Register asset catalog tools on the MCP server."""

    @mcp.tool()
    async def search_vendors(
        keyword: str | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Search the Hecate asset catalog for known software vendors.

        Returns vendor names and slugs. Use the slug with search_products to find products.
        Examples:
        - search_vendors(keyword="apache") — find Apache-related vendors
        - search_vendors(keyword="micro") — find vendors matching 'micro' (Microsoft, etc.)
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"keyword": keyword, "limit": limit}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="search_vendors", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return [{"error": "Rate limit exceeded."}]

        try:
            capped_limit = max(1, min(limit, settings.mcp_max_results))
            safe_keyword = sanitize_search_input(keyword) if keyword else None

            from app.services.asset_catalog_service import get_asset_catalog_service

            service = await get_asset_catalog_service()
            total, items = await service.search_vendors(safe_keyword, limit=capped_limit, offset=0)

            await log_tool_invocation(
                tool_name="search_vendors", inputs=tool_inputs,
                result_count=len(items), started_at=started_at,
            )
            return items

        except Exception as exc:
            await log_tool_invocation(
                tool_name="search_vendors", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return [{"error": f"Vendor search failed: {str(exc)[:200]}"}]

    @mcp.tool()
    async def search_products(
        keyword: str | None = None,
        vendor_slug: str | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Search the Hecate asset catalog for known software products.

        Optionally filter by vendor slug (from search_vendors). Returns product names and slugs.
        Examples:
        - search_products(keyword="tomcat") — find products matching 'tomcat'
        - search_products(vendor_slug="apache", keyword="http") — Apache HTTP products
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"keyword": keyword, "vendor_slug": vendor_slug, "limit": limit}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="search_products", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return [{"error": "Rate limit exceeded."}]

        try:
            capped_limit = max(1, min(limit, settings.mcp_max_results))
            safe_keyword = sanitize_search_input(keyword) if keyword else None
            vendor_slugs = [vendor_slug] if vendor_slug else None

            from app.services.asset_catalog_service import get_asset_catalog_service

            service = await get_asset_catalog_service()
            total, items = await service.search_products(
                vendor_slugs=vendor_slugs,
                keyword=safe_keyword,
                limit=capped_limit,
                offset=0,
            )

            await log_tool_invocation(
                tool_name="search_products", inputs=tool_inputs,
                result_count=len(items), started_at=started_at,
            )
            return items

        except Exception as exc:
            await log_tool_invocation(
                tool_name="search_products", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return [{"error": f"Product search failed: {str(exc)[:200]}"}]
