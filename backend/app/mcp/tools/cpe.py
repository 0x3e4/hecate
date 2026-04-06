"""MCP tools for CPE (Common Platform Enumeration) lookups."""

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
    """Register CPE tools on the MCP server."""

    @mcp.tool()
    async def search_cpe(
        keyword: str | None = None,
        vendor: str | None = None,
        product: str | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Search CPE (Common Platform Enumeration) entries to find standardized software identifiers.

        CPE entries map vendor/product/version to a standard naming scheme used in vulnerability databases.
        Examples:
        - search_cpe(keyword="apache tomcat") — find CPE entries for Apache Tomcat
        - search_cpe(vendor="microsoft", product="windows") — find Windows CPE entries
        """
        started_at = datetime.now(tz=UTC)
        tool_inputs = {"keyword": keyword, "vendor": vendor, "product": product, "limit": limit}

        rate_limiter = get_rate_limiter()
        if not rate_limiter.check(mcp_client_id.get()):
            await log_tool_invocation(
                tool_name="search_cpe", inputs=tool_inputs,
                success=False, error="Rate limit exceeded", started_at=started_at,
            )
            return [{"error": "Rate limit exceeded."}]

        try:
            capped_limit = max(1, min(limit, settings.mcp_max_results))
            safe_keyword = sanitize_search_input(keyword) if keyword else None

            from app.schemas.cpe import CPEQuery
            from app.services.cpe_service import get_cpe_service

            service = await get_cpe_service()
            query = CPEQuery(keyword=safe_keyword, vendor=vendor, product=product, limit=capped_limit)
            response = await service.search(query)

            output = [
                {
                    "cpeName": item.cpe_name,
                    "title": item.title,
                    "vendor": item.vendor,
                    "product": item.product,
                    "version": item.version,
                    "deprecated": item.deprecated,
                }
                for item in response.items
            ]
            await log_tool_invocation(
                tool_name="search_cpe", inputs=tool_inputs,
                result_count=len(output), started_at=started_at,
            )
            return output

        except Exception as exc:
            await log_tool_invocation(
                tool_name="search_cpe", inputs=tool_inputs,
                success=False, error=str(exc)[:300], started_at=started_at,
            )
            return [{"error": f"CPE search failed: {str(exc)[:200]}"}]
